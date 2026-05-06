# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Host system operations for VPN007 deployment.

Provides functions for applying and persisting nftables firewall rules,
installing systemd timers, provisioning the AmneziaWG kernel module (with
amneziawg-go userspace fallback), verifying firewall rules, validating
Nginx configuration, and running post-deployment smoke tests.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from vpn007.models import DeployConfig, DeployError

logger = logging.getLogger("vpn007")


# ---------------------------------------------------------------------------
# nftables rule application and persistence
# ---------------------------------------------------------------------------


def apply_nftables(nftables_conf_path: Path) -> None:
    """Apply nftables rules from a configuration file via ``nft -f``.

    Uses atomic file-based loading so the entire ruleset is applied in a
    single transaction, preventing momentary firewall state drops.

    Parameters
    ----------
    nftables_conf_path:
        Path to the generated ``nftables.conf`` file.

    Raises
    ------
    DeployError
        If the ``nft -f`` command fails.
    """
    cmd = ["nft", "-f", str(nftables_conf_path)]
    logger.info("Applying nftables rules: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        logger.debug("nft stdout: %s", result.stdout)
        logger.debug("nft stderr: %s", result.stderr)
        logger.info("nftables rules applied successfully.")
    except subprocess.CalledProcessError as exc:
        raise DeployError(
            service="firewall",
            step="apply_nftables",
            message=f"Failed to apply nftables rules (exit code {exc.returncode}): "
            f"{exc.stderr.strip()}",
            remediation="Check the nftables.conf syntax with: nft -c -f "
            f"{nftables_conf_path}",
        ) from exc
    except FileNotFoundError as exc:
        raise DeployError(
            service="firewall",
            step="apply_nftables",
            message="'nft' command not found. Is nftables installed?",
            remediation="Install nftables: apt-get install -y nftables",
        ) from exc


def persist_nftables(nftables_conf_path: Path) -> None:
    """Persist nftables rules by copying to ``/etc/nftables.conf``.

    This ensures the firewall rules survive system reboots. The nftables
    systemd service loads ``/etc/nftables.conf`` on boot.

    Parameters
    ----------
    nftables_conf_path:
        Path to the generated ``nftables.conf`` file.

    Raises
    ------
    DeployError
        If the copy operation fails.
    """
    dest = Path("/etc/nftables.conf")
    logger.info("Persisting nftables rules to %s", dest)

    try:
        shutil.copy2(str(nftables_conf_path), str(dest))
        logger.info("nftables rules persisted to %s", dest)
    except OSError as exc:
        raise DeployError(
            service="firewall",
            step="persist_nftables",
            message=f"Failed to copy nftables.conf to {dest}: {exc}",
            remediation="Ensure the deployer is running with root privileges.",
        ) from exc


# ---------------------------------------------------------------------------
# Systemd timer installation
# ---------------------------------------------------------------------------


def install_systemd_timers(systemd_dir: Path) -> None:
    """Install and enable systemd service and timer units.

    Copies all ``.service`` and ``.timer`` files from *systemd_dir* to
    ``/etc/systemd/system/``, reloads the systemd daemon, and enables +
    starts each timer.

    Parameters
    ----------
    systemd_dir:
        Path to the directory containing generated ``.service`` and
        ``.timer`` files (e.g. ``{output_dir}/systemd/``).

    Raises
    ------
    DeployError
        If any systemd operation fails.
    """
    dest_dir = Path("/etc/systemd/system")
    unit_files = sorted(systemd_dir.glob("*.service")) + sorted(
        systemd_dir.glob("*.timer")
    )

    if not unit_files:
        logger.warning("No systemd unit files found in %s", systemd_dir)
        return

    # Copy unit files
    for unit_file in unit_files:
        dest = dest_dir / unit_file.name
        logger.info("Installing systemd unit: %s -> %s", unit_file, dest)
        try:
            shutil.copy2(str(unit_file), str(dest))
        except OSError as exc:
            raise DeployError(
                service="systemd",
                step="install_systemd_timers",
                message=f"Failed to copy {unit_file.name} to {dest}: {exc}",
                remediation="Ensure the deployer is running with root privileges.",
            ) from exc

    # Reload systemd daemon
    logger.info("Reloading systemd daemon...")
    try:
        subprocess.run(
            ["systemctl", "daemon-reload"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise DeployError(
            service="systemd",
            step="install_systemd_timers",
            message=f"systemctl daemon-reload failed: {exc.stderr.strip()}",
            remediation="Check systemd status: systemctl status",
        ) from exc
    except FileNotFoundError as exc:
        raise DeployError(
            service="systemd",
            step="install_systemd_timers",
            message="'systemctl' command not found. Is systemd available?",
            remediation="This system may not use systemd. "
            "Manual timer setup is required.",
        ) from exc

    # Enable and start each timer
    timer_files = [f for f in unit_files if f.suffix == ".timer"]
    for timer_file in timer_files:
        timer_name = timer_file.name
        logger.info("Enabling and starting timer: %s", timer_name)
        try:
            subprocess.run(
                ["systemctl", "enable", "--now", timer_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            logger.info("Timer %s enabled and started.", timer_name)
        except subprocess.CalledProcessError as exc:
            raise DeployError(
                service="systemd",
                step="install_systemd_timers",
                message=f"Failed to enable/start timer {timer_name}: "
                f"{exc.stderr.strip()}",
                remediation=f"Check timer status: systemctl status {timer_name}",
            ) from exc


# ---------------------------------------------------------------------------
# AmneziaWG kernel module provisioning
# ---------------------------------------------------------------------------


def provision_awg_kernel_module(distro: str) -> bool:
    """Provision the AmneziaWG kernel module on the host.

    On Debian/Ubuntu:
      (a) Check if ``amneziawg`` module is already loaded via ``lsmod``.
      (b) Install kernel headers for the running kernel.
      (c) Compile and load the module via DKMS.
      (d) Add the module to ``/etc/modules-load.d/`` for persistence.

    On Alpine: skip kernel module entirely and use amneziawg-go userspace
    fallback (Alpine does not support DKMS).

    Parameters
    ----------
    distro:
        Distribution ID (e.g. ``"debian"``, ``"ubuntu"``, ``"alpine"``).

    Returns
    -------
    bool
        ``True`` if the kernel module was successfully loaded or was
        already loaded. ``False`` if the module could not be loaded and
        the amneziawg-go userspace fallback should be used.
    """
    distro_lower = distro.lower()

    if distro_lower == "alpine":
        logger.info(
            "Alpine Linux detected: skipping AmneziaWG kernel module. "
            "Using amneziawg-go userspace fallback."
        )
        return False

    if distro_lower not in ("debian", "ubuntu"):
        logger.warning(
            "Unsupported distro '%s' for kernel module provisioning. "
            "Using amneziawg-go userspace fallback.",
            distro,
        )
        return False

    # (a) Check if module is already loaded
    if _is_module_loaded("amneziawg"):
        logger.info("AmneziaWG kernel module is already loaded.")
        return True

    # (b) Install kernel headers
    if not _install_kernel_headers():
        logger.warning(
            "Failed to install kernel headers. "
            "Falling back to amneziawg-go userspace."
        )
        return False

    # (c) Compile and load via DKMS
    if not _compile_and_load_awg_module():
        logger.warning(
            "Failed to compile/load AmneziaWG kernel module via DKMS. "
            "Falling back to amneziawg-go userspace."
        )
        return False

    # (d) Persist module loading across reboots
    _persist_module_load("amneziawg")

    logger.info("AmneziaWG kernel module provisioned successfully.")
    return True


def _is_module_loaded(module_name: str) -> bool:
    """Check if a kernel module is currently loaded via ``lsmod``."""
    try:
        result = subprocess.run(
            ["lsmod"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            if line.split() and line.split()[0] == module_name:
                return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _install_kernel_headers() -> bool:
    """Install kernel headers for the running kernel.

    Uses ``linux-headers-$(uname -r)`` on Debian/Ubuntu.

    Returns
    -------
    bool
        ``True`` if installation succeeded.
    """
    try:
        uname_result = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        kernel_version = uname_result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        logger.warning("Could not determine kernel version: %s", exc)
        return False

    package = f"linux-headers-{kernel_version}"
    logger.info("Installing kernel headers: %s", package)

    try:
        subprocess.run(
            ["apt-get", "install", "-y", package],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        logger.info("Kernel headers installed: %s", package)
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "Failed to install %s: %s", package, exc.stderr.strip()
        )
        return False
    except FileNotFoundError:
        logger.warning("'apt-get' not found. Cannot install kernel headers.")
        return False


def _compile_and_load_awg_module() -> bool:
    """Compile and load the AmneziaWG kernel module via DKMS.

    Returns
    -------
    bool
        ``True`` if the module was compiled and loaded successfully.
    """
    # Ensure DKMS is installed
    try:
        subprocess.run(
            ["apt-get", "install", "-y", "dkms"],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.warning("Failed to install DKMS: %s", exc)
        return False

    # Build and install via DKMS
    logger.info("Building AmneziaWG kernel module via DKMS...")
    try:
        subprocess.run(
            ["dkms", "install", "amneziawg/1.0"],
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "DKMS install failed: %s", exc.stderr.strip()
        )
        return False
    except FileNotFoundError:
        logger.warning("'dkms' command not found after installation attempt.")
        return False

    # Load the module
    logger.info("Loading amneziawg kernel module...")
    try:
        subprocess.run(
            ["modprobe", "amneziawg"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        logger.info("AmneziaWG kernel module loaded successfully.")
        return True
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "modprobe amneziawg failed: %s", exc.stderr.strip()
        )
        return False
    except FileNotFoundError:
        logger.warning("'modprobe' command not found.")
        return False


def _persist_module_load(module_name: str) -> None:
    """Add a kernel module to ``/etc/modules-load.d/`` for boot persistence."""
    conf_path = Path(f"/etc/modules-load.d/{module_name}.conf")
    try:
        conf_path.write_text(f"{module_name}\n", encoding="utf-8")
        logger.info("Module persistence configured: %s", conf_path)
    except OSError as exc:
        logger.warning(
            "Could not persist module load for %s: %s", module_name, exc
        )


# ---------------------------------------------------------------------------
# amneziawg-go userspace fallback
# ---------------------------------------------------------------------------


def apply_awg_userspace_fallback(
    compose_path: Path,
    project_name: str,
) -> None:
    """Switch to amneziawg-go userspace fallback and restart the service.

    When the kernel module cannot be compiled or loaded, this function:
    1. Logs a warning about reduced performance.
    2. Rebuilds the amneziawg service using the custom Dockerfile.amneziawg
       with amneziawg-go.
    3. Re-runs ``docker compose up -d amneziawg`` to restart the service.

    Parameters
    ----------
    compose_path:
        Path to the ``docker-compose.yml`` file.
    project_name:
        Docker Compose project name.

    Raises
    ------
    DeployError
        If the compose rebuild/restart fails.
    """
    logger.warning(
        "AmneziaWG kernel module not available. Switching to amneziawg-go "
        "userspace implementation. Performance will be reduced compared to "
        "the kernel module."
    )

    # Rebuild the amneziawg service with the custom Dockerfile
    build_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        project_name,
        "build",
        "amneziawg",
    ]
    logger.info("Building amneziawg with userspace fallback: %s", " ".join(build_cmd))

    try:
        subprocess.run(
            build_cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise DeployError(
            service="amneziawg",
            step="apply_awg_userspace_fallback",
            message=f"Failed to build amneziawg-go image: {exc.stderr.strip()}",
            remediation="Check Dockerfile.amneziawg and Docker build logs.",
        ) from exc

    # Restart the amneziawg service
    up_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        project_name,
        "up",
        "-d",
        "amneziawg",
    ]
    logger.info("Restarting amneziawg service: %s", " ".join(up_cmd))

    try:
        subprocess.run(
            up_cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        logger.info("amneziawg service restarted with userspace fallback.")
    except subprocess.CalledProcessError as exc:
        raise DeployError(
            service="amneziawg",
            step="apply_awg_userspace_fallback",
            message=f"Failed to restart amneziawg service: {exc.stderr.strip()}",
            remediation="Check container logs: docker compose logs amneziawg",
        ) from exc


# ---------------------------------------------------------------------------
# Firewall rule verification
# ---------------------------------------------------------------------------


def verify_firewall_rules() -> bool:
    """Verify that nftables rules are active and log the result.

    Runs ``nft list ruleset`` and checks that the output contains the
    expected ``inet filter`` table with input/output chains.

    Returns
    -------
    bool
        ``True`` if the firewall rules appear to be active.
    """
    logger.info("Verifying nftables firewall rules...")

    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.error("Could not run 'nft list ruleset': %s", exc)
        return False

    if result.returncode != 0:
        logger.error(
            "nft list ruleset failed (exit code %d): %s",
            result.returncode,
            result.stderr.strip(),
        )
        return False

    ruleset = result.stdout

    # Check for expected table and chains
    has_filter_table = "table inet filter" in ruleset
    has_input_chain = "chain input" in ruleset
    has_output_chain = "chain output" in ruleset
    has_policy_drop = "policy drop" in ruleset

    if has_filter_table and has_input_chain and has_output_chain and has_policy_drop:
        logger.info(
            "Firewall verification passed: inet filter table with "
            "input/output chains and default-deny policy detected."
        )
        return True

    missing = []
    if not has_filter_table:
        missing.append("inet filter table")
    if not has_input_chain:
        missing.append("input chain")
    if not has_output_chain:
        missing.append("output chain")
    if not has_policy_drop:
        missing.append("default-deny policy")

    logger.warning(
        "Firewall verification incomplete. Missing: %s",
        ", ".join(missing),
    )
    return False


# ---------------------------------------------------------------------------
# Nginx config validation
# ---------------------------------------------------------------------------


def validate_nginx_config(compose_path: Path) -> bool:
    """Validate Nginx configuration by running ``nginx -t`` inside the container.

    Executes ``docker compose exec reverse_proxy nginx -t`` to check the
    Nginx configuration syntax before applying changes.

    Parameters
    ----------
    compose_path:
        Path to the ``docker-compose.yml`` file.

    Returns
    -------
    bool
        ``True`` if the Nginx configuration is valid.
    """
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "exec",
        "reverse_proxy",
        "nginx",
        "-t",
    ]
    logger.info("Validating Nginx configuration: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.error("Could not run nginx -t: %s", exc)
        return False

    if result.returncode == 0:
        logger.info("Nginx configuration is valid.")
        logger.debug("nginx -t output: %s", result.stderr.strip())
        return True

    logger.error(
        "Nginx configuration validation failed: %s",
        result.stderr.strip(),
    )
    return False


# ---------------------------------------------------------------------------
# Post-deployment smoke test
# ---------------------------------------------------------------------------


def smoke_test(config: DeployConfig) -> dict[str, bool]:
    """Run post-deployment smoke tests.

    Verifies:
    1. The cover site responds to HTTP requests (via curl).
    2. All expected containers report healthy/running status.

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    dict[str, bool]
        Mapping of test name → pass/fail result.
    """
    results: dict[str, bool] = {}

    # 1. Verify cover site responds
    results["cover_site_responds"] = _check_cover_site(config.domain)

    # 2. Check container health status
    compose_path = config.output_dir / "docker-compose.yml"
    results["containers_healthy"] = _check_container_health(compose_path)

    for test_name, passed in results.items():
        if passed:
            logger.info("Smoke test PASSED: %s", test_name)
        else:
            logger.warning("Smoke test FAILED: %s", test_name)

    return results


def _check_cover_site(domain: str) -> bool:
    """Verify the cover site responds to an HTTPS request.

    Uses ``curl`` with ``--insecure`` flag to allow self-signed certs
    during initial deployment (before certbot runs).
    """
    url = f"https://{domain}/"
    cmd = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--insecure",
        "--max-time",
        "10",
        url,
    ]
    logger.info("Checking cover site: %s", url)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        status_code = result.stdout.strip()
        if status_code and status_code[0] in ("2", "3"):
            logger.info("Cover site responded with HTTP %s", status_code)
            return True
        logger.warning("Cover site returned HTTP %s", status_code)
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("Cover site check failed: %s", exc)
        return False


def _check_container_health(compose_path: Path) -> bool:
    """Check that all expected containers are running.

    Uses ``docker compose ps --format json`` to query container states.
    """
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "ps",
        "--format",
        "json",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("Container health check failed: %s", exc)
        return False

    if result.returncode != 0:
        logger.warning(
            "docker compose ps failed (exit code %d): %s",
            result.returncode,
            result.stderr.strip(),
        )
        return False

    import json

    output = result.stdout.strip()
    if not output:
        logger.warning("No containers found.")
        return False

    try:
        parsed = json.loads(output)
        if isinstance(parsed, list):
            entries = parsed
        else:
            entries = [parsed]
    except json.JSONDecodeError:
        # Line-by-line parsing for older compose versions
        entries = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not entries:
        logger.warning("No container entries parsed.")
        return False

    expected_services = {
        "reverse_proxy",
        "three_x_ui",
        "amneziawg",
        "tailscale",
        "cover_site",
    }

    running_services: set[str] = set()
    for entry in entries:
        service = entry.get("Service") or entry.get("Name", "")
        state = entry.get("State", "").lower()
        if state == "running":
            running_services.add(service)

    missing = expected_services - running_services
    if missing:
        logger.warning(
            "Not all expected services are running. Missing: %s",
            ", ".join(sorted(missing)),
        )
        return False

    logger.info("All expected containers are running.")
    return True


# ---------------------------------------------------------------------------
# Swap provisioning for low-memory systems
# ---------------------------------------------------------------------------

# Threshold: provision swap when total RAM is at or below this value.
_LOW_RAM_THRESHOLD_KB = 1_536_000  # ~1.5 GB (covers 1 GB VMs with slight variance)
_SWAP_SIZE_GB = 1
_SWAPFILE_PATH = Path("/swapfile")


def _get_total_ram_kb() -> int | None:
    """Read total physical RAM in kilobytes from /proc/meminfo.

    Returns None if the value cannot be determined (non-Linux or read error).
    """
    try:
        meminfo = Path("/proc/meminfo").read_text()
        for line in meminfo.splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                return int(parts[1])
    except (FileNotFoundError, ValueError, OSError, IndexError):
        pass
    return None


def _get_total_swap_kb() -> int:
    """Read total configured swap in kilobytes from /proc/meminfo.

    Returns 0 if swap cannot be determined.
    """
    try:
        meminfo = Path("/proc/meminfo").read_text()
        for line in meminfo.splitlines():
            if line.startswith("SwapTotal:"):
                parts = line.split()
                return int(parts[1])
    except (FileNotFoundError, ValueError, OSError, IndexError):
        pass
    return 0


def provision_swap_if_needed() -> bool:
    """Auto-provision a 1 GB swapfile if the system has ≤1.5 GB RAM and no swap.

    This ensures low-memory VMs (1 GB) can handle transient memory spikes
    during Docker image pulls, certbot renewals, and concurrent VPN clients.

    The function is idempotent:
    - If swap already exists (any amount), it does nothing.
    - If /swapfile already exists, it does nothing.
    - If RAM is above the threshold, it does nothing.

    Returns
    -------
    bool
        True if swap was provisioned, False if no action was taken.

    Raises
    ------
    DeployError
        If swap provisioning is attempted but fails.
    """
    total_ram = _get_total_ram_kb()
    if total_ram is None:
        logger.debug("Cannot determine RAM size — skipping swap provisioning.")
        return False

    ram_mb = total_ram / 1024
    if total_ram > _LOW_RAM_THRESHOLD_KB:
        logger.debug(
            "RAM is %.0f MB (above threshold) — swap provisioning not needed.", ram_mb
        )
        return False

    # Check if swap already exists
    existing_swap = _get_total_swap_kb()
    if existing_swap > 0:
        logger.debug(
            "Swap already configured (%d MB) — skipping provisioning.",
            existing_swap // 1024,
        )
        return False

    # Check if swapfile already exists on disk (maybe not activated)
    if _SWAPFILE_PATH.exists():
        logger.info(
            "%s already exists — activating it.", _SWAPFILE_PATH
        )
        _activate_existing_swapfile()
        return True

    # Provision new swapfile
    logger.info(
        "Low RAM detected (%.0f MB, no swap). Provisioning %d GB swapfile...",
        ram_mb,
        _SWAP_SIZE_GB,
    )

    try:
        _create_swapfile()
    except (subprocess.CalledProcessError, OSError) as exc:
        raise DeployError(
            service="system",
            step="provision_swap",
            message=f"Failed to provision swap: {exc}",
            remediation=(
                "Manually create swap:\n"
                f"  fallocate -l {_SWAP_SIZE_GB}G /swapfile\n"
                "  chmod 600 /swapfile\n"
                "  mkswap /swapfile\n"
                "  swapon /swapfile\n"
                "  echo '/swapfile none swap sw 0 0' >> /etc/fstab"
            ),
        ) from exc

    logger.info("Swap provisioned successfully (%d GB).", _SWAP_SIZE_GB)
    return True


def _create_swapfile() -> None:
    """Create, format, activate a swapfile and persist it in /etc/fstab."""
    swapfile = str(_SWAPFILE_PATH)

    # Allocate the file
    subprocess.run(
        ["fallocate", "-l", f"{_SWAP_SIZE_GB}G", swapfile],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    # Restrict permissions (swap must be 600)
    _SWAPFILE_PATH.chmod(0o600)

    # Format as swap
    subprocess.run(
        ["mkswap", swapfile],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Activate
    subprocess.run(
        ["swapon", swapfile],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Persist across reboots (idempotent — check if already in fstab)
    _persist_swapfile_in_fstab(swapfile)


def _activate_existing_swapfile() -> None:
    """Activate an existing /swapfile that isn't currently enabled."""
    swapfile = str(_SWAPFILE_PATH)

    # Ensure correct permissions
    _SWAPFILE_PATH.chmod(0o600)

    try:
        subprocess.run(
            ["swapon", swapfile],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        # May already be active or need mkswap first
        if "already" not in exc.stderr.lower():
            # Try formatting first, then activating
            subprocess.run(
                ["mkswap", swapfile],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            subprocess.run(
                ["swapon", swapfile],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )

    _persist_swapfile_in_fstab(swapfile)
    logger.info("Existing swapfile activated.")


def _persist_swapfile_in_fstab(swapfile: str) -> None:
    """Add swapfile entry to /etc/fstab if not already present."""
    fstab = Path("/etc/fstab")
    try:
        fstab_content = fstab.read_text()
        if swapfile in fstab_content:
            return  # Already persisted
        with fstab.open("a") as f:
            f.write(f"\n{swapfile} none swap sw 0 0\n")
        logger.debug("Added %s to /etc/fstab.", swapfile)
    except OSError as exc:
        logger.warning("Could not persist swap in /etc/fstab: %s", exc)
