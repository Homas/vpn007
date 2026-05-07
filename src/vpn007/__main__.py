# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""CLI entry point for VPN007 deployer.

Usage::

    python -m vpn007 --domain vpn.example.com
    vpn007 --domain vpn.example.com --dry-run
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path

from vpn007.cli import parse_args
from vpn007.config import load_config
from vpn007.models import DeployConfig, DeployError
from vpn007.validator import validate_config

# ---------------------------------------------------------------------------
# Exit codes per error category (see design doc)
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_CONFIG_ERROR = 1
EXIT_NETWORK_ERROR = 2
EXIT_DOCKER_ERROR = 3
EXIT_SYSTEM_ERROR = 4
EXIT_FATAL_ERROR = 5

# Map DeployError service hints to exit codes
_SERVICE_EXIT_MAP: dict[str, int] = {
    "config": EXIT_CONFIG_ERROR,
    "network": EXIT_NETWORK_ERROR,
    "docker": EXIT_DOCKER_ERROR,
    "system": EXIT_SYSTEM_ERROR,
}

logger = logging.getLogger("vpn007")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(log_path: Path, *, debug: bool = False) -> None:
    """Configure logging to both stdout and a deployment log file.

    Parameters
    ----------
    log_path:
        Path to the deployment log file.  Parent directories are created
        automatically if they don't exist.
    debug:
        When *True*, the console handler is set to DEBUG level so that full
        command stdout/stderr appears on the terminal.  When *False*
        (the default), the console shows INFO and above.
    """
    root = logging.getLogger("vpn007")
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls (e.g. in tests)
    root.handlers.clear()

    # --- File handler: always DEBUG, with timestamps ---
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(fh)

    # --- Console handler: INFO by default, DEBUG when --debug ---
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root.addHandler(ch)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Run the VPN007 deployer.

    Returns the process exit code (0 on success).
    """
    # 1. Parse CLI arguments
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        # argparse calls sys.exit on --help / --version / parse errors
        return exc.code if isinstance(exc.code, int) else EXIT_FATAL_ERROR

    # 2. Set up logging (needs output dir from args, fall back to defaults)
    debug = getattr(args, "debug", False) or False
    log_path = Path(
        getattr(args, "deployment_log_path", None) or "./deploy/deploy.log"
    )
    setup_logging(log_path, debug=debug)

    logger.info("VPN007 deployer starting")

    # 3. Load configuration
    try:
        logger.info("Loading configuration...")
        config = load_config(args)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_CONFIG_ERROR
        logger.error("Configuration loading failed (exit %s)", code)
        return code
    except DeployError as exc:
        logger.error("Configuration error: %s", exc)
        if exc.remediation:
            logger.info("Remediation: %s", exc.remediation)
        return EXIT_CONFIG_ERROR
    except TypeError as exc:
        # e.g. DeployConfig.__init__() missing required positional argument
        msg = str(exc)
        if "missing" in msg and "argument" in msg:
            # Extract field name from "missing 1 required positional argument: 'domain'"
            import re
            fields = re.findall(r"'(\w+)'", msg)
            field_names = ", ".join(f.upper() for f in fields)
            logger.error(
                "Missing required parameter: %s. "
                "Set it in .env file or pass via CLI (e.g. --domain vpn.example.com).",
                field_names,
            )
        else:
            logger.error("Configuration error: %s", exc)
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error loading config: %s", exc)
        return EXIT_FATAL_ERROR

    # 4. Validate configuration
    logger.info("Validating configuration...")
    errors = validate_config(config)
    if errors:
        for err in errors:
            logger.error("Validation error: %s", err)
        return EXIT_CONFIG_ERROR

    logger.info("Configuration valid")

    # 5. Generate all configuration files
    dry_run = getattr(args, "dry_run", False) or False

    try:
        from vpn007.generator import generate_all, generate_deployment_summary

        logger.info("Generating all configuration files to %s ...", config.output_dir)
        files = generate_all(config)
        logger.info("Generated %d files", len(files))

        summary = generate_deployment_summary(config, files)
        print(summary)

    except DeployError as exc:
        logger.error("Generation error: %s", exc)
        if exc.remediation:
            logger.info("Remediation: %s", exc.remediation)
        return _SERVICE_EXIT_MAP.get(exc.service, EXIT_FATAL_ERROR)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error during generation: %s", exc)
        return EXIT_FATAL_ERROR

    if dry_run:
        logger.info(
            "Dry-run complete — configs written to %s. "
            "No containers started, no firewall rules applied, "
            "no systemd timers installed, no kernel modules loaded.",
            config.output_dir,
        )
        return EXIT_OK

    # 6. Full deployment (prerequisites, containers, firewall, timers)
    from vpn007.docker_ops import compose_up
    from vpn007.prerequisites import (
        detect_os,
        run_prerequisite_checks,
    )
    from vpn007.system_ops import (
        apply_awg_userspace_fallback,
        apply_nftables,
        install_systemd_timers,
        persist_nftables,
        provision_awg_kernel_module,
        provision_swap_if_needed,
        smoke_test,
        verify_firewall_rules,
    )

    # 6a. Check prerequisites
    logger.info("Checking prerequisites...")
    try:
        distro, version = detect_os()
        logger.info("Detected OS: %s %s", distro, version)
    except Exception as exc:  # noqa: BLE001
        logger.error("OS detection failed: %s", exc)
        return EXIT_SYSTEM_ERROR

    prereq_ok, prereq_errors = run_prerequisite_checks()
    if not prereq_ok:
        for err in prereq_errors:
            logger.error("Prerequisite check failed: %s", err)
        return EXIT_SYSTEM_ERROR

    # 6b. Auto-provision swap on low-memory systems
    try:
        if provision_swap_if_needed():
            logger.info("Swap auto-provisioned for low-memory system.")
    except DeployError as exc:
        logger.warning("Swap provisioning failed (non-fatal): %s", exc.message)
        logger.info("Continuing without swap. %s", exc.remediation or "")

    # 6c. Set required kernel parameters
    logger.info("Setting kernel parameters...")
    _set_kernel_parameters()

    # 6d. Start containers
    logger.info("Starting containers...")
    compose_path = config.output_dir / "docker-compose.yml"
    project_name = "vpn007"
    try:
        compose_up(compose_path, project_name)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error(
            "Failed to start containers after %d attempts. "
            "Check docker compose logs for details.",
            3,
        )
        logger.debug("Last error: %s", exc)
        _print_cleanup_instructions(config)
        return EXIT_DOCKER_ERROR

    # 6d-2. Configure 3x-ui panel base path
    _configure_three_x_ui(config, compose_path)

    # 6d-3. Provision VLESS+Reality inbound in 3x-ui via API
    _provision_xray_inbound(config)

    # 6e. Apply firewall rules (before certbot — certbot needs to punch a hole)
    logger.info("Applying firewall rules...")
    nftables_path = config.output_dir / "nftables.conf"
    try:
        apply_nftables(nftables_path)
        persist_nftables(nftables_path)
        verify_firewall_rules()
    except DeployError as exc:
        logger.error("Firewall provisioning failed: %s", exc.message)
        if exc.remediation:
            logger.info("Remediation: %s", exc.remediation)
        _print_cleanup_instructions(config)
        return EXIT_SYSTEM_ERROR

    # 6f. Acquire TLS certificate
    logger.info("Acquiring TLS certificate...")
    if config.skip_certbot:
        logger.info("SKIP_CERTBOT is set — keeping self-signed certificate.")
    else:
        try:
            _run_certbot(config, compose_path)
        except DeployError as exc:
            logger.warning(
                "Certbot failed (non-fatal, using self-signed cert): %s",
                exc.message,
            )
            logger.info("You can retry manually: %s", exc.remediation or "")

    # 6g. Install systemd timers
    logger.info("Installing systemd timers...")
    systemd_dir = config.output_dir / "systemd"
    try:
        install_systemd_timers(systemd_dir)
    except DeployError as exc:
        logger.error("Systemd timer installation failed: %s", exc.message)
        if exc.remediation:
            logger.info("Remediation: %s", exc.remediation)
        _print_cleanup_instructions(config)
        return EXIT_SYSTEM_ERROR

    # 6h. Provision AmneziaWG kernel module (non-fatal — falls back to userspace)
    logger.info("Provisioning AmneziaWG kernel module...")
    kernel_module_loaded = provision_awg_kernel_module(distro)
    if not kernel_module_loaded:
        logger.info(
            "Using amneziawg-go userspace fallback (reduced performance)."
        )
        try:
            apply_awg_userspace_fallback(compose_path, project_name)
        except DeployError as exc:
            logger.warning(
                "Userspace fallback failed (non-fatal): %s", exc.message
            )

    # 6i. Run smoke tests
    logger.info("Running smoke tests...")
    test_results = smoke_test(config)
    all_passed = all(test_results.values())
    if all_passed:
        logger.info("All smoke tests passed.")
    else:
        failed = [k for k, v in test_results.items() if not v]
        logger.warning(
            "Some smoke tests failed: %s. "
            "Services may still be starting. Check with: docker compose ps",
            ", ".join(failed),
        )

    logger.info("Deployment complete.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Cleanup instructions
# ---------------------------------------------------------------------------


def _print_cleanup_instructions(config: DeployConfig) -> None:
    """Print cleanup instructions when deployment fails mid-way."""
    output_dir = config.output_dir
    logger.error("")
    logger.error("=" * 60)
    logger.error("  DEPLOYMENT FAILED — Cleanup Instructions")
    logger.error("=" * 60)
    logger.error("")
    logger.error("The deployment failed after partial setup. To clean up:")
    logger.error("")
    logger.error("  # 1. Stop and remove VPN007 containers")
    logger.error("  cd %s", output_dir)
    logger.error("  docker compose --project-name vpn007 down --remove-orphans")
    logger.error("")
    logger.error("  # 2. Remove any broken networks")
    logger.error("  docker network prune -f")
    logger.error("")
    logger.error("  # 3. Flush VPN007 firewall rules (if partially applied)")
    logger.error("  sudo nft delete table inet filter 2>/dev/null")
    logger.error("  sudo nft delete table ip nat 2>/dev/null")
    logger.error("")
    logger.error("  # 4. Disable VPN007 systemd timers (if partially installed)")
    logger.error(
        "  sudo systemctl disable --now "
        "blocklist-updater.timer hostname-resolver.timer "
        "certbot-renew.timer 2>/dev/null"
    )
    logger.error("")
    logger.error("After fixing the issue, re-run: sudo vpn007")
    logger.error("Client configs in %s/clients/ are preserved.", output_dir)
    logger.error("=" * 60)
    logger.error("")


# ---------------------------------------------------------------------------
# Certbot helper
# ---------------------------------------------------------------------------


def _set_kernel_parameters() -> None:
    """Set required kernel parameters for WireGuard/AmneziaWG and IP forwarding.

    These must be set on the host (not via Docker sysctls) because the
    AmneziaWG and Tailscale containers use network_mode: host.
    """
    params = [
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv4.conf.all.src_valid_mark", "1"),
    ]
    for param, value in params:
        try:
            subprocess.run(
                ["sysctl", "-w", f"{param}={value}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            logger.debug("Set %s = %s", param, value)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.warning("Failed to set %s=%s: %s", param, value, exc)


def _run_certbot(config: DeployConfig, compose_path: Path) -> None:
    """Acquire a TLS certificate via Let's Encrypt certbot.

    1. Temporarily opens port 80 in nftables for HTTP-01 challenge.
    2. Runs certbot via docker compose run --rm.
    3. Closes port 80.
    4. Reloads Nginx with the new certificate.

    Raises
    ------
    DeployError
        If certbot fails.
    """
    # Open port 80 temporarily
    logger.info("Opening port 80 for ACME challenge...")
    _nft_open_port_80()

    try:
        # Run certbot
        certbot_cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_path),
            "run",
            "--rm",
            "certbot",
            "certonly",
            "--webroot",
            "-w",
            "/var/www/certbot",
            "-d",
            config.domain,
            "--non-interactive",
            "--agree-tos",
            "--email",
            f"admin@{config.domain}",
        ]
        logger.info("Running certbot: %s", " ".join(certbot_cmd))

        result = subprocess.run(
            certbot_cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            raise DeployError(
                service="certbot",
                step="acquire_certificate",
                message=f"Certbot failed (exit {result.returncode}): "
                f"{result.stderr.strip()}",
                remediation=(
                    "Retry manually:\n"
                    f"  docker compose -f {compose_path} run --rm certbot "
                    f"certonly --webroot -w /var/www/certbot -d {config.domain}"
                ),
            )

        logger.info("TLS certificate acquired successfully.")

        # Copy the Let's Encrypt cert to the nginx self-signed directory
        # so nginx continues to use the same path (/etc/nginx/certs/).
        _copy_letsencrypt_cert_to_nginx(config)

    finally:
        # Always close port 80
        logger.info("Closing port 80...")
        _nft_close_port_80()

    # Reload Nginx to pick up the new cert
    logger.info("Reloading Nginx with new certificate...")
    reload_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "exec",
        "reverse_proxy",
        "nginx",
        "-s",
        "reload",
    ]
    try:
        subprocess.run(
            reload_cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        logger.info("Nginx reloaded with TLS certificate.")
    except subprocess.CalledProcessError as exc:
        logger.warning("Nginx reload failed: %s", exc.stderr.strip())


def _configure_three_x_ui(config: DeployConfig, compose_path: Path) -> None:
    """Configure 3x-ui panel webBasePath to match the nginx path prefix.

    Runs ``x-ui setting -webBasePath`` inside the 3x-ui container so the
    panel serves its assets and routes under the configured prefix path.
    This is required because 3x-ui generates absolute URLs for its assets.

    This is idempotent — setting the same path again is a no-op.
    """
    web_base_path = f"{config.xui_path_prefix}/"
    logger.info("Configuring 3x-ui webBasePath: %s", web_base_path)

    # Set the webBasePath via the x-ui CLI
    setting_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        "vpn007",
        "exec",
        "-T",
        "three_x_ui",
        "/app/x-ui",
        "setting",
        "-webBasePath",
        web_base_path,
    ]

    try:
        result = subprocess.run(
            setting_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning(
                "Failed to set 3x-ui webBasePath (exit %d): %s",
                result.returncode,
                result.stderr.strip(),
            )
            return
        logger.debug("x-ui setting output: %s", result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("Could not configure 3x-ui webBasePath: %s", exc)
        return

    # Restart 3x-ui to apply the new setting
    restart_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        "vpn007",
        "restart",
        "three_x_ui",
    ]

    try:
        subprocess.run(
            restart_cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        logger.info("3x-ui restarted with webBasePath: %s", web_base_path)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("Failed to restart 3x-ui: %s", exc)


def _provision_xray_inbound(config: DeployConfig) -> None:
    """Create the VLESS+Reality inbound and default client in 3x-ui via its API.

    Uses the 3x-ui REST API to:
    1. Log in with default credentials (admin/admin).
    2. Check if the inbound already exists (idempotent).
    3. Create the VLESS+Reality inbound with the default client UUID.

    This ensures the client config generated in
    ``/opt/vpn007/clients/xray-default-client.txt`` actually works.
    """
    import json
    import time
    import urllib.request
    import urllib.error

    # Resolve Reality keys (same logic as xray config generation)
    from vpn007.crypto import generate_reality_keypair

    reality_keys = config.reality_keys
    if reality_keys is None:
        # Keys were auto-generated during config generation; read them from
        # the generated xray config to stay consistent.
        xray_config_path = config.output_dir / "xray" / "config.json"
        if xray_config_path.exists():
            try:
                xray_data = json.loads(xray_config_path.read_text())
                inbounds = xray_data.get("inbounds", [])
                if inbounds:
                    rs = inbounds[0].get("streamSettings", {}).get("realitySettings", {})
                    from vpn007.models import RealityKeys
                    reality_keys = RealityKeys(
                        private_key=rs.get("privateKey", ""),
                        public_key="",  # not in server config
                        short_id=rs.get("shortIds", [""])[0],
                    )
            except (json.JSONDecodeError, KeyError, IndexError):
                pass

    if reality_keys is None:
        logger.warning("Cannot provision inbound: Reality keys not available.")
        return

    # Read the client UUID from the generated client config
    client_config_path = (
        config.output_dir / "clients" / f"xray-{config.xray_initial_client}.txt"
    )
    if not client_config_path.exists():
        logger.warning(
            "Cannot provision inbound: client config not found at %s",
            client_config_path,
        )
        return

    vless_link = client_config_path.read_text().strip()
    # Extract UUID from vless://{uuid}@...
    if not vless_link.startswith("vless://"):
        logger.warning("Invalid VLESS link format in client config.")
        return
    client_uuid = vless_link.split("@")[0].removeprefix("vless://")

    # 3x-ui API base URL (container is on bridge network at 172.20.0.3)
    base_url = "http://172.20.0.3:2053"
    web_base_path = config.xui_path_prefix

    # Wait for 3x-ui to be ready (it was just restarted)
    logger.info("Waiting for 3x-ui API to be ready...")
    for _ in range(10):
        try:
            req = urllib.request.Request(f"{base_url}{web_base_path}/")
            with urllib.request.urlopen(req, timeout=5):
                break
        except (urllib.error.URLError, OSError):
            time.sleep(2)
    else:
        logger.warning("3x-ui API not ready after 20s — skipping inbound provisioning.")
        return

    # Step 1: Login
    logger.info("Logging into 3x-ui API...")
    login_data = json.dumps({"username": "admin", "password": "admin"}).encode()
    login_req = urllib.request.Request(
        f"{base_url}{web_base_path}/login",
        data=login_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(login_req, timeout=10) as resp:
            login_resp = json.loads(resp.read())
            if not login_resp.get("success"):
                logger.info(
                    "3x-ui login with default credentials failed — "
                    "credentials may have been changed. Skipping inbound provisioning."
                )
                return
            # Extract session cookie
            cookie = resp.headers.get("Set-Cookie", "")
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("3x-ui login failed: %s", exc)
        return

    # Step 2: Check if inbound already exists
    list_req = urllib.request.Request(
        f"{base_url}{web_base_path}/panel/api/inbounds/list",
        headers={"Cookie": cookie},
    )
    try:
        with urllib.request.urlopen(list_req, timeout=10) as resp:
            list_resp = json.loads(resp.read())
            inbounds = list_resp.get("obj", [])
            for inbound in inbounds:
                if inbound.get("tag") == "vless-reality":
                    logger.info(
                        "VLESS+Reality inbound already exists in 3x-ui (id=%s) — skipping.",
                        inbound.get("id"),
                    )
                    return
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to list 3x-ui inbounds: %s", exc)
        return

    # Step 3: Create the inbound
    logger.info("Creating VLESS+Reality inbound with client %s...", client_uuid)

    inbound_settings = json.dumps({
        "clients": [
            {
                "id": client_uuid,
                "flow": "",
                "email": config.xray_initial_client,
                "limitIp": 0,
                "totalGB": 0,
                "expiryTime": 0,
                "enable": True,
            }
        ],
        "decryption": "none",
        "fallbacks": [],
    })

    stream_settings = json.dumps({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": f"{config.reality_sni}:443",
            "xver": 0,
            "serverNames": [config.reality_sni],
            "privateKey": reality_keys.private_key,
            "shortIds": [reality_keys.short_id],
        },
        "tcpSettings": {
            "acceptProxyProtocol": True,
            "header": {"type": "none"},
        },
    })

    sniffing = json.dumps({
        "enabled": True,
        "destOverride": ["http", "tls", "quic"],
    })

    add_data = json.dumps({
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": "VLESS+Reality (VPN007)",
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": config.xray_internal_port,
        "protocol": "vless",
        "settings": inbound_settings,
        "streamSettings": stream_settings,
        "tag": "vless-reality",
        "sniffing": sniffing,
    }).encode()

    add_req = urllib.request.Request(
        f"{base_url}{web_base_path}/panel/api/inbounds/add",
        data=add_data,
        headers={
            "Content-Type": "application/json",
            "Cookie": cookie,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(add_req, timeout=15) as resp:
            add_resp = json.loads(resp.read())
            if add_resp.get("success"):
                logger.info(
                    "VLESS+Reality inbound created successfully in 3x-ui."
                )
            else:
                logger.warning(
                    "3x-ui inbound creation returned: %s",
                    add_resp.get("msg", "unknown error"),
                )
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to create 3x-ui inbound: %s", exc)


def _copy_letsencrypt_cert_to_nginx(config: DeployConfig) -> None:
    """Copy Let's Encrypt certificate to the nginx self-signed directory.

    After certbot acquires a certificate, it lives at
    ``{output_dir}/data/letsencrypt/live/{domain}/``.  Nginx is configured
    to read certs from ``{output_dir}/nginx/self-signed/`` (mounted as
    ``/etc/nginx/certs/`` inside the container).  This function copies the
    LE cert files there so nginx uses the real certificate after reload.
    """
    le_live_dir = config.output_dir / "data" / "letsencrypt" / "live" / config.domain
    nginx_cert_dir = config.output_dir / "nginx" / "self-signed"

    fullchain_src = le_live_dir / "fullchain.pem"
    privkey_src = le_live_dir / "privkey.pem"

    if not fullchain_src.exists() or not privkey_src.exists():
        logger.warning(
            "Let's Encrypt cert files not found at %s — "
            "nginx will continue using self-signed certificate.",
            le_live_dir,
        )
        return

    try:
        shutil.copy2(str(fullchain_src), str(nginx_cert_dir / "fullchain.pem"))
        shutil.copy2(str(privkey_src), str(nginx_cert_dir / "privkey.pem"))
        logger.info(
            "Copied Let's Encrypt certificate to %s", nginx_cert_dir
        )
    except OSError as exc:
        logger.warning("Failed to copy LE cert to nginx dir: %s", exc)


def _nft_open_port_80() -> None:
    """Temporarily add an nftables rule to allow inbound TCP port 80."""
    try:
        subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                "tcp",
                "dport",
                "80",
                "accept",
                "comment",
                '"vpn007-certbot-temp"',
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.warning("Could not open port 80: %s", exc)


def _nft_close_port_80() -> None:
    """Remove the temporary port 80 rule from nftables."""
    try:
        # Find and delete the rule by comment
        result = subprocess.run(
            ["nft", "-a", "list", "chain", "inet", "filter", "input"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "vpn007-certbot-temp" in line and "handle" in line:
                    # Extract handle number
                    parts = line.strip().split()
                    handle_idx = parts.index("handle") + 1
                    handle = parts[handle_idx]
                    subprocess.run(
                        [
                            "nft",
                            "delete",
                            "rule",
                            "inet",
                            "filter",
                            "input",
                            "handle",
                            handle,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    break
    except (FileNotFoundError, OSError, ValueError, IndexError) as exc:
        logger.warning("Could not close port 80: %s", exc)


if __name__ == "__main__":
    sys.exit(main())
