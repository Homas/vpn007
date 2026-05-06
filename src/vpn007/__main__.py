# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""CLI entry point for VPN007 deployer.

Usage::

    python -m vpn007 --domain vpn.example.com
    vpn007 --domain vpn.example.com --dry-run
"""

from __future__ import annotations

import logging
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

    # 6c. Start containers
    logger.info("Starting containers...")
    compose_path = config.output_dir / "docker-compose.yml"
    project_name = "vpn007"
    try:
        compose_up(compose_path, project_name)
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Failed to start containers after %d attempts. "
            "Check docker compose logs for details.",
            3,
        )
        logger.debug("Last error: %s", exc.stderr if hasattr(exc, "stderr") else exc)
        return EXIT_DOCKER_ERROR

    # 6d. Acquire TLS certificate
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

    # 6e. Apply firewall rules
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
        return EXIT_SYSTEM_ERROR

    # 6f. Install systemd timers
    logger.info("Installing systemd timers...")
    systemd_dir = config.output_dir / "systemd"
    try:
        install_systemd_timers(systemd_dir)
    except DeployError as exc:
        logger.error("Systemd timer installation failed: %s", exc.message)
        if exc.remediation:
            logger.info("Remediation: %s", exc.remediation)
        return EXIT_SYSTEM_ERROR

    # 6g. Provision AmneziaWG kernel module (non-fatal — falls back to userspace)
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

    # 6h. Run smoke tests
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
# Certbot helper
# ---------------------------------------------------------------------------


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
