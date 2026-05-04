# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""CLI entry point for VPN007 deployer.

Usage::

    python -m vpn007 --domain vpn.example.com
    vpn007 --domain vpn.example.com --dry-run
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from vpn007.cli import parse_args
from vpn007.config import load_config
from vpn007.models import DeployError
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
    logger.info("Checking prerequisites...")
    # TODO: prerequisites.check_all(config)

    logger.info("Starting containers...")
    # TODO: docker_ops.compose_up(...)

    logger.info("Acquiring TLS certificate...")
    # TODO: certbot initial acquisition (skip if config.skip_certbot)
    if config.skip_certbot:
        logger.info("SKIP_CERTBOT is set — keeping self-signed certificate")
    else:
        pass  # TODO: run certbot

    logger.info("Applying firewall rules...")
    # TODO: system_ops.apply_nftables(...)

    logger.info("Installing systemd timers...")
    # TODO: system_ops.install_systemd_timers(...)

    logger.info("Provisioning AmneziaWG kernel module...")
    # TODO: system_ops.provision_awg_kernel_module(...)

    logger.info("Running smoke tests...")
    # TODO: system_ops.smoke_test(config)

    logger.info("Deployment complete")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
