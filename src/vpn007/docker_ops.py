# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Docker Compose operations for VPN007 deployment.

Provides functions to bring up services, pull images, and detect existing
deployments for idempotent re-deployment.
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("vpn007")

# Retry configuration for compose_up
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5


def compose_up(compose_path: Path, project_name: str) -> None:
    """Run ``docker compose up -d`` with retry logic.

    Attempts the command up to 3 times with a 5-second delay between
    attempts. On each failed attempt the container logs from the failed
    run are captured and logged at DEBUG level.

    Parameters
    ----------
    compose_path:
        Path to the ``docker-compose.yml`` file.
    project_name:
        Docker Compose project name (``--project-name``).

    Raises
    ------
    subprocess.CalledProcessError
        If all retry attempts are exhausted.
    """
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        project_name,
        "up",
        "-d",
    ]

    last_error: subprocess.CalledProcessError | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(
            "Starting containers (attempt %d/%d): %s",
            attempt,
            MAX_RETRIES,
            " ".join(cmd),
        )
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            logger.debug("compose up stdout: %s", result.stdout)
            logger.debug("compose up stderr: %s", result.stderr)
            logger.info("Containers started successfully.")
            return
        except subprocess.CalledProcessError as exc:
            last_error = exc
            logger.warning(
                "compose up attempt %d/%d failed (exit code %d).",
                attempt,
                MAX_RETRIES,
                exc.returncode,
            )
            logger.debug("stdout: %s", exc.stdout)
            logger.debug("stderr: %s", exc.stderr)

            # Capture container logs for diagnostics
            _log_container_output(compose_path, project_name)

            if attempt < MAX_RETRIES:
                logger.info("Retrying in %d seconds...", RETRY_DELAY_SECONDS)
                time.sleep(RETRY_DELAY_SECONDS)

    # All attempts exhausted
    assert last_error is not None
    logger.error(
        "All %d compose up attempts failed. Last error: %s",
        MAX_RETRIES,
        last_error.stderr,
    )
    raise last_error


def _log_container_output(compose_path: Path, project_name: str) -> None:
    """Capture and log container output after a failed compose up attempt."""
    logs_cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "--project-name",
        project_name,
        "logs",
        "--tail",
        "50",
    ]
    try:
        logs_result = subprocess.run(
            logs_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if logs_result.stdout:
            logger.debug("Container logs:\n%s", logs_result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        logger.debug("Could not retrieve container logs.")


def compose_pull(compose_path: Path, service: str | None = None) -> None:
    """Pull latest Docker images for one or all services.

    Parameters
    ----------
    compose_path:
        Path to the ``docker-compose.yml`` file.
    service:
        Optional service name. When ``None``, pulls images for all services.

    Raises
    ------
    subprocess.CalledProcessError
        If the pull command fails.
    """
    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "pull",
    ]
    if service is not None:
        cmd.append(service)

    logger.info(
        "Pulling images%s: %s",
        f" for service '{service}'" if service else " for all services",
        " ".join(cmd),
    )

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        check=True,
    )
    logger.debug("compose pull stdout: %s", result.stdout)
    logger.debug("compose pull stderr: %s", result.stderr)
    logger.info("Image pull completed.")


def check_existing_deployment(compose_path: Path) -> dict[str, bool]:
    """Detect which services are already running for idempotent re-deployment.

    Uses ``docker compose ps --format json`` to query the current state of
    services defined in the compose file.

    Parameters
    ----------
    compose_path:
        Path to the ``docker-compose.yml`` file.

    Returns
    -------
    dict[str, bool]
        Mapping of service name → ``True`` if the service container is
        currently running, ``False`` otherwise. Returns an empty dict if
        the compose file has never been deployed or the command fails.
    """
    import json

    cmd = [
        "docker",
        "compose",
        "-f",
        str(compose_path),
        "ps",
        "--format",
        "json",
    ]

    logger.info("Checking existing deployment: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("Could not check existing deployment: %s", exc)
        return {}

    if result.returncode != 0:
        logger.debug(
            "compose ps returned non-zero exit code %d: %s",
            result.returncode,
            result.stderr,
        )
        return {}

    output = result.stdout.strip()
    if not output:
        return {}

    services: dict[str, bool] = {}

    # docker compose ps --format json may output one JSON object per line
    # or a JSON array depending on the Docker Compose version.
    try:
        parsed = json.loads(output)
        if isinstance(parsed, list):
            entries = parsed
        else:
            entries = [parsed]
    except json.JSONDecodeError:
        # Try line-by-line parsing (older compose versions)
        entries = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for entry in entries:
        name = entry.get("Service") or entry.get("Name", "")
        state = entry.get("State", "").lower()
        services[name] = state == "running"

    logger.info(
        "Existing deployment: %s",
        ", ".join(f"{k}={'running' if v else 'stopped'}" for k, v in services.items())
        or "none",
    )

    return services
