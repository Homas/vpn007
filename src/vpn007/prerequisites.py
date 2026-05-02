# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Host OS validation, dependency checking, and resource verification for VPN007.

This module provides functions to detect the host operating system, validate it
against the supported list, check for required dependencies, verify Docker daemon
accessibility, inspect kernel capabilities, and validate system resources before
deployment proceeds.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("vpn007")

# ---------------------------------------------------------------------------
# Supported operating systems: (distro_id, minimum_version_tuple)
# ---------------------------------------------------------------------------
SUPPORTED_OS: dict[str, tuple[int, ...]] = {
    "debian": (11,),
    "ubuntu": (22, 4),
    "alpine": (3, 18),
}

# ---------------------------------------------------------------------------
# Required dependencies: name → (binary_name, min_version, version_flag)
# ---------------------------------------------------------------------------
REQUIRED_DEPENDENCIES: dict[str, tuple[str, str, list[str]]] = {
    "docker": ("docker", "20.10.0", ["docker", "--version"]),
    "docker-compose": ("docker", "2.0.0", ["docker", "compose", "version"]),
    "python3": ("python3", "3.14.0", ["python3", "--version"]),
    "nftables": ("nft", "0.9.0", ["nft", "--version"]),
    "curl": ("curl", "7.0.0", ["curl", "--version"]),
    "git": ("git", "2.0.0", ["git", "--version"]),
}

# ---------------------------------------------------------------------------
# Package manager mappings: dependency → package name per distro family
# ---------------------------------------------------------------------------
_APT_PACKAGES: dict[str, str] = {
    "docker": "docker-ce",
    "docker-compose": "docker-compose-plugin",
    "python3": "python3",
    "nftables": "nftables",
    "curl": "curl",
    "git": "git",
}

_APK_PACKAGES: dict[str, str] = {
    "docker": "docker",
    "docker-compose": "docker-cli-compose",
    "python3": "python3",
    "nftables": "nftables",
    "curl": "curl",
    "git": "git",
}

# Minimum resource thresholds
MIN_RAM_GB = 2
MIN_DISK_GB = 10


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------


def detect_os() -> tuple[str, str]:
    """Detect the host OS distribution and version.

    Parses ``/etc/os-release`` to extract the distribution ID and version.

    Returns
    -------
    tuple[str, str]
        ``(distro_id, version_string)`` — e.g. ``("ubuntu", "22.04")`` or
        ``("alpine", "3.18.4")``.

    Raises
    ------
    FileNotFoundError
        If ``/etc/os-release`` does not exist.
    ValueError
        If the file cannot be parsed for ID or VERSION_ID.
    """
    os_release_path = Path("/etc/os-release")
    text = os_release_path.read_text()

    distro: str | None = None
    version: str | None = None

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("ID="):
            distro = line.split("=", 1)[1].strip().strip('"').lower()
        elif line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip().strip('"')

    if not distro:
        raise ValueError("Could not determine distribution ID from /etc/os-release")
    if not version:
        raise ValueError("Could not determine VERSION_ID from /etc/os-release")

    return distro, version


# ---------------------------------------------------------------------------
# OS validation
# ---------------------------------------------------------------------------


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints for comparison."""
    parts: list[int] = []
    for part in version_str.split("."):
        # Strip non-numeric suffixes (e.g. "3.18.4-r0" → "4")
        match = re.match(r"(\d+)", part)
        if match:
            parts.append(int(match.group(1)))
    return tuple(parts)


def validate_os(distro: str, version: str) -> list[str]:
    """Validate the detected OS against the supported list.

    Parameters
    ----------
    distro:
        Distribution ID (e.g. ``"debian"``, ``"ubuntu"``, ``"alpine"``).
    version:
        Version string (e.g. ``"22.04"``, ``"11"``, ``"3.18.4"``).

    Returns
    -------
    list[str]
        List of error messages. Empty if the OS is supported.
    """
    errors: list[str] = []
    distro_lower = distro.lower()

    if distro_lower not in SUPPORTED_OS:
        supported = ", ".join(
            f"{d.capitalize()} {'.'.join(str(v) for v in ver)}+"
            for d, ver in SUPPORTED_OS.items()
        )
        errors.append(
            f"Unsupported OS: {distro} {version}. "
            f"Supported distributions: {supported}"
        )
        return errors

    min_version = SUPPORTED_OS[distro_lower]
    detected_version = _parse_version(version)

    if detected_version < min_version:
        min_str = ".".join(str(v) for v in min_version)
        errors.append(
            f"{distro.capitalize()} {version} is below the minimum supported version "
            f"({min_str}+)"
        )

    return errors


# ---------------------------------------------------------------------------
# Dependency checking
# ---------------------------------------------------------------------------


def _extract_version(output: str) -> str | None:
    """Extract a version number from command output.

    Looks for patterns like ``1.2.3``, ``20.10.17``, etc.
    """
    match = re.search(r"(\d+\.\d+[\.\d]*)", output)
    return match.group(1) if match else None


def check_dependencies() -> dict[str, str | None]:
    """Check presence and versions of all required host dependencies.

    Returns
    -------
    dict[str, str | None]
        Mapping of dependency name → detected version string, or ``None``
        if the dependency is not found.
    """
    results: dict[str, str | None] = {}

    for dep_name, (binary, _min_ver, version_cmd) in REQUIRED_DEPENDENCIES.items():
        # First check if the binary exists on PATH
        if not shutil.which(binary):
            results[dep_name] = None
            continue

        # Try to get the version
        try:
            proc = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = proc.stdout + proc.stderr
            version = _extract_version(output)
            results[dep_name] = version
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            results[dep_name] = None

    return results


# ---------------------------------------------------------------------------
# Missing dependency detection
# ---------------------------------------------------------------------------


def get_missing_dependencies(deps: dict[str, str | None]) -> list[str]:
    """Identify dependencies that are missing or below minimum version.

    Parameters
    ----------
    deps:
        Output from :func:`check_dependencies`.

    Returns
    -------
    list[str]
        Names of dependencies that are missing or below minimum version.
    """
    missing: list[str] = []

    for dep_name, detected_version in deps.items():
        if detected_version is None:
            missing.append(dep_name)
            continue

        _binary, min_ver_str, _cmd = REQUIRED_DEPENDENCIES[dep_name]
        min_ver = _parse_version(min_ver_str)
        detected_ver = _parse_version(detected_version)

        if detected_ver < min_ver:
            missing.append(dep_name)

    return missing


# ---------------------------------------------------------------------------
# Dependency installation
# ---------------------------------------------------------------------------


def install_missing_dependencies(missing: list[str], distro: str) -> list[str]:
    """Build and execute package install commands for missing dependencies.

    Parameters
    ----------
    missing:
        List of dependency names to install.
    distro:
        Distribution ID (``"debian"``, ``"ubuntu"``, or ``"alpine"``).

    Returns
    -------
    list[str]
        The shell command that was (or would be) executed, as a list of
        arguments.

    Raises
    ------
    ValueError
        If the distro is not supported for package installation.
    """
    if not missing:
        return []

    distro_lower = distro.lower()

    if distro_lower in ("debian", "ubuntu"):
        pkg_map = _APT_PACKAGES
        packages = [pkg_map[dep] for dep in missing if dep in pkg_map]
        if not packages:
            return []
        cmd = ["apt-get", "install", "-y"] + packages
    elif distro_lower == "alpine":
        pkg_map = _APK_PACKAGES
        packages = [pkg_map[dep] for dep in missing if dep in pkg_map]
        if not packages:
            return []
        cmd = ["apk", "add", "--no-cache"] + packages
    else:
        raise ValueError(
            f"Unsupported distro for package installation: {distro}. "
            "Supported: debian, ubuntu, alpine."
        )

    logger.info("Installing missing dependencies: %s", " ".join(packages))
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return cmd


# ---------------------------------------------------------------------------
# Docker daemon check
# ---------------------------------------------------------------------------


def check_docker_daemon() -> bool:
    """Verify that the Docker daemon is running and accessible.

    Returns
    -------
    bool
        ``True`` if ``docker info`` succeeds, ``False`` otherwise.
    """
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# Kernel capabilities check
# ---------------------------------------------------------------------------


def check_kernel_capabilities(distro: str | None = None) -> list[str]:
    """Verify kernel capabilities required for VPN container operation.

    Checks for:
    - ``/dev/net/tun`` device availability
    - ``NET_ADMIN`` capability support (via ``/proc/1/status``)
    - ``SYS_MODULE`` capability support

    On Alpine Linux, skips kernel header checks for AmneziaWG and notes
    that ``amneziawg-go`` userspace implementation will be used.

    Parameters
    ----------
    distro:
        Optional distribution ID. When ``"alpine"``, kernel header checks
        are skipped.

    Returns
    -------
    list[str]
        List of warning messages. Empty if all capabilities are available.
    """
    warnings: list[str] = []

    # Check /dev/net/tun
    tun_path = Path("/dev/net/tun")
    if not tun_path.exists():
        warnings.append(
            "/dev/net/tun is not available. "
            "VPN containers (AmneziaWG, Tailscale) require TUN device support."
        )

    # Check capability support by reading /proc/1/status for CapBnd
    try:
        status_text = Path("/proc/1/status").read_text()
        cap_bnd_line = None
        for line in status_text.splitlines():
            if line.startswith("CapBnd:"):
                cap_bnd_line = line.split(":", 1)[1].strip()
                break

        if cap_bnd_line:
            cap_bnd = int(cap_bnd_line, 16)
            # CAP_NET_ADMIN = 12, CAP_SYS_MODULE = 16
            if not (cap_bnd & (1 << 12)):
                warnings.append(
                    "NET_ADMIN capability is not available in the bounding set. "
                    "VPN containers require NET_ADMIN."
                )
            if not (cap_bnd & (1 << 16)):
                warnings.append(
                    "SYS_MODULE capability is not available in the bounding set. "
                    "AmneziaWG kernel module loading requires SYS_MODULE."
                )
    except (FileNotFoundError, ValueError, OSError):
        warnings.append(
            "Could not read /proc/1/status to verify kernel capabilities. "
            "Ensure NET_ADMIN and SYS_MODULE are available."
        )

    # Alpine-specific: skip kernel header checks, note amneziawg-go usage
    if distro and distro.lower() == "alpine":
        logger.info(
            "Alpine Linux detected: skipping kernel header checks for AmneziaWG. "
            "The amneziawg-go userspace implementation will be used."
        )
        warnings.append(
            "Alpine Linux: kernel headers not checked. "
            "AmneziaWG will use amneziawg-go userspace implementation "
            "(reduced performance compared to kernel module)."
        )

    return warnings


# ---------------------------------------------------------------------------
# System resource checks
# ---------------------------------------------------------------------------


def check_system_resources() -> list[str]:
    """Verify that the host has sufficient RAM and disk space.

    Checks:
    - Total RAM >= 2 GB
    - Free disk space on the root filesystem >= 10 GB

    Returns
    -------
    list[str]
        List of warning messages. Empty if resources are sufficient.
    """
    warnings: list[str] = []

    # Check RAM via /proc/meminfo
    try:
        meminfo_text = Path("/proc/meminfo").read_text()
        for line in meminfo_text.splitlines():
            if line.startswith("MemTotal:"):
                # Format: "MemTotal:       16384000 kB"
                parts = line.split()
                mem_kb = int(parts[1])
                mem_gb = mem_kb / (1024 * 1024)
                if mem_gb < MIN_RAM_GB:
                    warnings.append(
                        f"Insufficient RAM: {mem_gb:.1f} GB detected, "
                        f"minimum {MIN_RAM_GB} GB required."
                    )
                break
    except (FileNotFoundError, ValueError, OSError, IndexError):
        warnings.append(
            "Could not read /proc/meminfo to check available RAM."
        )

    # Check disk space via `df` command
    try:
        result = subprocess.run(
            ["df", "--output=avail", "-B1", "/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            if len(lines) >= 2:
                avail_bytes = int(lines[1].strip())
                avail_gb = avail_bytes / (1024**3)
                if avail_gb < MIN_DISK_GB:
                    warnings.append(
                        f"Insufficient disk space: {avail_gb:.1f} GB available, "
                        f"minimum {MIN_DISK_GB} GB required."
                    )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        warnings.append(
            "Could not check available disk space."
        )

    return warnings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_prerequisite_checks() -> tuple[bool, list[str]]:
    """Run all prerequisite checks and return overall status.

    This is the main entry point called by ``__main__.py`` before deployment.

    Returns
    -------
    tuple[bool, list[str]]
        ``(ok, messages)`` where *ok* is ``True`` if all critical checks pass
        and *messages* contains informational, warning, and error messages.
    """
    messages: list[str] = []
    ok = True

    # 1. Detect and validate OS
    try:
        distro, version = detect_os()
        messages.append(f"Detected OS: {distro.capitalize()} {version}")
    except (FileNotFoundError, ValueError) as exc:
        messages.append(f"ERROR: OS detection failed: {exc}")
        ok = False
        distro, version = "unknown", "0"

    os_errors = validate_os(distro, version)
    if os_errors:
        messages.extend(f"ERROR: {e}" for e in os_errors)
        ok = False

    # 2. Check dependencies
    deps = check_dependencies()
    for dep_name, dep_version in deps.items():
        if dep_version:
            messages.append(f"  {dep_name}: {dep_version}")
        else:
            messages.append(f"  {dep_name}: NOT FOUND")

    missing = get_missing_dependencies(deps)
    if missing:
        messages.append(f"Missing or outdated dependencies: {', '.join(missing)}")
        try:
            install_missing_dependencies(missing, distro)
            messages.append("Successfully installed missing dependencies.")
        except (subprocess.CalledProcessError, ValueError) as exc:
            messages.append(f"ERROR: Failed to install dependencies: {exc}")
            ok = False

    # 3. Check Docker daemon
    if not check_docker_daemon():
        messages.append(
            "ERROR: Docker daemon is not running or not accessible. "
            "Start Docker with: sudo systemctl start docker"
        )
        ok = False
    else:
        messages.append("Docker daemon: running")

    # 4. Check kernel capabilities
    kernel_warnings = check_kernel_capabilities(distro)
    for w in kernel_warnings:
        messages.append(f"WARNING: {w}")

    # 5. Check system resources
    resource_warnings = check_system_resources()
    for w in resource_warnings:
        messages.append(f"WARNING: {w}")

    return ok, messages
