# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Docker Compose configuration generator for VPN007.

Renders the ``docker-compose.yml.j2`` Jinja2 template with values from a
:class:`~vpn007.models.DeployConfig` instance, producing a complete Docker
Compose file that defines five long-running services (reverse_proxy,
three_x_ui, amneziawg, tailscale, cover_site) plus a certbot utility
container.
"""

from __future__ import annotations

import random
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.crypto import generate_awg_obfuscation
from vpn007.models import AwgObfuscation, CoverSiteMode, DeployConfig

# Path to the templates directory within the vpn007 package.
_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Range for random AWG UDP port to avoid standard WireGuard fingerprinting.
_AWG_PORT_MIN = 10000
_AWG_PORT_MAX = 65535


def _create_jinja_env() -> Environment:
    """Create a Jinja2 environment configured for VPN007 templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _resolve_awg_listen_port(config: DeployConfig) -> int:
    """Resolve the AmneziaWG listen port.

    If ``config.awg_listen_port`` is ``None``, generate a random high port
    in the range 10000–65535 to avoid the standard WireGuard port (51820)
    which is easily fingerprinted by DPI systems.  If a port is explicitly
    set, return it unchanged.
    """
    if config.awg_listen_port is not None:
        return config.awg_listen_port
    return random.randint(_AWG_PORT_MIN, _AWG_PORT_MAX)


def _resolve_awg_obfuscation(config: DeployConfig) -> AwgObfuscation:
    """Resolve AmneziaWG 2.0 obfuscation parameters.

    If ``config.awg_obfuscation`` is ``None``, auto-generate a full set of
    random obfuscation parameters within valid 2.0 ranges using
    :func:`~vpn007.crypto.generate_awg_obfuscation`.  If parameters are
    explicitly provided, return them unchanged.
    """
    if config.awg_obfuscation is not None:
        return config.awg_obfuscation
    return generate_awg_obfuscation()


def generate_compose(config: DeployConfig) -> str:
    """Generate ``docker-compose.yml`` content from a deployment config.

    Returns the rendered YAML string defining all services:

    **Long-running services** (start with ``docker compose up -d``):

    - ``reverse_proxy`` — Nginx with stream module for L4 SNI routing and
      L7 path-based routing with TLS termination.
    - ``three_x_ui`` — 3x-ui panel with embedded Xray for VLESS+Reality.
    - ``amneziawg`` — AmneziaWG 2.0 VPN with web panel (host network).
    - ``tailscale`` — Tailscale mesh VPN client (host network).
    - ``cover_site`` — Nginx serving a legitimate cover website.

    **Utility containers** (invoked on demand):

    - ``certbot`` — Certificate management via ``docker compose run --rm
      certbot``. Uses ``profiles: [certbot]`` so it does not start with
      ``docker compose up``.

    AmneziaWG 2.0 specifics:

    - If ``awg_listen_port`` is ``None``, a random high port (10000–65535)
      is chosen to avoid standard WireGuard fingerprinting.
    - If ``awg_obfuscation`` is ``None``, random 2.0 obfuscation parameters
      are auto-generated via :func:`~vpn007.crypto.generate_awg_obfuscation`.
    - The AmneziaWG panel is bound to ``127.0.0.1`` (local-only) by default.
    - ``EXPERIMENTAL_AWG=true`` and ``OVERRIDE_AUTO_AWG=awg`` are always set.
    """
    env = _create_jinja_env()
    template = env.get_template("docker-compose.yml.j2")

    context = _build_template_context(config)
    return template.render(context)


def _build_template_context(config: DeployConfig) -> dict:
    """Build the template context dictionary from a DeployConfig.

    String values are sanitized to remove control characters that would
    produce invalid YAML output.  AWG listen port and obfuscation parameters
    are resolved (auto-generated if not explicitly provided).
    """
    awg_listen_port = _resolve_awg_listen_port(config)
    awg_obfuscation = _resolve_awg_obfuscation(config)

    return {
        # General
        "domain": _yaml_safe(config.domain),
        "incoming_ip": _yaml_safe(config.incoming_ip) if config.incoming_ip else None,
        "enable_port_8443": config.enable_port_8443,
        "https_port": config.https_port,
        # AmneziaWG
        "awg_listen_port": awg_listen_port,
        "awg_panel_port": config.awg_panel_port,
        "awg_obfuscation": awg_obfuscation,
        "use_custom_awg_image": config.use_custom_awg_image,
        # Tailscale
        "tailscale_auth_key": (
            _yaml_safe(config.tailscale_auth_key)
            if config.tailscale_auth_key
            else None
        ),
        "tailscale_hostname": (
            _yaml_safe(config.tailscale_hostname)
            if config.tailscale_hostname
            else None
        ),
        "tailscale_extra_args": _yaml_safe(config.tailscale_extra_args),
        # Cover site
        "cover_site_mode": config.cover_site_mode.value,
        "cover_site_url": config.cover_site_url,
        "cover_site_static_path": (
            str(config.cover_site_static_path)
            if config.cover_site_static_path
            else None
        ),
    }


def validate_awg_2_0_support(container_name: str = "vpn007_amneziawg") -> None:
    """Validate that the deployed AmneziaWG instance supports 2.0 parameters.

    Checks the ``awg`` tool version and kernel module version inside the
    running container.  Raises :class:`RuntimeError` with a clear message
    if 2.0 support is not available.

    Parameters
    ----------
    container_name:
        Name of the running AmneziaWG Docker container.

    Raises
    ------
    RuntimeError
        If the ``awg`` tool or kernel module does not report a 2.0-compatible
        version, or if the container is not running / the tool is missing.
    """
    # Check awg tool version inside the container.
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "awg", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "AmneziaWG 2.0 validation failed: 'docker' command not found. "
            "Ensure Docker is installed and accessible."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"AmneziaWG 2.0 validation failed: timed out checking awg tool "
            f"version in container '{container_name}'."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"AmneziaWG 2.0 validation failed: 'awg --version' exited with "
            f"code {result.returncode} in container '{container_name}'. "
            f"stderr: {result.stderr.strip()!r}. "
            f"Ensure the container is running and the awg tool is installed."
        )

    awg_version_output = result.stdout.strip()
    if not _is_awg_2_0_compatible(awg_version_output):
        raise RuntimeError(
            f"AmneziaWG 2.0 validation failed: awg tool reports version "
            f"{awg_version_output!r} which does not appear to be 2.0+. "
            f"The full AmneziaWG 2.0 parameter set (S3, S4, H1-H4, I1-I5) "
            f"requires awg tools version 2.0 or later. Consider building "
            f"the custom image from Dockerfile.amneziawg."
        )

    # Check kernel module version via /sys or modinfo inside the container.
    try:
        mod_result = subprocess.run(
            ["docker", "exec", container_name, "cat",
             "/sys/module/amneziawg/version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # If we can't check the kernel module, the awg-go userspace fallback
        # may be in use — that's acceptable as long as the tool version is 2.0+.
        return

    if mod_result.returncode == 0:
        module_version = mod_result.stdout.strip()
        if not _is_awg_2_0_compatible(module_version):
            raise RuntimeError(
                f"AmneziaWG 2.0 validation failed: kernel module reports "
                f"version {module_version!r} which does not appear to be "
                f"2.0+. The full AmneziaWG 2.0 parameter set requires "
                f"kernel module version 2.0 or later."
            )
    # If the kernel module file doesn't exist (returncode != 0), the
    # amneziawg-go userspace implementation may be in use, which is fine.


def _is_awg_2_0_compatible(version_string: str) -> bool:
    """Check whether a version string indicates AmneziaWG 2.0+ support.

    Accepts version strings like ``"amneziawg-tools v2.0.0"``,
    ``"2.0.1"``, ``"v2.1.0"``, etc.  Returns ``True`` if the major
    version is >= 2, or if the string contains ``"2.0"`` or higher.
    """
    import re

    # Try to extract a semver-like version number.
    match = re.search(r"(\d+)\.(\d+)", version_string)
    if match:
        major = int(match.group(1))
        return major >= 2

    # Fallback: check for "2.0" substring (handles non-standard formats).
    return "2.0" in version_string or "2.1" in version_string


def _yaml_safe(value: str | None) -> str | None:
    """Strip control characters from a string to ensure valid YAML output.

    Removes ASCII control characters (0x00–0x1F except 0x0A newline) and
    the DEL character (0x7F), plus Unicode surrogates and non-characters
    that YAML parsers reject.
    """
    if value is None:
        return None
    # Keep only printable characters and newlines
    return "".join(
        ch for ch in value
        if ch == "\n" or (ch >= " " and ch != "\x7f" and ord(ch) < 0xFFFE)
    )


def enable_custom_awg_fallback(config: DeployConfig) -> DeployConfig:
    """Enable the custom AmneziaWG image fallback on a DeployConfig.

    Called when :func:`validate_awg_2_0_support` fails, indicating the
    official ``wg-easy`` image does not support the full AmneziaWG 2.0
    parameter set.  Returns a **new** ``DeployConfig`` with
    ``use_custom_awg_image`` set to ``True`` so that
    :func:`generate_compose` renders a ``build:`` directive pointing to
    ``Dockerfile.amneziawg`` instead of the ``image:`` reference.

    Parameters
    ----------
    config:
        The original deployment configuration.

    Returns
    -------
    DeployConfig
        A copy of *config* with ``use_custom_awg_image = True``.
    """
    from dataclasses import replace

    return replace(config, use_custom_awg_image=True)


def check_and_fallback_awg(
    config: DeployConfig,
    container_name: str = "vpn007_amneziawg",
) -> DeployConfig:
    """Validate AmneziaWG 2.0 support and fall back to custom image if needed.

    Attempts to validate the running AmneziaWG container.  If validation
    fails (the official image lacks 2.0 support), returns a new config
    with ``use_custom_awg_image = True``.  If validation succeeds, returns
    the original config unchanged.

    This is the primary entry point for the fallback logic described in
    Requirements 4.3 and 4.4.

    Parameters
    ----------
    config:
        The current deployment configuration.
    container_name:
        Name of the running AmneziaWG Docker container.

    Returns
    -------
    DeployConfig
        Either the original config (2.0 supported) or a copy with
        ``use_custom_awg_image = True`` (fallback triggered).
    """
    try:
        validate_awg_2_0_support(container_name)
        return config
    except RuntimeError:
        return enable_custom_awg_fallback(config)
