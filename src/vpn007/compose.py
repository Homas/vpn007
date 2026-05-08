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
    - The custom AmneziaWG 2.0 image is always built from
      ``Dockerfile.amneziawg`` (wg-easy does not support 2.0).
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

    # Generate AWG panel admin credentials for unattended setup
    import secrets as _secrets
    import string as _string
    awg_admin_username = "admin" + "".join(
        _secrets.choice(_string.ascii_lowercase + _string.digits) for _ in range(3)
    )
    from vpn007.clients import generate_3xui_admin_credentials
    _, awg_admin_password = generate_3xui_admin_credentials()

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
        "awg_admin_username": awg_admin_username,
        "awg_admin_password": awg_admin_password,
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



