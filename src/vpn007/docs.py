# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Documentation generator for VPN007.

Renders Jinja2 templates (``README.md.j2``, ``troubleshooting.md.j2``,
``client-guides.md.j2``) with values from a
:class:`~vpn007.models.DeployConfig` instance, producing deployment
documentation files.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.models import DeployConfig

# Path to the templates directory within the vpn007 package.
_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Template filenames mapped to their output filenames.
_TEMPLATE_MAP: dict[str, str] = {
    "README.md.j2": "README.md",
    "troubleshooting.md.j2": "troubleshooting.md",
    "client-guides.md.j2": "client-guides.md",
}


def _create_jinja_env() -> Environment:
    """Create a Jinja2 environment configured for VPN007 doc templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _build_template_context(config: DeployConfig) -> dict:
    """Build the template context dictionary from a DeployConfig.

    Passes all relevant config fields to the documentation templates so
    they can render deployment-specific values (domain, ports, IPs, etc.).
    """
    return {
        # General
        "domain": config.domain,
        "reality_sni": config.reality_sni,
        "cover_site_mode": config.cover_site_mode.value,
        "cover_site_url": config.cover_site_url,
        # Routing
        "xui_path_prefix": config.xui_path_prefix,
        "awg_panel_path_prefix": config.awg_panel_path_prefix,
        "enable_port_8443": config.enable_port_8443,
        # Xray / Reality
        "xray_internal_port": config.xray_internal_port,
        # AmneziaWG
        "awg_listen_port": config.awg_listen_port,
        "awg_obfuscation": config.awg_obfuscation,
        "awg_panel_port": config.awg_panel_port,
        "use_custom_awg_image": config.use_custom_awg_image,
        # Tailscale
        "tailscale_auth_key": config.tailscale_auth_key,
        # Multi-IP
        "incoming_ip": config.incoming_ip,
        "outgoing_ip": config.outgoing_ip,
        "public_ipv4": config.public_ipv4,
        "public_ipv6": config.public_ipv6,
        # TLS
        "tls_versions": config.tls_versions,
        # Access control
        "approved_ips": config.approved_ips,
        "approved_hostnames": config.approved_hostnames,
        "ssh_approved_ips": config.ssh_approved_ips,
        "hostname_resolve_interval_min": config.hostname_resolve_interval_min,
        # Blocking
        "blocked_as_numbers": config.blocked_as_numbers,
        "blocked_subnets": config.blocked_subnets,
        "blocklist_update_interval_hours": config.blocklist_update_interval_hours,
        # Forwarding
        "forwarding_enabled": config.forwarding_enabled,
        "tunnel_type": config.tunnel_type.value if config.tunnel_type else None,
        "secondary_vm_ip": config.secondary_vm_ip,
        "reverse_initiated": config.reverse_initiated,
        "forwarding_ports": config.forwarding_ports,
        "reconnect_initial_delay_sec": config.reconnect_initial_delay_sec,
        "reconnect_max_delay_sec": config.reconnect_max_delay_sec,
    }


def generate_docs(config: DeployConfig) -> dict[str, str]:
    """Generate documentation files from deployment configuration.

    Renders all documentation Jinja2 templates with the provided config
    and returns a mapping of output filename to rendered content.

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    dict[str, str]
        Mapping of filename (e.g. ``"README.md"``) to rendered Markdown
        content.
    """
    env = _create_jinja_env()
    context = _build_template_context(config)
    result: dict[str, str] = {}

    for template_name, output_name in _TEMPLATE_MAP.items():
        template = env.get_template(template_name)
        result[output_name] = template.render(context)

    return result
