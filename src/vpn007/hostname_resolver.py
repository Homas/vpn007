# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Hostname resolver generator for VPN007.

Generates a shell script, systemd service unit, and systemd timer unit
for periodically resolving hostnames in the approved-access list to IP
addresses and updating the Nginx ``approved_panel_ips.conf`` include
file.

The resolver script:
- Resolves each configured hostname to IPv4 and IPv6 addresses via
  ``dig``
- Generates an Nginx include file with ``allow`` directives for
  resolved IPs and static approved IPs
- Reloads Nginx only when resolved addresses have changed
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.models import DeployConfig

logger = logging.getLogger(__name__)

# Path to the templates directory within the vpn007 package.
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _create_jinja_env() -> Environment:
    """Create a Jinja2 environment configured for VPN007 templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_hostname_resolver(
    config: DeployConfig,
) -> tuple[str, str, str]:
    """Generate hostname resolver script, service unit, and timer unit.

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    tuple[str, str, str]
        A 3-tuple of (script_content, service_unit, timer_unit).
    """
    env = _create_jinja_env()

    output_dir = config.output_dir
    scripts_dir = str(output_dir / "scripts")
    nginx_conf_dir = str(output_dir / "nginx")
    compose_dir = str(output_dir)

    # Render the shell script
    script_template = env.get_template("hostname-resolver.sh.j2")
    script = script_template.render(
        hostnames=config.approved_hostnames,
        static_ips=config.approved_ips,
        ssh_hostnames=config.ssh_approved_hostnames,
        ssh_static_ips=config.ssh_approved_ips,
        nginx_conf_dir=nginx_conf_dir,
        compose_dir=compose_dir,
    )

    # Render the systemd service unit
    service_template = env.get_template("hostname-resolver.service.j2")
    service = service_template.render(scripts_dir=scripts_dir)

    # Render the systemd timer unit
    timer_template = env.get_template("hostname-resolver.timer.j2")
    timer = timer_template.render(
        hostname_resolve_interval_min=config.hostname_resolve_interval_min,
    )

    return script, service, timer
