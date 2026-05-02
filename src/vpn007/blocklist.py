# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Blocklist updater generator for VPN007.

Generates a shell script, systemd service unit, and systemd timer unit
for periodically re-resolving AS numbers to IP prefixes and updating
nftables named sets using atomic file loads.

The updater script:
- Resolves AS numbers via Team Cymru whois (primary) and RIPE RIS API
  (fallback)
- Updates nftables named sets atomically using ``nft -f`` with a
  temporary ``.nft`` file containing ``flush set`` + ``add element``
  commands
- Logs added/removed prefixes by comparing with cached results
- If all resolution sources are unreachable, keeps existing rules
  unchanged and logs a warning
"""

from __future__ import annotations

import ipaddress
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


def _classify_subnets(subnets: list[str]) -> tuple[list[str], list[str]]:
    """Split subnets into IPv4 and IPv6 lists."""
    v4: list[str] = []
    v6: list[str] = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            if net.version == 4:
                v4.append(str(net))
            else:
                v6.append(str(net))
        except ValueError:
            logger.warning("Skipping invalid subnet: %s", subnet)
    return v4, v6


def generate_blocklist_updater(
    config: DeployConfig,
) -> tuple[str, str, str]:
    """Generate blocklist updater script, service unit, and timer unit.

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

    static_v4, static_v6 = _classify_subnets(config.blocked_subnets)

    scripts_dir = str(config.output_dir / "scripts")

    # Render the shell script
    script_template = env.get_template("blocklist-updater.sh.j2")
    script = script_template.render(
        as_numbers=config.blocked_as_numbers,
        static_v4_subnets=static_v4,
        static_v6_subnets=static_v6,
    )

    # Render the systemd service unit
    service_template = env.get_template("blocklist-updater.service.j2")
    service = service_template.render(scripts_dir=scripts_dir)

    # Render the systemd timer unit
    timer_template = env.get_template("blocklist-updater.timer.j2")
    timer = timer_template.render(
        blocklist_update_interval_hours=config.blocklist_update_interval_hours,
    )

    return script, service, timer
