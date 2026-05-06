# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Inter-VM forwarding script generator for VPN007.

Renders the ``forwarding-script.py.j2`` Jinja2 template with values from a
:class:`~vpn007.models.DeployConfig` instance, producing a standalone
Python 3.10+ script that can be executed on a secondary VM to establish
an encrypted tunnel back to the primary VM and configure nftables
DNAT/SNAT forwarding rules.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.models import DeployConfig

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


def generate_forwarding_script(config: DeployConfig) -> str:
    """Generate a standalone Python 3.10+ forwarding script for a secondary VM.

    The generated script targets Python 3.10+ for broad compatibility on
    secondary VMs that may not have the latest Python.  It avoids 3.12+
    features (e.g., type parameter syntax) but uses match statements
    (3.10+) and union type hints (3.10+ with ``from __future__ import
    annotations``).

    The script:

    1. Installs the tunnel endpoint (WireGuard/AmneziaWG, SSH with
       autossh, or Tailscale) on the secondary VM.
    2. Configures nftables DNAT/SNAT rules for each port forward.
    3. Sets up auto-reconnection with exponential backoff (initial_delay
       doubling to max_delay).
    4. Supports reverse-initiated connections (secondary VM connects back
       to the primary VM).

    Parameters
    ----------
    config:
        The deployment configuration.  Must have ``forwarding_enabled``
        set to ``True`` and ``tunnel_type``, ``secondary_vm_ip``, and
        ``forwarding_ports`` populated.

    Returns
    -------
    str
        The rendered Python script content.
    """
    import ipaddress as _ipaddress

    env = _create_jinja_env()
    template = env.get_template("forwarding-script.py.j2")

    # Build port forwards as a list of dicts for the template.
    port_forwards = [
        {
            "protocol": pf.protocol,
            "listen_port": pf.listen_port,
            "forward_port": pf.forward_port,
            "description": pf.description,
        }
        for pf in config.forwarding_ports
    ]

    # Compute tunnel IPs from subnet
    tunnel_net = _ipaddress.ip_network(config.tunnel_subnet, strict=False)
    tunnel_hosts = list(tunnel_net.hosts())
    # .1 = primary VM side, .2 = secondary VM side
    tunnel_primary_ip = str(tunnel_hosts[0]) if len(tunnel_hosts) >= 2 else "10.99.0.1"
    tunnel_secondary_ip = str(tunnel_hosts[1]) if len(tunnel_hosts) >= 2 else "10.99.0.2"

    context = {
        # Primary VM connection info
        "primary_vm_ip": config.incoming_ip or config.public_ipv4 or "REPLACE_ME",
        "secondary_vm_ip": config.secondary_vm_ip or "REPLACE_ME",
        # Tunnel configuration
        "tunnel_type": config.tunnel_type.value if config.tunnel_type else "wireguard",
        "reverse_initiated": config.reverse_initiated,
        # Tunnel subnet and IPs
        "tunnel_subnet": config.tunnel_subnet,
        "tunnel_primary_ip": tunnel_primary_ip,
        "tunnel_secondary_ip": tunnel_secondary_ip,
        # Port forwarding rules
        "forwarding_ports": port_forwards,
        # Reconnection parameters
        "reconnect_initial_delay_sec": config.reconnect_initial_delay_sec,
        "reconnect_max_delay_sec": config.reconnect_max_delay_sec,
    }

    return template.render(context)
