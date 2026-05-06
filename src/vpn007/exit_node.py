# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Exit node role configuration generator for VPN007.

When a VM runs the full VPN007 stack AND also serves as an exit node for
another VPN007 instance, this module generates the additional configuration
files needed for the exit-node role:

1. A WireGuard tunnel config (separate interface from the main AWG VPN)
2. An nftables include with DNAT/SNAT rules in a separate table
   (``vpn007_exit_node``) that doesn't conflict with the main firewall
3. A systemd service for the exit-node tunnel

The exit-node tunnel uses a different subnet (default ``10.99.1.0/30``)
and a different WireGuard listen port (default ``51822``) to avoid any
collision with the primary forwarding tunnel (``10.99.0.0/30:51821``).

Architecture when both forwarding and exit-node are enabled on the same VM::

    ┌─────────────────────────────────────────────────────────────┐
    │  This VM                                                     │
    │                                                              │
    │  [VPN007 stack] ─── tunnel (10.99.0.0/30) ──→ VM-B (exit)  │
    │       ↑                                                      │
    │  [Exit node role] ←── tunnel (10.99.1.0/30) ── VM-C (entry)│
    │       │                                                      │
    │       └──→ Internet (masquerade)                             │
    └─────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.crypto import generate_wg_keypair
from vpn007.models import DeployConfig, TunnelType

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


def _subnet_to_ips(subnet: str) -> tuple[str, str]:
    """Extract the two usable host IPs from a /30 subnet.

    Returns (local_ip, peer_ip) where local is .2 (exit node side)
    and peer is .1 (entrance node side).
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    # .1 = entrance/peer side, .2 = exit/local side
    return str(hosts[1]), str(hosts[0])


def _tunnel_interface_name(tunnel_type: TunnelType) -> str:
    """Return the expected tunnel interface name for the exit-node role."""
    if tunnel_type == TunnelType.WIREGUARD:
        return "wg-exit-node"
    if tunnel_type == TunnelType.TAILSCALE:
        return "tailscale0"
    return "tun-exit"


def generate_exit_node_nftables(config: DeployConfig) -> str:
    """Generate nftables rules for the exit-node role.

    These rules live in a separate table (``ip vpn007_exit_node``) and
    handle masquerading traffic from the tunnel peer to the internet.
    They do NOT interfere with the main ``inet filter`` table.
    """
    env = _create_jinja_env()
    template = env.get_template("exit-node-nftables.conf.j2")

    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)
    tunnel_iface = _tunnel_interface_name(config.exit_node_tunnel_type or TunnelType.WIREGUARD)

    context = {
        "peer_ip": config.exit_node_peer_ip,
        "tunnel_type": (config.exit_node_tunnel_type or TunnelType.WIREGUARD).value,
        "tunnel_subnet": config.exit_node_tunnel_subnet,
        "local_tunnel_ip": local_ip,
        "peer_tunnel_ip": peer_ip,
        "tunnel_interface": tunnel_iface,
    }

    return template.render(context)


def generate_exit_node_wg_config(config: DeployConfig) -> tuple[str, str, str]:
    """Generate WireGuard config for the exit-node tunnel endpoint.

    Returns
    -------
    tuple[str, str, str]
        (wg_conf_content, private_key, public_key)
        The private key is embedded in the config; the public key must be
        shared with the peer VM.
    """
    env = _create_jinja_env()
    template = env.get_template("exit-node-wg.conf.j2")

    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)
    private_key, public_key = generate_wg_keypair()

    # The peer's public key needs to be provided by the operator or
    # generated on the peer side. We use a placeholder.
    peer_public_key = "REPLACE_WITH_PEER_PUBLIC_KEY"

    # Determine the peer's listen port (their forwarding tunnel port)
    # Default to 51821 (standard forwarding tunnel port)
    peer_listen_port = 51821

    nftables_conf_path = f"{config.output_dir}/exit-node/nftables-exit-node.conf"

    context = {
        "private_key": private_key,
        "local_tunnel_ip": local_ip,
        "listen_port": config.exit_node_listen_port,
        "peer_public_key": peer_public_key,
        "peer_tunnel_ip": peer_ip,
        "peer_ip": config.exit_node_peer_ip,
        "peer_listen_port": peer_listen_port,
        "reverse_initiated": config.exit_node_reverse_initiated,
        "nftables_conf_path": nftables_conf_path,
    }

    content = template.render(context)
    return content, private_key, public_key


def generate_exit_node_configs(config: DeployConfig) -> dict[str, str]:
    """Generate all exit-node role configuration files.

    Returns a dict of relative_path → file_content for all files that
    should be written to the output directory.
    """
    if not config.exit_node_enabled:
        return {}

    files: dict[str, str] = {}

    # 1. nftables rules for exit-node forwarding
    nft_content = generate_exit_node_nftables(config)
    files["exit-node/nftables-exit-node.conf"] = nft_content

    # 2. WireGuard config (only for wireguard tunnel type)
    if config.exit_node_tunnel_type == TunnelType.WIREGUARD:
        wg_content, _private_key, public_key = generate_exit_node_wg_config(config)
        files["exit-node/wg-exit-node.conf"] = wg_content
        files["exit-node/exit-node-public.key"] = public_key + "\n"

    # 3. Setup instructions
    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)
    tunnel_type = (config.exit_node_tunnel_type or TunnelType.WIREGUARD).value
    instructions = _generate_setup_instructions(config, local_ip, peer_ip, tunnel_type)
    files["exit-node/README.md"] = instructions

    return files


def _generate_setup_instructions(
    config: DeployConfig,
    local_ip: str,
    peer_ip: str,
    tunnel_type: str,
) -> str:
    """Generate setup instructions for the exit-node role."""
    return f"""# Exit Node Role Setup

This VM is configured to serve as an **exit node** for another VPN007 instance.

## Configuration

| Parameter | Value |
|-----------|-------|
| Peer VM IP | `{config.exit_node_peer_ip}` |
| Tunnel type | `{tunnel_type}` |
| Tunnel subnet | `{config.exit_node_tunnel_subnet}` |
| Local tunnel IP | `{local_ip}` (this VM) |
| Peer tunnel IP | `{peer_ip}` (entrance node) |
| Listen port | `{config.exit_node_listen_port}` |
| Reverse initiated | `{config.exit_node_reverse_initiated}` |

## How it works

This VM runs the full VPN007 stack (serving its own VPN clients) AND accepts
forwarded traffic from the peer VM (`{config.exit_node_peer_ip}`).

- Traffic arriving on the **public interface** → handled by local VPN services
- Traffic arriving on the **tunnel interface** from `{peer_ip}` → masqueraded to internet

The two roles use separate nftables tables and don't interfere:
- `table inet filter` — main VPN007 firewall (input/output/forward)
- `table ip vpn007_exit_node` — exit-node NAT and forwarding

## Setup steps

### 1. Install the WireGuard tunnel config

```bash
cp exit-node/wg-exit-node.conf /etc/wireguard/wg-exit-node.conf
chmod 600 /etc/wireguard/wg-exit-node.conf
```

### 2. Edit the peer's public key

Replace `REPLACE_WITH_PEER_PUBLIC_KEY` in the config with the actual public key
from the peer VM's forwarding tunnel.

### 3. Copy the nftables rules

```bash
cp exit-node/nftables-exit-node.conf {config.output_dir}/exit-node/nftables-exit-node.conf
```

### 4. Bring up the tunnel

```bash
wg-quick up wg-exit-node
```

### 5. Enable on boot

```bash
systemctl enable wg-quick@wg-exit-node
```

### 6. Share your public key with the peer VM

Your exit-node public key is in `exit-node/exit-node-public.key`.
The peer VM needs this key as the `PublicKey` in their forwarding tunnel config.

## Verifying

```bash
# Check tunnel is up
wg show wg-exit-node

# Check nftables exit-node table
nft list table ip vpn007_exit_node

# Ping the peer through the tunnel
ping {peer_ip}
```

## Coexistence with local VPN services

The exit-node tunnel (`wg-exit-node`) is completely independent of:
- The AmneziaWG VPN interface (serves local clients)
- The main nftables firewall (table inet filter)
- Any forwarding tunnel this VM uses to send traffic elsewhere

All three can run simultaneously without conflict.
"""
