# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Exit node role configuration generator for VPN007.

When a VM runs the full VPN007 stack AND also serves as an exit node for
another VPN007 instance, this module generates the additional configuration
files needed for the exit-node role:

1. A tunnel config (WireGuard, SSH/autossh, or Tailscale)
2. An nftables include with DNAT/SNAT rules in a separate table
   (``vpn007_exit_node``) that doesn't conflict with the main firewall
3. Setup instructions tailored to the chosen tunnel type

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

from vpn007.crypto import generate_ssh_keypair, generate_vless_uuid, generate_reality_keypair, generate_wg_keypair
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
    if tunnel_type == TunnelType.XRAY:
        return "lo"  # Xray is a proxy, no tunnel interface — uses loopback
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
        "peer_ip": config.exit_node_peer_host,
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
        "peer_ip": config.exit_node_peer_host,
        "peer_listen_port": peer_listen_port,
        "reverse_initiated": config.exit_node_reverse_initiated,
        "nftables_conf_path": nftables_conf_path,
    }

    content = template.render(context)
    return content, private_key, public_key


def generate_exit_node_ssh_config(config: DeployConfig) -> tuple[str, str, str, str]:
    """Generate SSH tunnel config for the exit-node role.

    Returns
    -------
    tuple[str, str, str, str]
        (autossh_service_content, private_key_pem, public_key_openssh, setup_script)
        - autossh_service_content: systemd unit for persistent SSH tunnel
        - private_key_pem: Ed25519 private key (OpenSSH PEM format)
        - public_key_openssh: public key to install on the peer VM
        - setup_script: shell script to install the exit-node SSH tunnel
    """
    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)
    private_key_pem, public_key_openssh = generate_ssh_keypair()

    ssh_tunnel_user = "vpn007-tunnel"
    ssh_key_path = "/root/.ssh/vpn007_exit_node_key"
    autossh_monitor_port = 20100  # Different from forwarding tunnel (20000)

    # Systemd service for autossh
    if config.exit_node_reverse_initiated:
        # Peer initiates connection TO us — we just need sshd running.
        # The autossh service is on the PEER side, not here.
        # We generate a service that listens for the reverse tunnel.
        autossh_service = f"""[Unit]
Description=VPN007 Exit Node — SSH tunnel (peer-initiated)
Documentation=https://github.com/Homas/vpn007
After=network-online.target sshd.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Peer VM initiates the reverse SSH tunnel to us.
# This service just ensures nftables rules are loaded.
ExecStart=/usr/sbin/nft -f {config.output_dir}/exit-node/nftables-exit-node.conf
ExecStart=/usr/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStop=/usr/sbin/nft delete table ip vpn007_exit_node

[Install]
WantedBy=multi-user.target
"""
    else:
        # We initiate the SSH tunnel TO the peer VM
        autossh_service = f"""[Unit]
Description=VPN007 Exit Node — SSH tunnel to peer ({config.exit_node_peer_host})
Documentation=https://github.com/Homas/vpn007
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=AUTOSSH_GATETIME=0
ExecStartPre=/usr/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStartPre=/usr/sbin/nft -f {config.output_dir}/exit-node/nftables-exit-node.conf
ExecStart=/usr/bin/autossh -M {autossh_monitor_port} -N \\
    -o "ServerAliveInterval=30" \\
    -o "ServerAliveCountMax=3" \\
    -o "StrictHostKeyChecking=accept-new" \\
    -o "ExitOnForwardFailure=yes" \\
    -i {ssh_key_path} \\
    -w 0:0 \\
    {ssh_tunnel_user}@{config.exit_node_peer_host}
ExecStop=/usr/sbin/nft delete table ip vpn007_exit_node
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

    # Setup script
    setup_script = f"""#!/usr/bin/env bash
# VPN007 Exit Node — SSH Tunnel Setup Script
# Generated by VPN007. Run as root on this VM.
set -euo pipefail

echo "[+] VPN007 Exit Node SSH Tunnel Setup"
echo "[+] Peer VM: {config.exit_node_peer_host}"
echo ""

# Install autossh if not present
if ! command -v autossh &>/dev/null; then
    echo "[+] Installing autossh..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq autossh
    elif command -v apk &>/dev/null; then
        apk add --no-cache autossh
    else
        echo "[!] Please install autossh manually."
        exit 1
    fi
fi

# Install SSH key
echo "[+] Installing SSH key..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cat > {ssh_key_path} << 'KEYEOF'
{private_key_pem}KEYEOF
chmod 600 {ssh_key_path}

# Install nftables rules
echo "[+] Installing nftables rules..."
SCRIPT_DIR="$(dirname "$0")"
NFT_DEST="{config.output_dir}/exit-node/nftables-exit-node.conf"
cp "$SCRIPT_DIR/nftables-exit-node.conf" "$NFT_DEST" 2>/dev/null || true

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Install and enable systemd service
echo "[+] Installing systemd service..."
cp "$SCRIPT_DIR/vpn007-exit-node-ssh.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn007-exit-node-ssh.service

echo ""
echo "[+] Done! SSH exit-node tunnel is active."
echo "[+] Public key to install on peer VM ({config.exit_node_peer_host}):"
echo ""
echo "    {public_key_openssh}"
echo ""
echo "    Create the tunnel user and install the key on the peer VM:"
echo ""
echo "    ssh root@{config.exit_node_peer_host} 'useradd -r -s /usr/sbin/nologin -d /home/{ssh_tunnel_user} -m {ssh_tunnel_user}'"
echo "    ssh root@{config.exit_node_peer_host} 'mkdir -p /home/{ssh_tunnel_user}/.ssh && chmod 700 /home/{ssh_tunnel_user}/.ssh'"
echo "    ssh root@{config.exit_node_peer_host} 'echo \\"{public_key_openssh}\\" >> /home/{ssh_tunnel_user}/.ssh/authorized_keys'"
echo "    ssh root@{config.exit_node_peer_host} 'chmod 600 /home/{ssh_tunnel_user}/.ssh/authorized_keys && chown -R {ssh_tunnel_user}:{ssh_tunnel_user} /home/{ssh_tunnel_user}/.ssh'"
echo ""
echo "[+] Verify with: systemctl status vpn007-exit-node-ssh"
"""

    return autossh_service, private_key_pem, public_key_openssh, setup_script


def generate_exit_node_tailscale_config(config: DeployConfig) -> tuple[str, str]:
    """Generate Tailscale tunnel config for the exit-node role.

    Returns
    -------
    tuple[str, str]
        (systemd_service_content, setup_script)
        - systemd_service_content: systemd unit for exit-node nftables + forwarding
        - setup_script: shell script to configure Tailscale exit-node role
    """
    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)

    # Systemd service to load nftables rules and enable forwarding
    # Tailscale itself is managed by its own service; this just handles
    # the exit-node nftables table.
    systemd_service = f"""[Unit]
Description=VPN007 Exit Node — Tailscale forwarding rules
Documentation=https://github.com/Homas/vpn007
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStart=/usr/sbin/nft -f {config.output_dir}/exit-node/nftables-exit-node.conf
ExecStop=/usr/sbin/nft delete table ip vpn007_exit_node

[Install]
WantedBy=multi-user.target
"""

    # Setup script
    setup_script = f"""#!/usr/bin/env bash
# VPN007 Exit Node — Tailscale Tunnel Setup Script
# Generated by VPN007. Run as root on this VM.
set -euo pipefail

echo "[+] VPN007 Exit Node Tailscale Setup"
echo "[+] Peer VM: {config.exit_node_peer_host}"
echo ""

# Install Tailscale if not present
if ! command -v tailscale &>/dev/null; then
    echo "[+] Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# Ensure Tailscale is up
if ! tailscale status &>/dev/null; then
    echo "[+] Tailscale not connected. Starting..."
    echo "[!] You may need to authenticate via the URL printed below."
    tailscale up --accept-routes
fi

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Install nftables rules
echo "[+] Installing nftables rules..."
SCRIPT_DIR="$(dirname "$0")"
NFT_DEST="{config.output_dir}/exit-node/nftables-exit-node.conf"
mkdir -p "$(dirname "$NFT_DEST")"
cp "$SCRIPT_DIR/nftables-exit-node.conf" "$NFT_DEST" 2>/dev/null || true
nft -f "$NFT_DEST"

# Install and enable systemd service
echo "[+] Installing systemd service..."
cp "$SCRIPT_DIR/vpn007-exit-node-tailscale.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn007-exit-node-tailscale.service

echo ""
echo "[+] Done! Tailscale exit-node forwarding is active."
echo "[+] Ensure the peer VM ({config.exit_node_peer_host}) is on the same tailnet."
echo "[+] The peer VM should use this node's Tailscale IP as its tunnel endpoint."
echo ""
echo "[+] Verify with:"
echo "    tailscale status"
echo "    nft list table ip vpn007_exit_node"
"""

    return systemd_service, setup_script


def generate_exit_node_xray_config(config: DeployConfig) -> tuple[str, str, str]:
    """Generate Xray VLESS+Reality config for the exit-node role.

    For a lightweight exit node, this generates a standalone Xray server config.
    For a full VPN007 node acting as exit, the primary VM connects as a regular
    VLESS client to the existing 3x-ui Xray — in that case, the credentials
    file tells the operator what UUID/keys to configure in 3x-ui.

    Returns
    -------
    tuple[str, str, str]
        (xray_config_json, setup_script, credentials_text)
        - xray_config_json: Xray server config for standalone deployment
        - setup_script: shell script to install Xray and start the tunnel
        - credentials_text: credentials the primary VM needs to connect
    """
    import json

    tunnel_uuid = generate_vless_uuid()
    reality_keys = generate_reality_keypair()
    tunnel_sni = config.reality_sni  # Reuse the same SNI target
    listen_port = config.exit_node_listen_port

    # Xray server config (standalone lightweight exit node)
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "vless-reality-tunnel",
                "listen": "0.0.0.0",
                "port": listen_port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": tunnel_uuid,
                            "flow": "xtls-rprx-vision",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": f"{tunnel_sni}:443",
                        "xver": 0,
                        "serverNames": [tunnel_sni],
                        "privateKey": reality_keys.private_key,
                        "shortIds": [reality_keys.short_id],
                    },
                },
            }
        ],
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            }
        ],
    }

    xray_config_json = json.dumps(xray_config, indent=2)

    # Credentials for the primary VM to connect
    credentials_text = f"""# VPN007 Exit Node — Xray VLESS+Reality Tunnel Credentials
# Generated by VPN007. Share these with the primary VM operator.
#
# The primary VM (entrance node) uses these to connect to this exit node.

SERVER_ADDRESS={config.exit_node_peer_host or "THIS_VM_IP"}
SERVER_PORT={listen_port}
UUID={tunnel_uuid}
REALITY_PUBLIC_KEY={reality_keys.public_key}
SHORT_ID={reality_keys.short_id}
SNI={tunnel_sni}
FLOW=xtls-rprx-vision

# VLESS share link (import into Xray client or 3x-ui):
# vless://{tunnel_uuid}@{config.exit_node_peer_host or "THIS_VM_IP"}:{listen_port}?security=reality&sni={tunnel_sni}&fp=chrome&pbk={reality_keys.public_key}&sid={reality_keys.short_id}&type=tcp&flow=xtls-rprx-vision#vpn007-tunnel

# For a FULL VPN007 node as exit:
# Instead of running standalone Xray, add a client with UUID={tunnel_uuid}
# to your existing 3x-ui VLESS+Reality inbound. The primary VM connects
# as a regular VLESS client — indistinguishable from other VPN clients.
"""

    # Setup script (for lightweight exit node)
    setup_script = f"""#!/usr/bin/env bash
# VPN007 Exit Node — Xray VLESS+Reality Tunnel Setup Script
# Generated by VPN007. Run as root on this VM.
set -euo pipefail

echo "[+] VPN007 Exit Node Xray VLESS+Reality Setup"
echo "[+] Peer VM: {config.exit_node_peer_host}"
echo ""

# Install Xray if not present
XRAY_BIN="/usr/local/bin/xray"
if [ ! -f "$XRAY_BIN" ] && [ ! -f "/usr/bin/xray" ]; then
    echo "[+] Installing Xray..."
    curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh
    bash /tmp/xray-install.sh install
    rm -f /tmp/xray-install.sh
fi

# Determine Xray binary path
if [ -f "/usr/local/bin/xray" ]; then
    XRAY_BIN="/usr/local/bin/xray"
elif [ -f "/usr/bin/xray" ]; then
    XRAY_BIN="/usr/bin/xray"
else
    echo "[!] Xray binary not found after installation."
    exit 1
fi

# Install Xray config
echo "[+] Installing Xray tunnel config..."
mkdir -p /etc/xray
SCRIPT_DIR="$(dirname "$0")"
cp "$SCRIPT_DIR/xray-tunnel-config.json" /etc/xray/config.json
chmod 600 /etc/xray/config.json

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Create systemd service
cat > /etc/systemd/system/vpn007-xray-tunnel.service << SERVICEEOF
[Unit]
Description=VPN007 Xray VLESS+Reality Tunnel (exit node)
Documentation=https://github.com/Homas/vpn007
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$XRAY_BIN run -config /etc/xray/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Start the service
systemctl daemon-reload
systemctl enable --now vpn007-xray-tunnel.service

echo ""
echo "[+] Done! Xray VLESS+Reality tunnel is active on port {listen_port}."
echo "[+] Credentials for the primary VM:"
echo ""
echo "    UUID: {tunnel_uuid}"
echo "    Reality public key: {reality_keys.public_key}"
echo "    Short ID: {reality_keys.short_id}"
echo "    SNI: {tunnel_sni}"
echo "    Port: {listen_port}"
echo ""
echo "[+] See tunnel-credentials.txt for the full connection details."
echo "[+] Verify with: systemctl status vpn007-xray-tunnel"
"""

    return xray_config_json, setup_script, credentials_text


def generate_exit_node_configs(config: DeployConfig) -> dict[str, str]:
    """Generate all exit-node role configuration files.

    Returns a dict of relative_path → file_content for all files that
    should be written to the output directory.
    """
    if not config.exit_node_enabled:
        return {}

    files: dict[str, str] = {}

    # 1. nftables rules for exit-node forwarding (all tunnel types)
    nft_content = generate_exit_node_nftables(config)
    files["exit-node/nftables-exit-node.conf"] = nft_content

    # 2. Tunnel-specific configs
    tunnel_type = config.exit_node_tunnel_type or TunnelType.WIREGUARD

    if tunnel_type == TunnelType.WIREGUARD:
        wg_content, _private_key, public_key = generate_exit_node_wg_config(config)
        files["exit-node/wg-exit-node.conf"] = wg_content
        files["exit-node/exit-node-public.key"] = public_key + "\n"

    elif tunnel_type == TunnelType.SSH:
        service_content, private_key, public_key, setup_script = (
            generate_exit_node_ssh_config(config)
        )
        files["exit-node/vpn007-exit-node-ssh.service"] = service_content
        files["exit-node/exit-node-ssh-private.key"] = private_key
        files["exit-node/exit-node-ssh-public.key"] = public_key + "\n"
        files["exit-node/setup-exit-node.sh"] = setup_script

    elif tunnel_type == TunnelType.TAILSCALE:
        service_content, setup_script = generate_exit_node_tailscale_config(config)
        files["exit-node/vpn007-exit-node-tailscale.service"] = service_content
        files["exit-node/setup-exit-node.sh"] = setup_script

    elif tunnel_type == TunnelType.XRAY:
        xray_config, setup_script, credentials = generate_exit_node_xray_config(config)
        files["exit-node/xray-tunnel-config.json"] = xray_config
        files["exit-node/setup-exit-node.sh"] = setup_script
        files["exit-node/tunnel-credentials.txt"] = credentials

    # 3. Setup instructions
    local_ip, peer_ip = _subnet_to_ips(config.exit_node_tunnel_subnet)
    instructions = _generate_setup_instructions(
        config, local_ip, peer_ip, tunnel_type.value
    )
    files["exit-node/README.md"] = instructions

    return files


def _generate_setup_instructions(
    config: DeployConfig,
    local_ip: str,
    peer_ip: str,
    tunnel_type: str,
) -> str:
    """Generate setup instructions for the exit-node role."""
    header = f"""# Exit Node Role Setup

This VM is configured to serve as an **exit node** for another VPN007 instance.

## Configuration

| Parameter | Value |
|-----------|-------|
| Peer VM IP | `{config.exit_node_peer_host}` |
| Tunnel type | `{tunnel_type}` |
| Tunnel subnet | `{config.exit_node_tunnel_subnet}` |
| Local tunnel IP | `{local_ip}` (this VM) |
| Peer tunnel IP | `{peer_ip}` (entrance node) |
| Listen port | `{config.exit_node_listen_port}` |
| Reverse initiated | `{config.exit_node_reverse_initiated}` |

## How it works

This VM runs the full VPN007 stack (serving its own VPN clients) AND accepts
forwarded traffic from the peer VM (`{config.exit_node_peer_host}`).

- Traffic arriving on the **public interface** → handled by local VPN services
- Traffic arriving on the **tunnel interface** from `{peer_ip}` → masqueraded to internet

The two roles use separate nftables tables and don't interfere:
- `table inet filter` — main VPN007 firewall (input/output/forward)
- `table ip vpn007_exit_node` — exit-node NAT and forwarding

"""

    if tunnel_type == "wireguard":
        steps = f"""## Setup steps

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
"""

    elif tunnel_type == "ssh":
        steps = f"""## Setup steps

### Option A: Run the setup script (recommended)

```bash
chmod +x exit-node/setup-exit-node.sh
sudo ./exit-node/setup-exit-node.sh
```

This installs autossh, the SSH key, nftables rules, and the systemd service.

### Option B: Manual setup

#### 1. Install autossh

```bash
apt-get install -y autossh   # Debian/Ubuntu
# or: apk add autossh        # Alpine
```

#### 2. Install the SSH key

```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
cp exit-node/exit-node-ssh-private.key /root/.ssh/vpn007_exit_node_key
chmod 600 /root/.ssh/vpn007_exit_node_key
```

#### 3. Create the tunnel user on the peer VM and install the public key

The SSH tunnel connects as an unprivileged user (`vpn007-tunnel`) on the
peer VM. This user has no shell and cannot execute commands — it only holds
the SSH connection open for port forwarding.

```bash
# On the peer VM ({config.exit_node_peer_host}):
useradd -r -s /usr/sbin/nologin -d /home/vpn007-tunnel -m vpn007-tunnel
mkdir -p /home/vpn007-tunnel/.ssh
chmod 700 /home/vpn007-tunnel/.ssh
cat exit-node/exit-node-ssh-public.key >> /home/vpn007-tunnel/.ssh/authorized_keys
chmod 600 /home/vpn007-tunnel/.ssh/authorized_keys
chown -R vpn007-tunnel:vpn007-tunnel /home/vpn007-tunnel/.ssh
```

#### 4. Install the systemd service

```bash
cp exit-node/vpn007-exit-node-ssh.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn007-exit-node-ssh.service
```

#### 5. Enable IP forwarding

```bash
sysctl -w net.ipv4.ip_forward=1
```

#### 6. Load nftables rules

```bash
nft -f exit-node/nftables-exit-node.conf
```

## Verifying

```bash
# Check the autossh service is running
systemctl status vpn007-exit-node-ssh

# Check nftables exit-node table
nft list table ip vpn007_exit_node

# Check SSH tunnel connectivity (from this VM to the peer)
ssh -i /root/.ssh/vpn007_exit_node_key vpn007-tunnel@{config.exit_node_peer_host} "echo ok"
# Note: this will fail with "This account is currently not available" which is
# expected — the nologin shell rejects interactive sessions. The tunnel uses
# -N (no command) so it works despite the restricted shell.
```

## Security notes

- The tunnel connects as `vpn007-tunnel` — an unprivileged user with no shell
  (`/usr/sbin/nologin`). Even if the key is compromised, the attacker cannot
  execute commands or escalate privileges on the peer VM.
- The private key (`exit-node-ssh-private.key`) is stored locally on this VM.
  Delete it from the deploy directory after installation:
  `rm exit-node/exit-node-ssh-private.key`
- The systemd service uses `StrictHostKeyChecking=accept-new` — on first
  connection it accepts the peer's host key. Subsequent connections verify it.
"""

    elif tunnel_type == "tailscale":
        steps = f"""## Setup steps

### Option A: Run the setup script (recommended)

```bash
chmod +x exit-node/setup-exit-node.sh
sudo ./exit-node/setup-exit-node.sh
```

This installs Tailscale (if needed), enables IP forwarding, loads nftables
rules, and installs the systemd service.

### Option B: Manual setup

#### 1. Install Tailscale

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

#### 2. Join the same tailnet as the peer VM

```bash
tailscale up --accept-routes
```

If the peer VM isn't on the same tailnet yet, authenticate both VMs to the
same Tailscale account.

#### 3. Enable IP forwarding

```bash
sysctl -w net.ipv4.ip_forward=1
```

#### 4. Load nftables rules

```bash
nft -f exit-node/nftables-exit-node.conf
```

#### 5. Install the systemd service (persists nftables on boot)

```bash
cp exit-node/vpn007-exit-node-tailscale.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn007-exit-node-tailscale.service
```

## Verifying

```bash
# Check Tailscale connectivity to the peer
tailscale ping {config.exit_node_peer_host}

# Check nftables exit-node table
nft list table ip vpn007_exit_node

# Check the systemd service
systemctl status vpn007-exit-node-tailscale
```

## Notes

- Both VMs must be on the same Tailscale tailnet.
- The peer VM should use this node's **Tailscale IP** (100.x.x.x) as the
  tunnel endpoint, not the public IP.
- Run `tailscale status` to find this node's Tailscale IP.
- The nftables rules masquerade traffic from the peer's Tailscale IP to
  the internet — no WireGuard keys or SSH keys needed.
"""

    elif tunnel_type == "xray":
        steps = f"""## Setup steps

### Option A: Lightweight exit node (run the setup script)

```bash
chmod +x exit-node/setup-exit-node.sh
sudo ./exit-node/setup-exit-node.sh
```

This installs Xray, deploys the tunnel config, and starts the systemd service.
The exit node listens on port `{config.exit_node_listen_port}` for VLESS+Reality
connections from the primary VM.

### Option B: Full VPN007 node as exit (reuse existing 3x-ui)

If this VM already runs the full VPN007 stack with 3x-ui, you don't need a
separate Xray process. Instead, add the tunnel as a regular VLESS client in
your existing 3x-ui panel:

1. Open 3x-ui at `https://your.domain/secretpanel-XXXXX/`
2. Go to Inbounds → your VLESS+Reality inbound
3. Add a new client with the UUID from `tunnel-credentials.txt`
4. Share the connection details with the primary VM operator

The primary VM connects as a regular VLESS client — indistinguishable from
other VPN clients. No extra ports, no extra processes, fully blended.

### Credentials for the primary VM

See `exit-node/tunnel-credentials.txt` for the full connection details:
- UUID, Reality public key, short ID, SNI, port
- A ready-to-import VLESS share link

## Verifying

```bash
# Lightweight exit node:
systemctl status vpn007-xray-tunnel
journalctl -u vpn007-xray-tunnel --since "5 min ago"

# Full VPN007 node:
docker exec vpn007_three_x_ui /app/x-ui setting -show
# Check that the tunnel UUID appears in the client list
```

## Security notes

- The tunnel credentials (`tunnel-credentials.txt`) contain the Reality private
  key (in the Xray config) and the UUID. Handle with care.
- Delete `tunnel-credentials.txt` from the deploy directory after sharing the
  public key and UUID with the primary VM operator.
- The tunnel connection is indistinguishable from a legitimate TLS 1.3
  connection to `{config.reality_sni}` — DPI cannot detect it.
- For a full VPN007 node, the tunnel traffic blends with regular VPN client
  traffic — an observer cannot tell which connections are the relay tunnel.
"""

    else:
        steps = f"""## Setup steps

Unsupported tunnel type: `{tunnel_type}`. Use `wireguard`, `ssh`, `tailscale`, or `xray`.
"""

    footer = """
## Coexistence with local VPN services

The exit-node tunnel is completely independent of:
- The AmneziaWG VPN interface (serves local clients)
- The main nftables firewall (table inet filter)
- Any forwarding tunnel this VM uses to send traffic elsewhere

All can run simultaneously without conflict.
"""

    return header + steps + footer
