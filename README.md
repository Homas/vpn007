# VPN007

A Python CLI tool that deploys multiple anti-censorship VPN services on a single Linux VM using Docker Compose.

VPN007 generates all the configuration files needed to run Xray (VLESS+Reality), AmneziaWG 2.0, and Tailscale behind an Nginx reverse proxy with a legitimate cover website. Traffic is routed through standard HTTPS ports (443/tcp) using a two-layer architecture: Layer 4 SNI-based routing sends Reality traffic directly to Xray, while everything else goes through Layer 7 path-based routing with TLS termination.

The tool also provisions an nftables firewall with AS/subnet blocking, sets up systemd timers for blocklist updates and hostname resolution, manages TLS certificates via Let's Encrypt, and can generate forwarding scripts for multi-VM relay architectures.

## Features

- **Xray VLESS+Reality** — VPN traffic indistinguishable from legitimate TLS 1.3 connections
- **AmneziaWG 2.0** — WireGuard with full obfuscation parameter set (S1-S4, H1-H4, I1-I5) for DPI resistance
- **Tailscale** — Mesh overlay network for secure management and exit node
- **Cover website** — Static or reverse-proxied legitimate site served by default
- **nftables firewall** — Default-deny policy with AS/subnet blocking and automatic prefix resolution
- **Multi-IP support** — Separate incoming and outgoing IP addresses
- **Inter-VM forwarding** — Encrypted tunnel relay via WireGuard, SSH, or Tailscale
- **TLS certificate management** — Automated Let's Encrypt with dynamic port 80 opening
- **Documentation generation** — README, troubleshooting guide, and client connection guides tailored to your deployment

## Prerequisites

### Host OS

| OS | Version |
|----|---------|
| Debian | 11+ (Bullseye) |
| Ubuntu | 22.04+ (Jammy) |
| Alpine Linux | 3.18+ |

### Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.12+ | VPN007 runtime |
| Docker Engine | Latest stable | Container runtime |
| Docker Compose | v2+ (plugin) | Service orchestration |
| nftables | System package | Firewall |
| curl | System package | IP detection, health checks |
| git | System package | Repository management |

### Python packages

| Package | Version | Purpose |
|---------|---------|---------|
| python-dotenv | ≥1.0 | `.env` file parsing |
| Jinja2 | ≥3.1 | Template rendering |
| cryptography | ≥42.0 | Key generation (x25519, WireGuard) |

Dev dependencies (for running tests):

| Package | Version |
|---------|---------|
| pytest | ≥8.0 |
| hypothesis | ≥6.100 |
| pyyaml | ≥6.0 |
| ruff | ≥0.4 |

### Hardware

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | 2+ vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 15 GB | 30 GB |

Disk usage grows with VPN client count, Docker image layers, and log retention. Additional resources are needed when inter-VM forwarding is enabled.

## Installation

```bash
# Clone the repository
git clone https://github.com/Homas/vpn007.git
cd vpn007

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package
pip install -e .

# (Optional) Install dev dependencies for testing
pip install -e ".[dev]"
```

## Usage

### Run modes

VPN007 supports three primary run modes:

| Mode | Command | What it does |
|------|---------|--------------|
| **Dry-run** | `vpn007 --dry-run` | Generates all config files without deploying anything |
| **Full deploy** | `sudo vpn007` | Generates configs, starts containers, applies firewall, installs timers |
| **Non-interactive** | `AUTO_INSTALL=y sudo vpn007` | Full deploy without prompts (for scripted/CI use) |

### Quick start

```bash
# 1. Copy and edit the environment file
cp .env.sample .env
vim .env   # Set DOMAIN, APPROVED_IPS, SSH_APPROVED_IPS, TAILSCALE_AUTH_KEY

# 2. Preview what will be generated
vpn007 --dry-run

# 3. Deploy everything
sudo vpn007
```

### Deploying to a remote server without source code

The generated output is self-contained. You can generate configs locally and deploy them anywhere:

```bash
# On your dev machine
vpn007 --domain vpn.example.com --output-dir ./deploy --dry-run

# Copy to server
scp -r ./deploy/ root@your-server:/opt/vpn007/

# On the server — start services
cd /opt/vpn007
docker compose up -d

# Then manually:
# 1. Install systemd timers (copy systemd/*.service and *.timer to /etc/systemd/system/)
# 2. Apply firewall: nft -f /opt/vpn007/nftables.conf
# 3. Acquire TLS cert (see TLS section below)
```

### CLI options

All parameters can be set via CLI flags, `.env` file, or both. CLI flags take precedence over `.env` values.

```
vpn007 [OPTIONS]
```

#### Operational flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Generate config files only — no containers, no firewall, no timers |
| `--debug` | Enable verbose debug logging (full command stdout/stderr on console) |
| `--env-file PATH` | Path to `.env` file (default: `.env` in current directory) |
| `--output-dir PATH` | Output directory for generated files (default: `./deploy`) |
| `--version` | Show version and exit |

#### General

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--domain` | `DOMAIN` | *(required)* | Primary domain name for the VPN server |
| `--reality-sni` | `REALITY_SNI` | `www.microsoft.com` | SNI target for Xray Reality (must support TLS 1.3) |
| `--cover-site-mode` | `COVER_SITE_MODE` | `static` | Cover site mode: `static` or `proxy` |
| `--cover-site-url` | `COVER_SITE_URL` | *(none)* | URL to proxy (required when mode=proxy) |
| `--cover-site-static-path` | `COVER_SITE_STATIC_PATH` | *(none)* | Path to static files (optional when mode=static) |

#### Routing

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--xui-path-prefix` | `XUI_PATH_PREFIX` | `/secretpanel` | URL path for 3x-ui web panel |
| `--awg-panel-path-prefix` | `AWG_PANEL_PATH_PREFIX` | `/awgadmin` | URL path for AmneziaWG panel |
| `--enable-port-8443` | `ENABLE_PORT_8443` | `false` | Enable secondary HTTPS port 8443 |

#### Xray / Reality

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--xray-internal-port` | `XRAY_INTERNAL_PORT` | `10443` | Internal container port for Xray |

Reality key pair (private key, public key, short_id) is auto-generated at deploy time if not provided.

#### AmneziaWG

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--awg-listen-port` | `AWG_LISTEN_PORT` | random 10000-65535 | UDP listen port on host |
| `--awg-panel-port` | `AWG_PANEL_PORT` | `51821` | Web panel port (local-only) |

Obfuscation parameters (env vars only — provide all or none for auto-generation):

| Env var | Range | Description |
|---------|-------|-------------|
| `AWG_S1` | 15-150 | Init packet magic header |
| `AWG_S2` | 15-150 | Response packet magic header |
| `AWG_S3` | 15-150 | Init packet junk size (2.0) |
| `AWG_S4` | 15-150 | Response packet junk size (2.0) |
| `AWG_H1` | 5-2147483647 | Header transform param 1 |
| `AWG_H2` | 5-2147483647 | Header transform param 2 |
| `AWG_H3` | 5-2147483647 | Header transform param 3 |
| `AWG_H4` | 5-2147483647 | Header transform param 4 |
| `AWG_JC` | 1-128 | Junk packet count (default: 4) |
| `AWG_JMIN` | 1-1280 | Min junk packet size (default: 50) |
| `AWG_JMAX` | 1-1280 | Max junk packet size (default: 1000) |
| `AWG_I1`–`AWG_I5` | 0-1280 | Init packet junk sizes (default: 0) |

#### Tailscale

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--tailscale-auth-key` | `TAILSCALE_AUTH_KEY` | *(empty)* | Auth key for automatic registration |
| `--tailscale-hostname` | `TAILSCALE_HOSTNAME` | *(empty — uses system hostname)* | Node hostname in the tailnet |
| `--tailscale-extra-args` | `TAILSCALE_EXTRA_ARGS` | `--advertise-exit-node` | Extra args for Tailscale daemon |

All three Tailscale variables (`TS_AUTHKEY`, `TS_HOSTNAME`, `TS_EXTRA_ARGS`) are always present in the generated `docker-compose.yml`, even when empty. This makes them easy to edit in-place on the server without regenerating.

#### Multi-IP

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--incoming-ip` | `INCOMING_IP` | *(all interfaces)* | Bind IP for reverse proxy |
| `--outgoing-ip` | `OUTGOING_IP` | *(default route)* | Source IP for outbound traffic (SNAT) |
| `--public-ipv4` | `PUBLIC_IPV4` | *(auto-detected)* | Public IPv4 for client configs |
| `--public-ipv6` | `PUBLIC_IPV6` | *(auto-detected)* | Public IPv6 for client configs |

#### TLS

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--tls-versions` | `TLS_VERSIONS` | `1.2,1.3` | Accepted TLS versions (comma-separated) |
| `--skip-certbot` | `SKIP_CERTBOT` | `false` | Skip Let's Encrypt; use self-signed cert |
| `--https-port` | `HTTPS_PORT` | `443` | Main HTTPS listen port |

ECH/ESNI extensions are never advertised (blocked by Russia's TSPU since November 2024).

#### Access control

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--approved-ips` | `APPROVED_IPS` | *(required)* | IPs/CIDRs allowed to access web panels |
| `--approved-hostnames` | `APPROVED_HOSTNAMES` | *(empty)* | Hostnames resolved periodically for panel access |
| `--ssh-approved-ips` | `SSH_APPROVED_IPS` | *(required)* | IPs allowed to SSH into the VM |
| `--hostname-resolve-interval-min` | `HOSTNAME_RESOLVE_INTERVAL_MIN` | `30` | Re-resolve interval in minutes |

#### Firewall / blocking

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--blocked-as-numbers` | `BLOCKED_AS_NUMBERS` | *(empty)* | AS numbers to block (e.g. `AS196747,AS61280`) |
| `--blocked-subnets` | `BLOCKED_SUBNETS` | *(empty)* | CIDR subnets to block directly |
| `--blocklist-update-interval-hours` | `BLOCKLIST_UPDATE_INTERVAL_HOURS` | `6` | AS prefix re-resolution interval |

#### Inter-VM forwarding

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--forwarding-enabled` | `FORWARDING_ENABLED` | `false` | Enable traffic forwarding to secondary VM |
| `--tunnel-type` | `TUNNEL_TYPE` | *(none)* | Tunnel type: `wireguard`, `ssh`, or `tailscale` |
| `--secondary-vm-ip` | `SECONDARY_VM_IP` | *(none)* | IP of the secondary VM |
| `--reverse-initiated` | `REVERSE_INITIATED` | `false` | Secondary VM initiates tunnel back |
| `--forwarding-ports` | `FORWARDING_PORTS` | *(none)* | Port forwards (`proto:listen:fwd[:desc],...`) |
| `--reconnect-initial-delay-sec` | `RECONNECT_INITIAL_DELAY_SEC` | `5` | Initial reconnect delay (seconds) |
| `--reconnect-max-delay-sec` | `RECONNECT_MAX_DELAY_SEC` | `300` | Max reconnect delay (seconds) |

#### Output

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--output-dir` | `OUTPUT_DIR` | `./deploy` | Directory for generated files |
| `--deployment-log-path` | `DEPLOYMENT_LOG_PATH` | `./deploy/deploy.log` | Deployment log file path |

### Configuration precedence

Parameters are resolved in this order (highest priority first):

1. CLI arguments
2. `.env` file values
3. Built-in defaults

### Generated output structure

After running `vpn007 --dry-run` (or a full deploy), the output directory contains:

```
deploy/
├── docker-compose.yml          # All services orchestrated here
├── nginx/
│   ├── stream.conf             # L4 SNI routing (Reality → Xray)
│   ├── http.conf               # L7 path routing + TLS termination
│   ├── approved_panel_ips.conf # Nginx allow list for panels
│   └── self-signed/            # Bootstrap cert (before Let's Encrypt)
├── xray/
│   └── config.json             # VLESS+Reality configuration
├── data/                       # Persistent data (bind mounts)
│   ├── three_x_ui/            # 3x-ui panel data
│   ├── amneziawg/             # AmneziaWG/WireGuard configs
│   ├── tailscale/             # Tailscale node state
│   ├── letsencrypt/           # TLS certificates
│   └── certbot_webroot/       # ACME challenge files
├── nftables.conf               # Firewall rules
├── scripts/
│   ├── blocklist-updater.sh    # AS prefix resolver
│   ├── hostname-resolver.sh    # Panel IP updater
│   └── certbot-renew.sh       # Cert renewal with port 80 hooks
├── systemd/
│   ├── blocklist-updater.service
│   ├── blocklist-updater.timer
│   ├── hostname-resolver.service
│   ├── hostname-resolver.timer
│   ├── certbot-renew.service
│   └── certbot-renew.timer
├── clients/
│   └── xray-default-client.txt  # VLESS share link
├── docs/
│   ├── README.md
│   ├── troubleshooting.md
│   └── client-guides.md
└── forwarding-install.py       # (only when forwarding enabled)
```

All volume mounts in `docker-compose.yml` use relative paths (`./data/...`), so the output directory is portable — copy it anywhere and run `docker compose up -d`.

### Docker containers

| Container | Image | Network | Purpose |
|-----------|-------|---------|---------|
| `vpn007_reverse_proxy` | `nginx:mainline-alpine` | bridge (vpn_net) | L4/L7 routing, TLS termination |
| `vpn007_three_x_ui` | `ghcr.io/mhsanaei/3x-ui:latest` | bridge (vpn_net) | Xray management + VLESS+Reality |
| `vpn007_amneziawg` | `ghcr.io/wg-easy/wg-easy:15` | host | AmneziaWG 2.0 VPN + web panel |
| `vpn007_tailscale` | `tailscale/tailscale:latest` | host | Mesh VPN overlay |
| `vpn007_cover_site` | `nginx:alpine` | bridge (vpn_net) | Legitimate cover website |
| `vpn007_certbot` | `certbot/certbot:latest` | *(utility)* | TLS cert acquisition/renewal |

### Common operations

```bash
# Start all services
cd /opt/vpn007  # or wherever your deploy dir is
docker compose up -d

# Stop all services
docker compose down

# View logs
docker compose logs -f reverse_proxy
docker compose logs -f amneziawg

# Update images
docker compose pull
docker compose up -d

# Restart a single service
docker compose restart tailscale

# Acquire/renew TLS certificate manually
docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d your.domain
docker compose exec reverse_proxy nginx -s reload

# Check firewall rules
nft list ruleset

# Check systemd timers
systemctl list-timers 'blocklist*' 'hostname*' 'certbot*'
```

### TLS certificate management

On first deploy, Nginx starts with a self-signed certificate. The deployer then:

1. Temporarily opens port 80 in nftables
2. Runs `docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d $DOMAIN`
3. Closes port 80
4. Reloads Nginx with the real certificate

Subsequent renewals are handled by the `certbot-renew.timer` (runs twice daily). The renewal script dynamically opens port 80 only during the brief renewal window.

To skip Let's Encrypt entirely (lab/staging), set `SKIP_CERTBOT=true`.

### Lab/staging deployment

For testing without a real domain or public IP:

```bash
vpn007 --domain lab.local \
       --skip-certbot \
       --https-port 8443 \
       --public-ipv4 192.168.1.100 \
       --dry-run
```

This generates configs with a self-signed cert on port 8443, suitable for local testing.

## Inter-VM forwarding (relay architecture)

This section explains how to set up a two-VM relay where **VM-A** (entrance node) accepts VPN client connections and forwards traffic through an encrypted tunnel to **VM-B** (exit node), which routes it to the internet. This separates the entry point from the exit point for improved privacy and censorship resistance.

```
┌─────────────┐         encrypted tunnel         ┌─────────────┐
│   VM-A      │ ──────────────────────────────── │   VM-B      │
│  (entrance) │   WireGuard / SSH / Tailscale    │   (exit)    │
│             │                                   │             │
│  Clients ──►│ DNAT ──► tunnel ──► DNAT ──────► │ ──► Internet│
│  connect    │                                   │             │
│  here       │  Public IP: 203.0.113.10         │  Public IP: │
│             │                                   │  198.51.100.20
└─────────────┘                                   └─────────────┘
```

### Overview

- **VM-A** runs the full VPN007 stack (Nginx, Xray, AmneziaWG, Tailscale, cover site) and accepts client connections on ports 443/UDP.
- **VM-B** is a lightweight exit node that receives forwarded traffic from VM-A over an encrypted tunnel and routes it to the internet.
- The deployer generates a standalone Python script (`forwarding-install.py`) that you run on VM-B to set up its side of the tunnel.

### Supported tunnel types

| Tunnel type | Use case | Requirements on VM-B |
|-------------|----------|---------------------|
| `wireguard` | Best performance, lowest overhead | WireGuard or AmneziaWG kernel module |
| `ssh` | Works through most firewalls, no extra software | SSH server + autossh |
| `tailscale` | Easiest setup, works behind NAT | Tailscale client |

### Step 1: Configure VM-A (entrance node)

Edit your `.env` file on VM-A (or pass CLI flags):

```bash
# Enable forwarding
FORWARDING_ENABLED=true

# Choose tunnel type: wireguard, ssh, or tailscale
TUNNEL_TYPE=wireguard

# VM-B's public IP address
SECONDARY_VM_IP=198.51.100.20

# Ports to forward from VM-A to VM-B
# Format: protocol:listen_port:forward_port:description
FORWARDING_PORTS=tcp:443:443:HTTPS,udp:51820:51820:AmneziaWG

# Set to true if VM-B is behind NAT and must initiate the tunnel
REVERSE_INITIATED=false

# Reconnection settings (exponential backoff)
RECONNECT_INITIAL_DELAY_SEC=5
RECONNECT_MAX_DELAY_SEC=300
```

Then run the deployer:

```bash
# Generate all configs including the forwarding script
vpn007 --dry-run

# Or full deploy
sudo vpn007
```

This generates `deploy/forwarding-install.py` — a standalone script to run on VM-B.

### Step 2: Prepare VM-B (exit node)

VM-B needs minimal setup. It does NOT need the full VPN007 stack.

**Requirements on VM-B:**
- Linux (Debian 11+, Ubuntu 22.04+, or Alpine 3.18+)
- Python 3.10+
- Root access (for nftables and tunnel setup)
- Internet connectivity

**Copy the forwarding script to VM-B:**

```bash
# From your dev machine or VM-A
scp deploy/forwarding-install.py root@198.51.100.20:/root/
```

### Step 3: Run the forwarding script on VM-B

```bash
ssh root@198.51.100.20

# Make executable and run
chmod +x /root/forwarding-install.py
python3 /root/forwarding-install.py
```

The script will automatically:

1. Install the tunnel endpoint (WireGuard, autossh, or Tailscale — depending on `TUNNEL_TYPE`)
2. Configure the encrypted tunnel to VM-A
3. Set up nftables DNAT/SNAT rules to route forwarded traffic to the internet
4. Configure automatic reconnection with exponential backoff (5s → 10s → 20s → ... → 300s max)
5. Enable IP forwarding and NAT masquerading

### Step 4: Verify the tunnel

**On VM-A:**

```bash
# Check if the tunnel interface is up (WireGuard example)
wg show

# Verify forwarding rules
nft list table ip nat

# Test connectivity through the tunnel
ping 10.99.0.2   # VM-B's tunnel IP (WireGuard)
```

**On VM-B:**

```bash
# Check tunnel status
wg show           # WireGuard
# or
systemctl status autossh-tunnel   # SSH
# or
tailscale status  # Tailscale

# Verify DNAT rules are active
nft list table ip nat

# Test that traffic exits from VM-B's IP
curl -4 ifconfig.me   # Should show VM-B's public IP
```

### Tunnel type details

#### WireGuard / AmneziaWG tunnel

The deployer generates a point-to-point WireGuard tunnel between VM-A and VM-B using subnet `10.99.0.0/30`:
- VM-A: `10.99.0.1`
- VM-B: `10.99.0.2`

Keys are auto-generated and embedded in the forwarding script. Traffic is forwarded via nftables DNAT from VM-A's public ports through the tunnel to VM-B, which then SNATs it to the internet.

#### SSH tunnel

Uses `autossh` for persistent SSH tunnels with automatic reconnection. The deployer generates SSH key pairs and configures port forwarding over the SSH connection. No additional software needed on VM-B beyond an SSH server.

```bash
# The forwarding script sets up something like:
autossh -M 20000 -N -L 0.0.0.0:443:localhost:443 \
        -i /root/.ssh/vpn007_tunnel_key root@VM-A
```

#### Tailscale tunnel

The simplest option — both VMs join the same tailnet and traffic is routed over the Tailscale overlay network. VM-B must have Tailscale installed and authenticated to the same tailnet as VM-A.

```bash
# The forwarding script configures VM-B to accept routes from VM-A
tailscale up --accept-routes
```

### Reverse-initiated connections

When VM-B is behind NAT or a restrictive firewall and cannot accept incoming connections, set `REVERSE_INITIATED=true`. In this mode:

- **VM-B initiates** the tunnel connection back to VM-A
- **VM-A listens** for incoming tunnel connections from VM-B
- Once established, traffic flows in both directions through the tunnel

This is useful when VM-B is on a residential connection or behind a corporate firewall.

```bash
# .env on VM-A
REVERSE_INITIATED=true
```

With SSH tunnel type, this creates a reverse SSH tunnel where VM-B connects to VM-A and exposes its local ports back through the connection.

### Example: Full WireGuard relay setup

**VM-A** (entrance, IP: 203.0.113.10):

```bash
# .env
DOMAIN=vpn.example.com
FORWARDING_ENABLED=true
TUNNEL_TYPE=wireguard
SECONDARY_VM_IP=198.51.100.20
FORWARDING_PORTS=tcp:443:443:HTTPS,udp:51820:51820:AmneziaWG
RECONNECT_INITIAL_DELAY_SEC=5
RECONNECT_MAX_DELAY_SEC=300

# Deploy
sudo vpn007
```

**VM-B** (exit, IP: 198.51.100.20):

```bash
# Copy and run the generated script
scp root@203.0.113.10:/opt/vpn007/forwarding-install.py /root/
python3 /root/forwarding-install.py
```

After setup, clients connect to VM-A (203.0.113.10) but their traffic exits from VM-B (198.51.100.20).

### Example: Tailscale relay (VM-B behind NAT)

**VM-A** (entrance):

```bash
# .env
DOMAIN=vpn.example.com
FORWARDING_ENABLED=true
TUNNEL_TYPE=tailscale
REVERSE_INITIATED=true
TAILSCALE_AUTH_KEY=tskey-auth-xxxxx
FORWARDING_PORTS=tcp:443:443:HTTPS

# Deploy
sudo vpn007
```

**VM-B** (exit, behind NAT):

```bash
# Install Tailscale and join the same tailnet
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --authkey=tskey-auth-yyyyy --accept-routes

# Then run the forwarding script
python3 /root/forwarding-install.py
```

### Troubleshooting forwarding

| Symptom | Check |
|---------|-------|
| Tunnel won't establish | Verify VM-B can reach VM-A on the tunnel port (`nc -zv VM-A 51821`) |
| Traffic not forwarding | Check nftables DNAT rules on both VMs (`nft list table ip nat`) |
| Intermittent drops | Check reconnection logs; increase `RECONNECT_MAX_DELAY_SEC` |
| VM-B can't reach internet | Verify IP forwarding is enabled (`sysctl net.ipv4.ip_forward`) |
| Reverse tunnel fails | Ensure VM-A's SSH/WG port is open in its firewall for VM-B's IP |

## Running tests

```bash
source .venv/bin/activate

# Run the full test suite
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_compose.py -v

# Run with the CI Hypothesis profile (fewer examples, faster)
HYPOTHESIS_PROFILE=ci pytest
```

## Credits

VPN007 integrates with the following open-source projects:

- [Xray-core](https://github.com/XTLS/Xray-core) — VLESS+Reality protocol engine
- [3x-ui](https://github.com/MHSanaei/3x-ui) — Xray web management panel
- [wg-easy](https://github.com/wg-easy/wg-easy) — WireGuard/AmneziaWG with web UI (v15.2+ supports AWG 2.0)
- [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-tools) — Obfuscated WireGuard fork
- [Tailscale](https://github.com/tailscale/tailscale) — Mesh VPN overlay network
- [WireGuard](https://www.wireguard.com/) — Base VPN protocol
- [Nginx](https://nginx.org/) — Reverse proxy with stream module
- [Let's Encrypt](https://letsencrypt.org/) — Free TLS certificates via certbot

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

See [LICENSE](LICENSE) for the full license text and [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) for integrated component licenses.

### Integrated component licenses

| Component | License |
|-----------|---------|
| Xray-core | MPL-2.0 |
| 3x-ui | GPL-3.0 |
| AmneziaWG | GPL-2.0 / MIT |
| Tailscale | BSD-3-Clause |
| WireGuard | GPL-2.0 |

## Copyright

© Vadim Pavlov 2026
