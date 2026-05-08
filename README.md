# VPN007

A Python CLI tool that deploys multiple anti-censorship VPN services on a single Linux VM using Docker Compose.

VPN007 generates all the configuration files needed to run Xray (VLESS+Reality), AmneziaWG 2.0, and Tailscale behind an Nginx reverse proxy with a legitimate cover website. Traffic is routed through standard HTTPS ports (443/tcp) using a two-layer architecture: Layer 4 SNI-based routing sends Reality traffic directly to Xray, while everything else goes through Layer 7 path-based routing with TLS termination.

The tool also provisions an nftables firewall with AS/subnet blocking, sets up systemd timers for blocklist updates and hostname resolution, manages TLS certificates via Let's Encrypt, and can generate forwarding scripts for multi-VM relay architectures.

## Table of contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Run modes](#run-modes)
  - [Quick start](#quick-start)
  - [Deploying to a remote server without source code](#deploying-to-a-remote-server-without-source-code)
  - [CLI options](#cli-options)
  - [Configuration precedence](#configuration-precedence)
  - [Input validation](#input-validation)
  - [Generated output structure](#generated-output-structure)
  - [Docker containers](#docker-containers)
  - [Common operations](#common-operations)
  - [Firewall management script (`vpn007-fw.sh`)](#firewall-management-script-vpn007-fwsh)
  - [TLS certificate management](#tls-certificate-management)
  - [Lab/staging deployment](#labstaging-deployment)
  - [Low-memory deployment (1 GB RAM)](#low-memory-deployment-1-gb-ram)
  - [SSH access security](#ssh-access-security)
  - [Brute-force protection](#brute-force-protection)
  - [Admin credentials](#admin-credentials)
- [Inter-VM forwarding (relay architecture)](#inter-vm-forwarding-relay-architecture)
  - [Supported tunnel types](#supported-tunnel-types)
  - [Step 1: Configure VM-A](#step-1-configure-vm-a-entrance-node)
  - [Step 2: Prepare VM-B](#step-2-prepare-vm-b-exit-node)
  - [Step 3: Run the forwarding script on VM-B](#step-3-run-the-forwarding-script-on-vm-b)
  - [Step 4: Verify the tunnel](#step-4-verify-the-tunnel)
  - [Reverse-initiated connections](#reverse-initiated-connections)
  - [Dual-role: VM as both VPN node and exit node](#dual-role-vm-as-both-vpn-node-and-exit-node)
  - [Disabling forwarding to an exit node](#disabling-forwarding-to-an-exit-node)
  - [Disabling the exit-node role on this VM](#disabling-the-exit-node-role-on-this-vm)
- [Backup and restore](#backup-and-restore)
- [Upgrading](#upgrading)
- [IPv6 support](#ipv6-support)
- [Health checks and monitoring](#health-checks-and-monitoring)
- [Log management](#log-management)
- [Kernel parameters](#kernel-parameters)
- [CLI reference](#cli-reference)
- [Running tests](#running-tests)
- [Uninstalling VPN007](#uninstalling-vpn007)
- [Rollback](#rollback)
- [Container resource limits](#container-resource-limits)
- [Docker network isolation](#docker-network-isolation)
- [Web panel rate limiting](#web-panel-rate-limiting)
- [Security hardening (AppArmor)](#security-hardening-apparmor)
- [Credits](#credits)
- [License](#license)

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
| dig (dnsutils) | System package | Hostname resolution for access control |
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

| Resource | Bare minimum | Minimum | Recommended |
|----------|--------------|---------|-------------|
| CPU | 1 vCPU | 1 vCPU | 2+ vCPU |
| RAM | 1 GB — up to 10 clients (swap auto-provisioned) | 2 GB — up to 20-30 clients | 4 GB — many concurrent clients |
| Disk | 20 GB | 20 GB | 30 GB |

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

These flags are CLI-only and cannot be set via `.env` file.

| Flag | Description |
|------|-------------|
| `--dry-run` | Generate config files only — no containers, no firewall, no timers |
| `--debug` | Enable verbose debug logging (full command stdout/stderr on console) |
| `--env-file PATH` | Path to `.env` file (default: `.env` in current directory) |
| `--version` | Show version and exit |

The `AUTO_INSTALL=y` environment variable can be set to skip interactive prompts (for scripted/CI deployments). It is not a CLI flag.

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
| `--xui-path-prefix` | `XUI_PATH_PREFIX` | `/secretpanel-<random>` | URL path for 3x-ui web panel |
| `--awg-panel-path-prefix` | `AWG_PANEL_PATH_PREFIX` | `/awgadmin-<random>` | URL path for AmneziaWG panel |
| `--enable-port-8443` | `ENABLE_PORT_8443` | `false` | Enable secondary HTTPS port 8443 |

When not explicitly set, the deployer appends a random 6-character suffix to the default panel path prefixes (e.g., `/secretpanel-a7f3b2`). This prevents adversaries who know the tool from probing predictable paths. Set explicit values in `.env` if you need stable URLs.

#### Xray / Reality

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--xray-internal-port` | `XRAY_INTERNAL_PORT` | `10443` | Internal container port for Xray |

Reality key pair (private key, public key, short_id) is auto-generated at deploy time if not provided.

#### AmneziaWG

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--awg-listen-port` | `AWG_LISTEN_PORT` | *(random 10000-65535)* | UDP listen port on host (randomized to avoid DPI fingerprinting on standard port 51820) |
| `--awg-panel-port` | `AWG_PANEL_PORT` | `51821` | Web panel port (local-only) |

Obfuscation parameters (env vars only — provide all or none for auto-generation):

| Env var | Range | Description |
|---------|-------|-------------|
| `AWG_S1` | 0-1132 (rec. 15-150) | Random prefix for Init packets |
| `AWG_S2` | 0-1188 (rec. 15-150) | Random prefix for Response packets |
| `AWG_S3` | 0-1216 (rec. 15-150) | Random prefix for Cookie packets |
| `AWG_S4` | 0-32 | Random prefix for Data packets |
| `AWG_H1` | Range `min-max` in 5-2147483647 | Dynamic header range for Init packets (AmneziaWG 2.0) |
| `AWG_H2` | Range `min-max` in 5-2147483647 | Dynamic header range for Response packets |
| `AWG_H3` | Range `min-max` in 5-2147483647 | Dynamic header range for Cookie packets |
| `AWG_H4` | Range `min-max` in 5-2147483647 | Dynamic header range for Data packets |
| `AWG_JC` | 1-128 (rec. 4-10) | Junk packet count |
| `AWG_JMIN` | 0-1280 | Min junk packet size (default: 50) |
| `AWG_JMAX` | 0-1280 | Max junk packet size (default: 1000) |

CPS signature packets (protocol imitation — makes traffic look like a known UDP protocol):

| Env var | Default | Description |
|---------|---------|-------------|
| `AWG_I1` | `<b 0x000100002112a442><r 12>` | STUN Binding Request (WebRTC) |
| `AWG_I2` | `<b 0x0101><r 4><t><r 8>` | STUN follow-up with timestamp |
| `AWG_I3` | `<r 32>` | Random entropy packet |
| `AWG_I4` | *(empty)* | Optional additional signature |
| `AWG_I5` | *(empty)* | Optional additional signature |

The default I1-I3 signatures mimic WebRTC/STUN traffic (video call signaling). This is the most effective protocol for bypassing DPI because STUN is used by Google Meet, Zoom, Teams, and every WebRTC application — blocking it would break video conferencing.

Alternative I1 signatures for different scenarios:

| Protocol | CPS value | When to use |
|----------|-----------|-------------|
| **WebRTC/STUN** (default) | `<b 0x000100002112a442><r 12>` | Best general-purpose choice |
| **DNS response** | `<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>` | If STUN is throttled |
| **QUIC Initial** | Capture with Wireshark, wrap in `<b 0x...>` | Maximum stealth (unique per server) |

CPS format tags: `<b 0xHEX>` static bytes, `<r N>` random bytes, `<t>` timestamp, `<rc N>` random letters, `<rd N>` random digits.

#### Tailscale

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--tailscale-auth-key` | `TAILSCALE_AUTH_KEY` | *(empty — manual auth)* | Auth key for automatic registration |
| `--tailscale-hostname` | `TAILSCALE_HOSTNAME` | *(empty — uses system hostname)* | Node hostname in the tailnet |
| `--tailscale-extra-args` | `TAILSCALE_EXTRA_ARGS` | `--advertise-exit-node` | Extra args for Tailscale daemon |

When `TAILSCALE_AUTH_KEY` is empty, the Tailscale container logs a URL for manual browser-based authentication. Set an auth key (generate at https://login.tailscale.com/admin/settings/keys) for unattended deployments.

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

Two independent access control layers:

**Panel access** (Nginx `allow`/`deny` — controls 3x-ui and AmneziaWG web panels):

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--approved-ips` | `APPROVED_IPS` | *(empty)* | IPs/CIDRs allowed to access management panels |
| `--approved-hostnames` | `APPROVED_HOSTNAMES` | *(empty)* | Hostnames resolved periodically for panel access |
| `--hostname-resolve-interval-min` | `HOSTNAME_RESOLVE_INTERVAL_MIN` | `30` | Re-resolve interval in minutes |

**SSH access** (nftables port 22 — independent of panel access):

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--ssh-approved-ips` | `SSH_APPROVED_IPS` | *(empty — open to all)* | IPs allowed to SSH (restricts when set) |
| `--ssh-approved-hostnames` | `SSH_APPROVED_HOSTNAMES` | *(empty)* | Hostnames resolved periodically for SSH access |

When both `SSH_APPROVED_IPS` and `SSH_APPROVED_HOSTNAMES` are empty, SSH is open from all networks. As soon as either is set, SSH is restricted to those addresses only.

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
| `--tunnel-subnet` | `TUNNEL_SUBNET` | `10.99.0.0/30` | WireGuard tunnel subnet |

#### Exit node role

When a VM runs the full VPN007 stack AND also serves as an exit node for another VPN007 instance, enable the exit node role. This creates a separate tunnel and nftables table that coexists with the main VPN stack without interference.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--exit-node-enabled` | `EXIT_NODE_ENABLED` | `false` | Accept forwarded traffic from another VPN007 node |
| `--exit-node-tunnel-type` | `EXIT_NODE_TUNNEL_TYPE` | *(none)* | Tunnel type: `wireguard`, `ssh`, or `tailscale` |
| `--exit-node-peer-ip` | `EXIT_NODE_PEER_IP` | *(none)* | IP of the peer VM forwarding traffic to us |
| `--exit-node-tunnel-subnet` | `EXIT_NODE_TUNNEL_SUBNET` | `10.99.1.0/30` | Tunnel subnet (must differ from `TUNNEL_SUBNET`) |
| `--exit-node-listen-port` | `EXIT_NODE_LISTEN_PORT` | `51822` | WireGuard listen port for exit-node tunnel |
| `--exit-node-reverse-initiated` | `EXIT_NODE_REVERSE_INITIATED` | `false` | Peer initiates tunnel to this exit node |

#### Initial clients

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--xray-initial-client` | `XRAY_INITIAL_CLIENT` | `default-client` | Name for the initial Xray VLESS+Reality client |
| `--awg-initial-peer` | `AWG_INITIAL_PEER` | `default-peer` | Name for the initial AmneziaWG peer |

The deployer creates one Xray client and one AmneziaWG peer during initial deployment. A UUID and VLESS share link are generated for the Xray client; WireGuard keys and a `.conf` file are generated for the AmneziaWG peer. Client configs are saved to `{output_dir}/clients/`.

Both client configs use the `DOMAIN` value as the server address (not the IP), since:
- The VLESS+Reality connection requires SNI matching the TLS certificate
- Domain-based endpoints survive IP changes without client reconfiguration
- DNS resolution handles the domain → IP mapping on the client side

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

### Input validation

The deployer validates all parameters at startup and exits with a clear error message if any value is invalid. Key validation rules:

| Parameter | Validation |
|-----------|-----------|
| `DOMAIN` | Required; must be a valid hostname |
| `COVER_SITE_URL` | Required when `COVER_SITE_MODE=proxy`; must be a valid URL |
| `XUI_PATH_PREFIX`, `AWG_PANEL_PATH_PREFIX` | Must start with `/` |
| `AWG_S1` | Integer 0-1132 |
| `AWG_S2` | Integer 0-1188 |
| `AWG_S3` | Integer 0-1216 |
| `AWG_S4` | Integer 0-32 |
| `AWG_H1`-`AWG_H4` | Range format `min-max` (5-2147483647), non-overlapping |
| `AWG_JC` | Integer 1-128 |
| `AWG_JMIN`, `AWG_JMAX` | Integer 0-1280; `JMAX` must be > `JMIN` |
| `AWG_S1`-`H4` group | All eight must be provided together, or all omitted for auto-generation |
| `TLS_VERSIONS` | Comma-separated; only `1.2` and `1.3` accepted |
| `HTTPS_PORT` | Integer 1-65535 |
| `TUNNEL_TYPE` | Must be `wireguard`, `ssh`, or `tailscale` when `FORWARDING_ENABLED=true` |
| `SECONDARY_VM_IP` | Required when `FORWARDING_ENABLED=true` |
| `FORWARDING_PORTS` | Required when `FORWARDING_ENABLED=true`; format `proto:port:port[:desc]` |
| `EXIT_NODE_TUNNEL_TYPE` | Required when `EXIT_NODE_ENABLED=true` |
| `EXIT_NODE_PEER_IP` | Required when `EXIT_NODE_ENABLED=true`; valid IP address |
| `EXIT_NODE_TUNNEL_SUBNET` | Must differ from `TUNNEL_SUBNET` when both are enabled |
| `APPROVED_IPS`, `SSH_APPROVED_IPS` | Valid IPv4/IPv6 addresses or CIDR notation |
| `BLOCKED_AS_NUMBERS` | Must match `AS<digits>` format |

If validation fails, the deployer prints the invalid parameter name, the provided value, the expected format, and exits with code 1. No files are generated or modified.

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
│   ├── xray-default-client.txt  # VLESS share link
│   └── awg-default-peer.conf    # AmneziaWG client config
├── docs/
│   ├── README.md
│   ├── troubleshooting.md
│   └── client-guides.md
└── forwarding-install.py       # (only when forwarding enabled)
```

When `EXIT_NODE_ENABLED=true`, an additional directory is generated:

**WireGuard tunnel type** (`EXIT_NODE_TUNNEL_TYPE=wireguard`):

```
deploy/
└── exit-node/
    ├── wg-exit-node.conf           # WireGuard config for exit-node tunnel
    ├── nftables-exit-node.conf     # Separate nftables table for exit-node NAT
    ├── exit-node-public.key        # Public key to share with the peer VM
    └── README.md                   # Setup instructions for this deployment
```

**SSH tunnel type** (`EXIT_NODE_TUNNEL_TYPE=ssh`):

```
deploy/
└── exit-node/
    ├── vpn007-exit-node-ssh.service  # systemd unit for autossh tunnel
    ├── nftables-exit-node.conf       # Separate nftables table for exit-node NAT
    ├── exit-node-ssh-private.key     # Ed25519 private key (install on this VM)
    ├── exit-node-ssh-public.key      # Public key (install on peer VM)
    ├── setup-exit-node.sh            # One-command setup script
    └── README.md                     # Setup instructions
```

**Tailscale tunnel type** (`EXIT_NODE_TUNNEL_TYPE=tailscale`):

```
deploy/
└── exit-node/
    ├── vpn007-exit-node-tailscale.service  # systemd unit for nftables + forwarding
    ├── nftables-exit-node.conf             # Separate nftables table for exit-node NAT
    ├── setup-exit-node.sh                  # One-command setup script
    └── README.md                           # Setup instructions
```

All volume mounts in `docker-compose.yml` use relative paths (`./data/...`), so the output directory is portable — copy it anywhere and run `docker compose up -d`.

### Docker containers

| Container | Image | Network | Purpose |
|-----------|-------|---------|---------|
| `vpn007_reverse_proxy` | `nginx:mainline-alpine` | bridge (vpn_net) | L4/L7 routing, TLS termination |
| `vpn007_three_x_ui` | `ghcr.io/mhsanaei/3x-ui:latest` | bridge (vpn_net) | Xray management + VLESS+Reality |
| `vpn007_amneziawg` | `ghcr.io/wg-easy/wg-easy:15.3.0-beta.2` | host | AmneziaWG 2.0 VPN + web panel |
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

### Firewall management script (`vpn007-fw.sh`)

A standalone shell script for managing blocked/allowed IPs, subnets, and AS numbers in the running nftables firewall without regenerating the full config. All changes are applied immediately and automatically saved to `/etc/nftables.conf`, so they persist across reboots.

**Install on the server:**

```bash
cp scripts/vpn007-fw.sh /usr/local/bin/vpn007-fw
chmod +x /usr/local/bin/vpn007-fw
```

**Block/unblock IPs and subnets:**

```bash
# Block a single IP
sudo vpn007-fw block ip 192.168.1.100

# Block a subnet
sudo vpn007-fw block ip 10.0.0.0/8

# Unblock
sudo vpn007-fw unblock ip 192.168.1.100
```

**Block/unblock entire Autonomous Systems:**

```bash
# Block all prefixes announced by an AS (resolves automatically)
sudo vpn007-fw block as AS196747

# Unblock
sudo vpn007-fw unblock as AS196747

# Dry-run: see what prefixes an AS announces without blocking
vpn007-fw resolve as AS196747
```

**Manage SSH access:**

```bash
# Allow SSH from a new IP
sudo vpn007-fw allow ssh 203.0.113.50

# Revoke SSH access
sudo vpn007-fw deny ssh 203.0.113.50
```

**Manage web panel access:**

```bash
# Allow panel access from a new IP (updates Nginx and reloads)
sudo vpn007-fw allow panel 10.0.0.5

# Revoke panel access
sudo vpn007-fw deny panel 10.0.0.5
```

**List current rules:**

```bash
# Show everything
sudo vpn007-fw list

# Show only blocked IPs/subnets
sudo vpn007-fw list blocked

# Show SSH-approved IPs
sudo vpn007-fw list ssh
```

**Built-in help:**

```bash
vpn007-fw --help
```

This prints the full command reference, environment variables, and usage examples.

Changes made via `vpn007-fw` are applied immediately and automatically saved to `/etc/nftables.conf` (loaded by `nftables.service` on boot). To override the save path, set the `VPN007_NFTABLES_CONF` environment variable.

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

### Low-memory deployment (1 GB RAM)

The full stack runs on 1 GB RAM for light usage (1-10 concurrent clients). Typical memory breakdown:

| Component | RAM usage |
|-----------|-----------|
| OS + systemd + nftables | ~100-150 MB |
| Docker daemon | ~100-150 MB |
| Nginx (reverse_proxy + cover_site) | ~20-30 MB |
| 3x-ui + Xray | ~80-120 MB |
| wg-easy (AmneziaWG) | ~50-80 MB |
| Tailscale | ~30-50 MB |
| **Total (typical)** | **~400-580 MB** |

The 2 GB recommendation accounts for spikes during Docker image pulls, cert renewals, and many concurrent clients. To run comfortably on 1 GB:

**1. Swap (auto-provisioned):**

VPN007 automatically detects low-memory systems (≤1.5 GB RAM) during full deployment and provisions a 1 GB swapfile if no swap is configured. This is persisted in `/etc/fstab` so it survives reboots. No manual action needed.

If you prefer to provision swap manually (e.g., during dry-run workflows or with a custom size):

```bash
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

**2. Limit Docker log memory:**

```bash
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
systemctl restart docker
```

**3. (Optional) Drop Tailscale** if you don't need mesh management — saves ~40 MB:

```bash
# Start only the services you need
docker compose up -d reverse_proxy three_x_ui amneziawg cover_site
```

**4. Use static cover site mode** — proxy mode enables Nginx caching which uses additional RAM.

**5. (Optional) Drop 3x-ui** if you only need AmneziaWG — 3x-ui is the heaviest container. You can pre-configure Xray with a static `config.json` and run a standalone `teddysun/xray` container instead, but you lose the web panel.

**What to expect on 1 GB + 1 GB swap:**
- Normal operation: fine for 1-10 concurrent VPN clients
- `docker compose pull`: may use swap briefly (image decompression spikes)
- Certbot renewal: brief spike, handled by swap
- Don't go below 1 GB without removing at least one service

### SSH access security

SSH access behavior depends on whether `SSH_APPROVED_IPS` or `SSH_APPROVED_HOSTNAMES` is configured:

| Configuration | Behavior |
|---------------|----------|
| Both empty (default) | SSH open from all networks |
| `SSH_APPROVED_IPS=203.0.113.50` | SSH restricted to listed IPs only |
| `SSH_APPROVED_HOSTNAMES=admin.example.com` | SSH restricted to resolved IPs only |
| Both set | SSH restricted to combined static IPs + resolved hostnames |

When restricted, the nftables firewall only allows port 22 from addresses in the `approved_ssh_v4` set. The hostname resolver periodically re-resolves `SSH_APPROVED_HOSTNAMES` and updates the nftables set atomically (same interval as panel hostname resolution).

This is completely independent of panel access (`APPROVED_IPS` / `APPROVED_HOSTNAMES`), which is enforced at the Nginx level.

Recommendations:
- For production, set `SSH_APPROVED_IPS` or `SSH_APPROVED_HOSTNAMES` to reduce attack surface
- For operators with dynamic IPs, use `SSH_APPROVED_HOSTNAMES` with a DDNS hostname
- Tailscale provides out-of-band management access regardless of firewall rules (it uses its own overlay network)

### Brute-force protection

The nftables firewall includes rate limiting for SSH connections (port 22): a maximum of 5 new connections per minute per source IP. Connections exceeding this rate are dropped silently.

For additional protection, consider installing `fail2ban` on the server:

```bash
apt install fail2ban

# Enable the SSH jail (enabled by default on Debian/Ubuntu)
systemctl enable --now fail2ban
```

The web panels (3x-ui and AmneziaWG) are protected by:
1. IP-based access control (`APPROVED_IPS` / `APPROVED_HOSTNAMES`) — connections from unauthorized IPs never reach the panel
2. Random admin credentials generated at deploy time (see below)
3. Secret URL path prefixes with random suffixes

For environments where IP restriction is not feasible, consider placing the panels behind Tailscale (access via `100.x.x.x` tailnet IPs only) instead of exposing them on the public interface.

### Admin credentials

**3x-ui panel:**
- **Username**: `admin` (default — change on first login)
- **Password**: `admin` (default — change on first login)
- Retrieve: `docker exec -it vpn007_three_x_ui /app/x-ui setting -show`

**AmneziaWG panel (wg-easy):**
- **Username**: `admin` + 3 random alphanumeric characters (e.g. `adminx7k`)
- **Password**: 16-24 random characters (letters, digits, and `!@#%^&*`)
- Credentials are written to `docker-compose.yml` as `INIT_USERNAME` / `INIT_PASSWORD` env vars (used only on first container start)
- Retrieve: `grep 'INIT_USERNAME\|INIT_PASSWORD' /opt/vpn007/docker-compose.yml`

The AmneziaWG panel setup (user creation, host/port configuration) is fully automated via wg-easy's unattended setup mechanism — no manual wizard interaction required.

To retrieve credentials after deployment:

```bash
# 3x-ui credentials
docker exec -it vpn007_three_x_ui /app/x-ui setting -show

# AmneziaWG credentials
grep 'INIT_USERNAME\|INIT_PASSWORD' /opt/vpn007/docker-compose.yml
```

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

**Security note:** The generated `forwarding-install.py` contains embedded cryptographic keys (WireGuard private keys or SSH private keys). Handle it with care:
1. Transfer to VM-B over a secure channel only (SCP, SFTP, or via Tailscale)
2. Set restrictive permissions before execution: `chmod 700 /root/forwarding-install.py`
3. **Delete the script from VM-B after successful installation** — the keys are copied to their final locations during setup
4. Do not commit this file to version control or leave it on intermediate machines
5. If the script must be stored temporarily, ensure it is readable only by root (`0700`)

### Hardware requirements for VM-B (exit node)

VM-B only runs a tunnel endpoint and NAT — no Docker, no web panels, no TLS termination.

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | 1+ vCPU |
| RAM | 512 MB | 1 GB |
| Disk | 5 GB | 10 GB |
| OS | Debian 11+ / Ubuntu 22.04+ / Alpine 3.18+ | Same |

VM-B's bandwidth is the bottleneck for client internet speed. Choose a VM-B with good network throughput in the geographic location you want traffic to exit from.

### Failure behavior (fail closed)

If the tunnel between VM-A and VM-B goes down:

- **Traffic is dropped, not leaked.** Forwarding uses nftables DNAT rules pointing to the tunnel peer IP (e.g., `10.99.0.2`). When the tunnel is down, that IP is unreachable — packets are silently dropped.
- **Clients see a connection timeout**, not a fallback to VM-A's own internet connection. No traffic ever exits from VM-A's public IP.
- **Reconnection is automatic.** The tunnel daemon retries with exponential backoff (default: 5s → 10s → 20s → ... → 300s max). Once the tunnel re-establishes, forwarding resumes immediately.
- **This is fail-closed by design** — it protects against accidental IP leaks. If you need fail-open behavior (fall back to VM-A's exit when VM-B is unreachable), you would need to add a custom health-check script that removes the DNAT rules on tunnel failure. This is not provided by default because it compromises the privacy guarantee of the relay architecture.

### Supported tunnel types

All three tunnel types are supported for both the forwarding role (`TUNNEL_TYPE`) and the exit-node role (`EXIT_NODE_TUNNEL_TYPE`):

| Tunnel type | Use case | Requirements on peer VM |
|-------------|----------|------------------------|
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

The tunnel connects as a dedicated unprivileged user (`vpn007-tunnel`) on the remote side. This user has `/usr/sbin/nologin` as its shell and cannot execute commands — it only holds the SSH connection open for port forwarding. The `forwarding-install.py` script creates this user automatically on the receiving VM during setup.

```bash
# The forwarding script sets up something like:
autossh -M 20000 -N -L 0.0.0.0:443:localhost:443 \
        -i /root/.ssh/vpn007_tunnel_key vpn007-tunnel@VM-A
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

After setup, VM-B initiates the Tailscale connection (works behind NAT), and traffic forwarded from VM-A exits through VM-B's internet connection.

### Troubleshooting forwarding

| Symptom | Check |
|---------|-------|
| Tunnel won't establish | Verify VM-B can reach VM-A on the tunnel port (`nc -zv VM-A 51821`) |
| Traffic not forwarding | Check nftables DNAT rules on both VMs (`nft list table ip nat`) |
| Intermittent drops | Check reconnection logs; increase `RECONNECT_MAX_DELAY_SEC` |
| VM-B can't reach internet | Verify IP forwarding is enabled (`sysctl net.ipv4.ip_forward`) |
| Reverse tunnel fails | Ensure VM-A's SSH/WG port is open in its firewall for VM-B's IP |

### Converting from two-node relay back to single-node

If you no longer need the relay architecture and want all traffic to enter and exit from a single VM, follow these steps.

#### Scenario A: Keep VM-A as the single node (same IP for ingress and egress)

VM-A already runs the full VPN007 stack. You just need to disable forwarding and remove the tunnel.

**On VM-A:**

1. Update `.env`:

```bash
# Disable forwarding
FORWARDING_ENABLED=false

# Remove or comment out these:
# TUNNEL_TYPE=
# SECONDARY_VM_IP=
# FORWARDING_PORTS=
```

2. Re-run the deployer to regenerate configs without forwarding rules:

```bash
sudo vpn007
# or dry-run + manual apply:
vpn007 --dry-run
nft -f deploy/nftables.conf
```

3. Remove the tunnel interface (if WireGuard was used):

```bash
wg-quick down wg-tunnel   # or whatever the interface was named
rm /etc/wireguard/wg-tunnel.conf
```

4. Verify traffic now exits from VM-A's own IP:

```bash
# From a connected VPN client
curl -4 ifconfig.me   # Should show VM-A's public IP
```

**On VM-B (decommission):**

```bash
# Remove the tunnel
wg-quick down wg-tunnel
rm /etc/wireguard/wg-tunnel.conf

# Remove forwarding rules
nft flush table ip nat

# Disable IP forwarding
sysctl -w net.ipv4.ip_forward=0

# (Optional) Shut down the VM entirely
```

#### Scenario B: Keep VM-A with separate ingress/egress IPs (multi-IP single node)

If VM-A has multiple IP addresses and you want incoming VPN connections on one IP and outbound internet traffic from a different IP — all on the same machine:

1. Update `.env`:

```bash
# Disable forwarding (no more VM-B)
FORWARDING_ENABLED=false

# Configure multi-IP on the single VM
INCOMING_IP=10.0.0.2       # Private IP bound to the interface (for Nginx bind)
OUTGOING_IP=10.0.0.3       # Different private IP for outbound SNAT
PUBLIC_IPV4=203.0.113.10   # Public IP clients connect to
```

2. Ensure both IPs are assigned to the VM's network interface:

```bash
# Verify IPs are present
ip addr show

# If the outgoing IP isn't assigned, add it:
ip addr add 10.0.0.3/24 dev eth0
# Make persistent via /etc/network/interfaces or netplan
```

3. Re-deploy:

```bash
sudo vpn007
```

The generated `nftables.conf` will include a SNAT rule in the postrouting chain that rewrites the source IP of outbound traffic to `OUTGOING_IP`. Incoming connections arrive on `INCOMING_IP`, outbound exits from `OUTGOING_IP`.

4. Verify:

```bash
# Check the SNAT rule
nft list table ip nat
# Should show: oifname "eth0" snat to 10.0.0.3

# From a VPN client
curl -4 ifconfig.me   # Should show the public IP mapped to OUTGOING_IP
```

#### Scenario C: Migrate everything to VM-B (new single node)

If you want to decommission VM-A and run the full stack on VM-B instead:

1. On VM-B, install the VPN007 prerequisites (Docker, nftables, Python 3.12+)

2. Copy your `.env` from VM-A and update it:

```bash
# Disable forwarding
FORWARDING_ENABLED=false

# Update IPs to VM-B's addresses
PUBLIC_IPV4=198.51.100.20
# INCOMING_IP=...  (if needed)
# OUTGOING_IP=...  (if needed)

# Update DNS: point your DOMAIN to VM-B's IP
```

3. Deploy on VM-B:

```bash
sudo vpn007
```

4. Update DNS records to point `DOMAIN` to VM-B's public IP.

5. Decommission VM-A:

```bash
# On VM-A
docker compose down
# Remove systemd timers
systemctl disable --now blocklist-updater.timer hostname-resolver.timer certbot-renew.timer
```

#### Cleanup checklist

After converting to single-node, ensure these are cleaned up:

| Item | VM-A | VM-B |
|------|------|------|
| Tunnel interface (wg-tunnel) | Remove | Remove |
| Tunnel config (/etc/wireguard/wg-tunnel.conf) | Remove | Remove |
| DNAT/SNAT forwarding rules in nftables | Removed by re-deploy | Flush manually |
| autossh service (if SSH tunnel) | Stop + disable | Stop + disable |
| Tailscale routes (if Tailscale tunnel) | Remove `--accept-routes` | Remove |
| forwarding-install.py on VM-B | — | Delete |
| IP forwarding sysctl on VM-B | — | Set to 0 |

### Dual-role: VM as both VPN node and exit node

A VM can simultaneously run the full VPN007 stack (serving its own clients) AND act as an exit node for another VPN007 instance. This is useful when you have two VPN servers and want either one to serve as a backup exit for the other.

```
┌─────────────────────────────────────────────────────────────────┐
│  VM-A (dual-role)                                                │
│                                                                  │
│  [VPN007 stack] ─── tunnel (10.99.0.0/30) ──→ VM-B (exit)      │
│       ↑                                                          │
│  [Exit node role] ←── tunnel (10.99.1.0/30) ── VM-C (entrance) │
│       │                                                          │
│       └──→ Internet (masquerade)                                 │
└─────────────────────────────────────────────────────────────────┘
```

The two roles use completely separate resources:
- **Different nftables tables**: main firewall uses `table inet filter`, exit-node uses `table ip vpn007_exit_node`
- **Different tunnel interfaces**: VPN clients use the AmneziaWG interface, exit-node uses `wg-exit-node` (WireGuard), autossh (SSH), or Tailscale overlay
- **Different tunnel subnets**: forwarding uses `10.99.0.0/30`, exit-node uses `10.99.1.0/30` (configurable)
- **Different listen ports**: AmneziaWG uses its own port, exit-node tunnel uses port `51822` (configurable, WireGuard only)

#### Example: Two VMs, each serving as exit for the other

**VM-A** (IP: 203.0.113.10) forwards its traffic through VM-B, and also serves as exit node for VM-B:

```bash
# .env on VM-A
DOMAIN=vpn-a.example.com

# Forward my clients' traffic to VM-B
FORWARDING_ENABLED=true
TUNNEL_TYPE=wireguard
SECONDARY_VM_IP=198.51.100.20
TUNNEL_SUBNET=10.99.0.0/30
FORWARDING_PORTS=tcp:443:443:HTTPS,udp:51820:51820:AWG

# Also serve as exit node for VM-B's forwarded traffic
EXIT_NODE_ENABLED=true
EXIT_NODE_TUNNEL_TYPE=wireguard
EXIT_NODE_PEER_IP=198.51.100.20
EXIT_NODE_TUNNEL_SUBNET=10.99.1.0/30
EXIT_NODE_LISTEN_PORT=51822
```

**VM-B** (IP: 198.51.100.20) forwards its traffic through VM-A, and also serves as exit node for VM-A:

```bash
# .env on VM-B
DOMAIN=vpn-b.example.com

# Forward my clients' traffic to VM-A
FORWARDING_ENABLED=true
TUNNEL_TYPE=wireguard
SECONDARY_VM_IP=203.0.113.10
TUNNEL_SUBNET=10.99.0.0/30
FORWARDING_PORTS=tcp:443:443:HTTPS,udp:51820:51820:AWG

# Also serve as exit node for VM-A's forwarded traffic
EXIT_NODE_ENABLED=true
EXIT_NODE_TUNNEL_TYPE=wireguard
EXIT_NODE_PEER_IP=203.0.113.10
EXIT_NODE_TUNNEL_SUBNET=10.99.1.0/30
EXIT_NODE_LISTEN_PORT=51822
```

After deploying both VMs:
- VM-A's VPN clients exit through VM-B's IP (198.51.100.20)
- VM-B's VPN clients exit through VM-A's IP (203.0.113.10)
- Both VMs serve their own cover websites and management panels independently

#### Setup steps for exit-node role

1. Deploy with `EXIT_NODE_ENABLED=true` — generates configs in `deploy/exit-node/`

**WireGuard:**

2. Copy `exit-node/wg-exit-node.conf` to `/etc/wireguard/`
3. Replace `REPLACE_WITH_PEER_PUBLIC_KEY` with the peer's actual public key
4. Exchange public keys between VMs (your key is in `exit-node/exit-node-public.key`)
5. Bring up the tunnel: `wg-quick up wg-exit-node`
6. Enable on boot: `systemctl enable wg-quick@wg-exit-node`

**SSH:**

2. Run the setup script: `chmod +x exit-node/setup-exit-node.sh && sudo ./exit-node/setup-exit-node.sh`
3. Create the `vpn007-tunnel` user on the peer VM and install the public key (`exit-node/exit-node-ssh-public.key`) in `/home/vpn007-tunnel/.ssh/authorized_keys`
4. The systemd service (`vpn007-exit-node-ssh`) handles autossh with automatic reconnection

**Tailscale:**

2. Run the setup script: `chmod +x exit-node/setup-exit-node.sh && sudo ./exit-node/setup-exit-node.sh`
3. Ensure both VMs are on the same Tailscale tailnet
4. The systemd service (`vpn007-exit-node-tailscale`) loads nftables rules on boot

See `deploy/exit-node/README.md` for detailed instructions generated for your specific configuration.

#### Disabling forwarding to an exit node

To stop forwarding traffic from this VM to a remote exit node (VM-B) and route traffic directly to the internet from this VM instead:

**1. Update `.env`:**

```bash
FORWARDING_ENABLED=false
# Comment out or remove:
# TUNNEL_TYPE=
# SECONDARY_VM_IP=
# FORWARDING_PORTS=
```

**2. Re-deploy to regenerate configs without forwarding rules:**

```bash
sudo vpn007
# or dry-run + manual apply:
vpn007 --dry-run
nft -f deploy/nftables.conf
docker compose up -d
```

**3. Remove the tunnel interface on this VM:**

```bash
# WireGuard tunnel
wg-quick down wg-tunnel
systemctl disable wg-quick@wg-tunnel
rm -f /etc/wireguard/wg-tunnel.conf

# SSH tunnel
systemctl disable --now autossh-tunnel
rm -f /etc/systemd/system/autossh-tunnel.service
systemctl daemon-reload

# Tailscale — no interface to remove; just stop advertising routes if needed
```

**4. Verify traffic now exits from this VM's own IP:**

```bash
# From a connected VPN client
curl -4 ifconfig.me   # Should show this VM's public IP, not VM-B's
```

**5. (Optional) Clean up VM-B:**

If VM-B is no longer needed as an exit node for anyone:

```bash
# On VM-B
wg-quick down wg-tunnel           # WireGuard
systemctl disable --now vpn007-exit-node-ssh   # SSH
nft delete table ip vpn007_forward
sysctl -w net.ipv4.ip_forward=0
userdel -r vpn007-tunnel 2>/dev/null   # Remove the tunnel user if SSH was used
```

#### Disabling the exit-node role on this VM

To stop this VM from accepting forwarded traffic from another VPN007 instance (stop serving as an exit node for a peer):

**1. Update `.env`:**

```bash
EXIT_NODE_ENABLED=false
# Comment out or remove:
# EXIT_NODE_TUNNEL_TYPE=
# EXIT_NODE_PEER_IP=
# EXIT_NODE_TUNNEL_SUBNET=
# EXIT_NODE_LISTEN_PORT=
```

**2. Tear down the exit-node tunnel:**

```bash
# WireGuard
wg-quick down wg-exit-node
systemctl disable wg-quick@wg-exit-node
rm -f /etc/wireguard/wg-exit-node.conf

# SSH
systemctl disable --now vpn007-exit-node-ssh
rm -f /etc/systemd/system/vpn007-exit-node-ssh.service
rm -f /root/.ssh/vpn007_exit_node_key
systemctl daemon-reload

# Tailscale
systemctl disable --now vpn007-exit-node-tailscale
rm -f /etc/systemd/system/vpn007-exit-node-tailscale.service
systemctl daemon-reload
```

**3. Remove the exit-node nftables table:**

```bash
nft delete table ip vpn007_exit_node
```

**4. (Optional) Remove the tunnel user if SSH was used:**

```bash
userdel -r vpn007-tunnel
```

**5. Re-deploy to regenerate configs without exit-node files:**

```bash
sudo vpn007
# or:
vpn007 --dry-run
```

The `deploy/exit-node/` directory will no longer be generated.

**6. Verify:**

```bash
# No exit-node tunnel interface
wg show                          # Should not list wg-exit-node
ip link show wg-exit-node 2>&1   # Should say "does not exist"

# No exit-node nftables table
nft list tables | grep vpn007_exit_node   # Should be empty

# No exit-node systemd services
systemctl list-units 'vpn007-exit*'       # Should be empty

# Main VPN stack still works
docker compose ps                         # All containers Up
curl -sk https://your.domain/             # Cover site responds
```

**Note:** Disabling the exit-node role does NOT affect the main VPN007 stack on this VM. Your own VPN clients, cover website, firewall, and management panels continue to work unchanged.

## Backup and restore

### What to back up

The `data/` directory contains all persistent state. Back it up regularly:

| Path | Contents | Impact if lost |
|------|----------|----------------|
| `data/three_x_ui/` | 3x-ui database, Xray configs, client list | Lose all Xray clients and panel settings |
| `data/amneziawg/` | WireGuard keys, peer configs | Lose all AmneziaWG peers (must redistribute configs) |
| `data/tailscale/` | Tailscale node state | Node re-registers on next start (minor) |
| `data/letsencrypt/` | TLS certificates and account keys | Must re-acquire certs (automatic, but brief downtime) |
| `.env` | Deployment configuration | Must recreate from memory |
| `nftables.conf` | Firewall rules | Regenerated by re-running deployer |

### Backup procedure

```bash
# Stop services to ensure consistent state
cd /opt/vpn007
docker compose stop

# Create a timestamped backup
tar czf /root/vpn007-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
    .env data/ nftables.conf docker-compose.yml

# Restart services
docker compose start
```

For zero-downtime backups, you can skip the stop/start — the SQLite database in 3x-ui handles concurrent reads, and WireGuard configs are rarely written. However, stopping ensures a fully consistent snapshot.

### Restore procedure

```bash
# On a fresh VM with VPN007 prerequisites installed
cd /opt/vpn007
tar xzf /root/vpn007-backup-YYYYMMDD-HHMMSS.tar.gz

# Start services
docker compose up -d

# Re-apply firewall
nft -f nftables.conf

# Re-install systemd timers
cp systemd/*.service systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now blocklist-updater.timer hostname-resolver.timer certbot-renew.timer
```

## Upgrading

### Upgrading VPN007 itself

```bash
cd /path/to/vpn007
git pull
pip install -e .

# Re-run the deployer to regenerate configs with new templates
sudo vpn007
# or dry-run first to review changes:
vpn007 --dry-run
diff /opt/vpn007/docker-compose.yml deploy/docker-compose.yml
```

Re-running the deployer on an existing deployment is safe:
- Existing `data/` directories are preserved (never overwritten)
- Configuration files (Nginx, Xray, nftables, systemd) are regenerated from templates
- Docker containers are recreated with the new configs
- Client configurations remain intact in the 3x-ui database and AmneziaWG state

### Upgrading Docker images

```bash
cd /opt/vpn007
docker compose pull
docker compose up -d
```

This pulls the latest versions of all container images and recreates containers. Persistent data in `data/` bind mounts is unaffected.

### Upgrading the host OS

After a major OS upgrade (e.g., Debian 11 → 12):
1. Verify Docker and nftables still work: `docker info`, `nft list ruleset`
2. Re-run `sudo vpn007` to regenerate systemd units (paths may change)
3. Check that all timers are active: `systemctl list-timers`

## IPv6 support

### Dual-stack firewall

The generated `nftables.conf` includes rules for both IPv4 and IPv6:
- `table inet filter` — applies to both address families (input/forward/output chains)
- `table ip nat` — IPv4 NAT (SNAT for outgoing IP, DNAT for forwarding)
- `table ip6 nat` — IPv6 NAT (only when `OUTGOING_IP` is an IPv6 address or forwarding targets IPv6)

Blocked AS prefixes are resolved for both IPv4 and IPv6 and placed in separate nftables sets:
- `blocked_v4` — IPv4 prefixes from blocked AS numbers
- `blocked_v6` — IPv6 prefixes from blocked AS numbers

SSH and panel access sets also have IPv6 counterparts:
- `approved_ssh_v4` / `approved_ssh_v6`
- Panel access is enforced at Nginx level and supports both IPv4 and IPv6 in `APPROVED_IPS`

### IPv6 behavior

| Scenario | Behavior |
|----------|----------|
| `PUBLIC_IPV6` set | Included in client configs; Nginx listens on `[::]:443` |
| `PUBLIC_IPV6` empty | IPv6 auto-detected; if unavailable, IPv4-only configs generated |
| `BLOCKED_AS_NUMBERS` set | Both v4 and v6 prefixes resolved and blocked |
| `SSH_APPROVED_IPS` with IPv6 | Added to `approved_ssh_v6` set |

## Health checks and monitoring

### Post-deployment verification

After deployment, verify all services are running:

```bash
# Check all containers are up
docker compose ps

# Expected output: all services "Up" with correct ports
# vpn007_reverse_proxy   Up   0.0.0.0:443->443/tcp
# vpn007_three_x_ui      Up
# vpn007_amneziawg       Up   0.0.0.0:51820->51820/udp
# vpn007_tailscale       Up
# vpn007_cover_site      Up

# Test the cover site (should return 200)
curl -sk https://your.domain/ | head -20

# Test that Reality SNI routing works (should NOT return your cover site)
curl -sk --resolve www.microsoft.com:443:your-ip https://www.microsoft.com/

# Test panel access (from an approved IP)
curl -sk https://your.domain/secretpanel-XXXXX/

# Check Tailscale status
docker compose exec tailscale tailscale status

# Verify firewall is loaded
nft list ruleset | head -5

# Check systemd timers
systemctl list-timers 'blocklist*' 'hostname*' 'certbot*'
```

### Ongoing monitoring

Key indicators to monitor:

| Check | Command | Expected |
|-------|---------|----------|
| Containers running | `docker compose ps` | All "Up" |
| TLS cert expiry | `openssl s_client -connect localhost:443 </dev/null 2>/dev/null \| openssl x509 -noout -enddate` | >7 days remaining |
| Disk usage | `df -h /` | <80% |
| Docker logs for errors | `docker compose logs --since 1h \| grep -i error` | Empty or expected |
| Tunnel status (if forwarding) | `wg show` or `tailscale status` | Peer connected |
| Blocklist timer | `systemctl status blocklist-updater.timer` | Active, last run <6h ago |

### Container health checks

The generated `docker-compose.yml` includes Docker health checks for critical services:
- **reverse_proxy**: `curl -f http://localhost:80/health` (internal health endpoint)
- **three_x_ui**: TCP check on the Xray port
- **amneziawg**: WireGuard interface exists and has at least one peer configured

Unhealthy containers are automatically restarted by Docker's restart policy (`unless-stopped`).

## Log management

### Docker container logs

By default, Docker uses the `json-file` log driver with no size limit. For production, configure log rotation:

```bash
# /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Then restart Docker: `systemctl restart docker`

This limits each container to 3 log files of 10 MB each (30 MB max per container, ~180 MB total for 6 containers).

### Deployment log

The deployment log at `{output_dir}/deploy.log` records all actions performed during deployment at DEBUG level. It is overwritten on each deployment run. To preserve history, copy it before re-deploying:

```bash
cp deploy/deploy.log deploy/deploy-$(date +%Y%m%d-%H%M%S).log
```

### Systemd timer logs

Timer execution logs are captured by journald:

```bash
# View blocklist updater logs
journalctl -u blocklist-updater.service --since "1 hour ago"

# View hostname resolver logs
journalctl -u hostname-resolver.service --since "1 hour ago"

# View certbot renewal logs
journalctl -u certbot-renew.service --since "1 day ago"
```

Configure journald retention in `/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=200M
MaxRetentionSec=30day
```

## Kernel parameters

VPN007 automatically configures the required Linux kernel parameters during deployment. No manual `sysctl` configuration is needed.

### Parameters set automatically

| Parameter | Value | Set by | When |
|-----------|-------|--------|------|
| `net.ipv4.ip_forward` | `1` | Deployer (`sysctl -w`) | Before starting containers |
| `net.ipv4.conf.all.src_valid_mark` | `1` | Deployer (`sysctl -w`) | Before starting containers |
| `net.ipv4.ip_forward` | `1` | forwarding-install.py | VM-B setup (exit node) |
| `net.ipv4.ip_forward` | `1` | wg-exit-node PostUp | Exit-node tunnel up |

### How it works

**On VM-A (main VPN node):**

The deployer sets `net.ipv4.ip_forward=1` and `net.ipv4.conf.all.src_valid_mark=1` on the host via `sysctl -w` before starting containers. These are required because AmneziaWG and Tailscale run with `network_mode: host` — Docker does not allow setting sysctls via the `sysctls:` directive on host-network containers. The parameters are set each time the deployer runs; they persist until reboot (the containers re-apply them on restart via their own startup hooks).

**On VM-B (exit node via forwarding script):**

The generated `forwarding-install.py` script calls `sysctl -w net.ipv4.ip_forward=1` during setup. This enables IP forwarding so that traffic received through the tunnel can be routed to the internet. The setting is applied at runtime; to persist across reboots, the forwarding script also configures the tunnel via `wg-quick` or systemd, which re-applies the sysctl on interface up (via `PostUp` hooks).

**On exit-node role (dual-role VM):**

The generated `wg-exit-node.conf` includes a `PostUp = sysctl -w net.ipv4.ip_forward=1` directive that enables forwarding each time the exit-node WireGuard interface comes up.

### Verifying kernel parameters

```bash
# Check IP forwarding is enabled
sysctl net.ipv4.ip_forward
# Expected: net.ipv4.ip_forward = 1

# Check src_valid_mark (needed for WireGuard routing)
sysctl net.ipv4.conf.all.src_valid_mark
# Expected: net.ipv4.conf.all.src_valid_mark = 1
```

### Manual override

If you need to disable IP forwarding after stopping VPN007 (e.g., during decommissioning):

```bash
sysctl -w net.ipv4.ip_forward=0
```

This takes effect immediately. The setting reverts to the system default on next reboot (typically `0` unless configured in `/etc/sysctl.conf`).

## CLI reference

```
$ vpn007 --help
usage: vpn007 [-h] [--version] [--env-file ENV_FILE] [--dry-run] [--debug]
              [--domain DOMAIN] [--reality-sni REALITY_SNI]
              [--cover-site-mode COVER_SITE_MODE] [--cover-site-url COVER_SITE_URL]
              [--cover-site-static-path COVER_SITE_STATIC_PATH]
              [--xui-path-prefix XUI_PATH_PREFIX]
              [--awg-panel-path-prefix AWG_PANEL_PATH_PREFIX]
              [--enable-port-8443 ENABLE_PORT_8443]
              [--xray-internal-port XRAY_INTERNAL_PORT]
              [--awg-listen-port AWG_LISTEN_PORT] [--awg-panel-port AWG_PANEL_PORT]
              [--tailscale-auth-key TAILSCALE_AUTH_KEY]
              [--tailscale-hostname TAILSCALE_HOSTNAME]
              [--tailscale-extra-args TAILSCALE_EXTRA_ARGS]
              [--incoming-ip INCOMING_IP] [--outgoing-ip OUTGOING_IP]
              [--public-ipv4 PUBLIC_IPV4] [--public-ipv6 PUBLIC_IPV6]
              [--tls-versions TLS_VERSIONS] [--skip-certbot] [--https-port HTTPS_PORT]
              [--approved-ips APPROVED_IPS] [--approved-hostnames APPROVED_HOSTNAMES]
              [--ssh-approved-ips SSH_APPROVED_IPS]
              [--ssh-approved-hostnames SSH_APPROVED_HOSTNAMES]
              [--hostname-resolve-interval-min HOSTNAME_RESOLVE_INTERVAL_MIN]
              [--blocked-as-numbers BLOCKED_AS_NUMBERS]
              [--blocked-subnets BLOCKED_SUBNETS]
              [--blocklist-update-interval-hours BLOCKLIST_UPDATE_INTERVAL_HOURS]
              [--forwarding-enabled FORWARDING_ENABLED] [--tunnel-type TUNNEL_TYPE]
              [--secondary-vm-ip SECONDARY_VM_IP]
              [--reverse-initiated REVERSE_INITIATED]
              [--forwarding-ports FORWARDING_PORTS]
              [--reconnect-initial-delay-sec RECONNECT_INITIAL_DELAY_SEC]
              [--reconnect-max-delay-sec RECONNECT_MAX_DELAY_SEC]
              [--tunnel-subnet TUNNEL_SUBNET]
              [--exit-node-enabled EXIT_NODE_ENABLED]
              [--exit-node-tunnel-type EXIT_NODE_TUNNEL_TYPE]
              [--exit-node-peer-ip EXIT_NODE_PEER_IP]
              [--exit-node-tunnel-subnet EXIT_NODE_TUNNEL_SUBNET]
              [--exit-node-listen-port EXIT_NODE_LISTEN_PORT]
              [--exit-node-reverse-initiated EXIT_NODE_REVERSE_INITIATED]
              [--xray-initial-client XRAY_INITIAL_CLIENT]
              [--awg-initial-peer AWG_INITIAL_PEER]
              [--output-dir OUTPUT_DIR] [--deployment-log-path DEPLOYMENT_LOG_PATH]

CLI deployer for multiple anti-censorship VPN services on a single Linux VM.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --env-file ENV_FILE   Path to the .env configuration file (default: .env)
  --dry-run             Generate configuration files without deploying
  --debug               Enable verbose debug logging

See the full parameter reference above for all flags and their corresponding
environment variables.
```

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

## Uninstalling VPN007

To completely remove VPN007 from a server, use the cleanup script:

```bash
# Full cleanup (removes everything including client configs)
sudo /opt/vpn007/scripts/cleanup.sh

# Or keep client configs and certificates
sudo /opt/vpn007/scripts/cleanup.sh --keep-data
```

The cleanup script handles:
- Stopping and removing all Docker containers, networks, and images
- Removing nftables firewall rules (restores accept-all policy)
- Disabling and removing systemd timers/services
- Unloading the AmneziaWG kernel module
- Resetting kernel parameters
- Removing the deployment directory (unless `--keep-data`)
- Restarting the Docker daemon

**Manual cleanup** (if the script is unavailable):

```bash
cd /opt/vpn007

# 1. Stop and remove all containers and networks
docker compose down --volumes --remove-orphans

# 2. Remove Docker images (optional — frees disk space)
docker compose down --rmi all

# 3. Remove systemd timers and services
systemctl disable --now blocklist-updater.timer hostname-resolver.timer certbot-renew.timer
rm -f /etc/systemd/system/blocklist-updater.{service,timer}
rm -f /etc/systemd/system/hostname-resolver.{service,timer}
rm -f /etc/systemd/system/certbot-renew.{service,timer}
systemctl daemon-reload

# 4. Remove nftables rules (restores default policy)
nft flush ruleset
# Or restore your pre-VPN007 nftables config if you have one:
# nft -f /etc/nftables.conf.backup

# 5. Remove the firewall management script
rm -f /usr/local/bin/vpn007-fw

# 6. Remove WireGuard tunnel interfaces (if forwarding was used)
wg-quick down wg-tunnel 2>/dev/null
wg-quick down wg-exit-node 2>/dev/null
rm -f /etc/wireguard/wg-tunnel.conf /etc/wireguard/wg-exit-node.conf

# 7. Remove the deployment directory
rm -rf /opt/vpn007

# 8. (Optional) Remove swap if it was auto-provisioned
swapoff /swapfile
rm -f /swapfile
sed -i '/\/swapfile/d' /etc/fstab

# 9. (Optional) Remove Docker entirely
apt purge docker-ce docker-ce-cli containerd.io docker-compose-plugin
rm -rf /var/lib/docker
```

After uninstalling, verify:
- `docker ps` shows no VPN007 containers
- `nft list ruleset` shows no VPN007 tables
- `systemctl list-timers` shows no VPN007 timers
- Port 443 and the AmneziaWG UDP port are no longer listening

## Rollback

If a re-deployment breaks your setup, you can roll back to the previous working configuration.

### Quick rollback (from backup)

```bash
cd /opt/vpn007

# Stop broken services
docker compose down

# Restore from your most recent backup
tar xzf /root/vpn007-backup-YYYYMMDD-HHMMSS.tar.gz

# Restart with the restored config
docker compose up -d
nft -f nftables.conf
```

### Rollback without a backup

If you don't have a backup but the previous config was committed to git:

```bash
cd /path/to/vpn007

# Check what changed in the last deploy
git diff HEAD -- src/vpn007/templates/

# Revert to the previous version
git checkout HEAD~1

# Regenerate configs with the old version
pip install -e .
vpn007 --dry-run --output-dir /opt/vpn007

# Apply on the server
cd /opt/vpn007
docker compose up -d
nft -f nftables.conf
```

### Partial rollback (single component)

If only one service is broken, you can restore just that component:

```bash
# Restore only Nginx config from backup
tar xzf /root/vpn007-backup-YYYYMMDD-HHMMSS.tar.gz deploy/nginx/
docker compose restart reverse_proxy

# Restore only nftables rules
tar xzf /root/vpn007-backup-YYYYMMDD-HHMMSS.tar.gz deploy/nftables.conf
nft -f nftables.conf

# Restore only the 3x-ui database (client configs)
docker compose stop three_x_ui
tar xzf /root/vpn007-backup-YYYYMMDD-HHMMSS.tar.gz deploy/data/three_x_ui/
docker compose start three_x_ui
```

### Prevention

To make rollbacks easier, always back up before re-deploying:

```bash
tar czf /root/vpn007-backup-$(date +%Y%m%d-%H%M%S).tar.gz \
    .env data/ nftables.conf docker-compose.yml nginx/ xray/ systemd/ scripts/
```

## Container resource limits

The generated `docker-compose.yml` includes memory limits for each container to prevent any single service from exhausting host RAM (especially important on 1-2 GB VMs):

| Container | Memory limit | Memory reservation |
|-----------|-------------|-------------------|
| `vpn007_reverse_proxy` | 128 MB | 32 MB |
| `vpn007_three_x_ui` | 256 MB | 64 MB |
| `vpn007_amneziawg` | 128 MB | 32 MB |
| `vpn007_tailscale` | 128 MB | 32 MB |
| `vpn007_cover_site` | 64 MB | 16 MB |
| `vpn007_certbot` | 128 MB | 32 MB |

These limits are set via `deploy_resources` in the Compose file:

```yaml
services:
  reverse_proxy:
    deploy:
      resources:
        limits:
          memory: 128M
        reservations:
          memory: 32M
```

If a container exceeds its memory limit, Docker's OOM killer terminates it and the `restart: unless-stopped` policy brings it back. Monitor OOM events with:

```bash
docker events --filter event=oom --since 24h
journalctl -k | grep -i "out of memory"
```

For high-traffic deployments (many concurrent clients), increase the limits for `three_x_ui` and `amneziawg` in `docker-compose.yml`:

```bash
# Edit the generated file directly on the server
vim /opt/vpn007/docker-compose.yml
docker compose up -d  # Recreates containers with new limits
```

## Docker network isolation

All bridge-mode containers (`reverse_proxy`, `three_x_ui`, `cover_site`) communicate over an internal Docker bridge network (`vpn_net`). This network is intentionally isolated:

- **No inter-container access to host network**: Bridge containers cannot reach host-only services (e.g., SSH on port 22) unless explicitly published.
- **Internal DNS resolution**: Containers reference each other by service name (e.g., `three_x_ui:2053`) — no host ports are exposed for internal-only services.
- **Host-network containers** (`amneziawg`, `tailscale`) use `network_mode: host` because they require direct access to network interfaces for tunnel creation. These containers can reach all host ports and all bridge containers.

### Network security implications

| Container | Network mode | Can reach host ports | Can reach internet | Can reach other containers |
|-----------|-------------|---------------------|-------------------|---------------------------|
| reverse_proxy | bridge (vpn_net) | No | Yes (for proxy mode) | Yes (vpn_net only) |
| three_x_ui | bridge (vpn_net) | No | Yes (Xray outbound) | Yes (vpn_net only) |
| cover_site | bridge (vpn_net) | No | No | Yes (vpn_net only) |
| amneziawg | host | Yes | Yes | Yes (all) |
| tailscale | host | Yes | Yes | Yes (all) |
| certbot | bridge (vpn_net) | No | Yes (ACME) | No (run-once utility) |

### Hardening recommendations

For additional network isolation beyond the defaults:

1. **Disable ICC (inter-container communication)** if you don't need containers to talk to each other directly. Note: this breaks the reverse proxy → backend routing, so only use if you restructure with explicit links.

2. **Use Docker's `internal` network option** for the cover site if it serves only static files:
   ```yaml
   networks:
     vpn_net:
       internal: false  # default — allows internet access
     cover_net:
       internal: true   # no internet access for cover_site
   ```

3. **Drop capabilities** for containers that don't need them (already applied in the generated Compose file):
   ```yaml
   cap_drop:
     - ALL
   cap_add:
     - NET_BIND_SERVICE  # only for reverse_proxy (port 443)
   ```

## Web panel rate limiting

When `APPROVED_IPS` is configured, unauthorized connections are rejected at the Nginx level before reaching the panel. However, if IP-based access control is not feasible (e.g., operators with unpredictable IPs who cannot use DDNS), the panels are additionally protected by Nginx rate limiting:

- **Login endpoints**: 5 requests per minute per source IP (burst of 3)
- **API endpoints**: 30 requests per minute per source IP (burst of 10)
- **Static assets**: No rate limit

Rate limiting is enforced via `limit_req_zone` in the generated Nginx config:

```nginx
# Generated in nginx/http.conf
limit_req_zone $binary_remote_addr zone=panel_login:1m rate=5r/m;
limit_req_zone $binary_remote_addr zone=panel_api:1m rate=30r/m;

location ~ ^/secretpanel-.*/login {
    limit_req zone=panel_login burst=3 nodelay;
    ...
}
```

Requests exceeding the rate limit receive HTTP 429 (Too Many Requests). Combined with the random admin credentials and secret URL paths, this provides defense-in-depth against brute-force attacks even without IP allowlisting.

For maximum security, use IP-based access control (`APPROVED_IPS`) whenever possible — it is strictly superior to rate limiting because unauthorized traffic never reaches the application layer.

## Security hardening (AppArmor)

Docker applies default AppArmor profiles to all containers on Debian/Ubuntu systems. These profiles restrict containers from:
- Writing to `/proc` and `/sys` (except allowed paths)
- Mounting filesystems
- Accessing raw network sockets (unless `NET_RAW` capability is granted)
- Loading kernel modules

### VPN007-specific considerations

The default Docker AppArmor profile (`docker-default`) is sufficient for most VPN007 containers. Exceptions:

| Container | Additional requirements | Notes |
|-----------|------------------------|-------|
| `amneziawg` | `NET_ADMIN`, `NET_RAW` capabilities + host network | Required for WireGuard interface creation; runs with `--privileged` or explicit caps |
| `tailscale` | `NET_ADMIN`, `NET_RAW` + `/dev/net/tun` access | Required for tunnel interface; uses host network |
| `reverse_proxy` | `NET_BIND_SERVICE` | Bind to ports <1024 (443) |
| `three_x_ui` | None beyond defaults | Xray uses userspace networking |
| `cover_site` | None beyond defaults | Static file serving only |

### Verifying AppArmor status

```bash
# Check AppArmor is active
aa-status

# Verify Docker containers are confined
docker inspect --format='{{.AppArmorProfile}}' vpn007_reverse_proxy
# Expected: "docker-default"

# Containers with host network mode may show "unconfined" — this is expected
# for amneziawg and tailscale which need direct network access
docker inspect --format='{{.AppArmorProfile}}' vpn007_amneziawg
```

### Custom AppArmor profile (optional)

For environments requiring stricter confinement, you can create a custom AppArmor profile for the reverse proxy that additionally restricts file writes:

```bash
# /etc/apparmor.d/docker-vpn007-nginx
#include <tunables/global>

profile docker-vpn007-nginx flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  network inet stream,
  network inet6 stream,

  /etc/nginx/** r,
  /var/log/nginx/** w,
  /var/cache/nginx/** rw,
  /run/nginx.pid rw,
  /tmp/** rw,

  deny /proc/** w,
  deny /sys/** w,
}
```

Load and apply:

```bash
apparmor_parser -r /etc/apparmor.d/docker-vpn007-nginx
# Then in docker-compose.yml, add:
# security_opt:
#   - apparmor=docker-vpn007-nginx
```

For most deployments, the default Docker AppArmor profile provides adequate confinement. Custom profiles are recommended only for high-security environments or compliance requirements.

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
