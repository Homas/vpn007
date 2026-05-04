# VPN007

A Python CLI tool that deploys multiple anti-censorship VPN services on a single Linux VM using Docker Compose.

VPN007 generates all the configuration files needed to run Xray (VLESS+Reality), AmneziaWG 2.0, and Tailscale behind an Nginx reverse proxy with a legitimate cover website. Traffic is routed through standard HTTPS ports (443/tcp) using a two-layer architecture: Layer 4 SNI-based routing sends Reality traffic directly to Xray, while everything else goes through Layer 7 path-based routing with TLS termination.

The tool also provisions an nftables firewall with AS/subnet blocking, sets up systemd timers for blocklist updates and hostname resolution, manages TLS certificates via Let's Encrypt, and can generate forwarding scripts for multi-VM relay architectures.

## Features

- **Xray VLESS+Reality** — VPN traffic indistinguishable from legitimate TLS 1.3 connections
- **AmneziaWG 2.0** — WireGuard with full obfuscation parameter set (S1-S4, H1-H4, I1-I5) for DPI resistance
- **Tailscale** — Mesh overlay network for secure management
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
| Python | 3.14+ | VPN007 runtime |
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

## Installation

```bash
# Clone the repository
git clone https://github.com/Homas/vpn007.git
cd vpn007

# Create a virtual environment
python3.14 -m venv .venv
source .venv/bin/activate

# Install the package
pip install -e .

# (Optional) Install dev dependencies for testing
pip install -e ".[dev]"
```

## Quick start

```bash
# Copy and edit the sample environment file
cp .env.sample .env
# Edit .env with your domain, IPs, and preferences

# Run the deployer (dry-run to preview generated files)
vpn007 --dry-run

# Run the full deployment
sudo vpn007
```

The deployer will:

1. Validate the host OS and install missing dependencies
2. Generate all configuration files in `./deploy/`
3. Start Docker containers (Nginx, 3x-ui/Xray, AmneziaWG, Tailscale, cover site)
4. Acquire a TLS certificate via Let's Encrypt
5. Apply nftables firewall rules
6. Install systemd timers for blocklist updates, hostname resolution, and cert renewal
7. Provision initial VPN clients and output a post-install summary

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
