# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""CLI argument parser for VPN007 deployer."""

from __future__ import annotations

import argparse

import vpn007


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments and return an :class:`argparse.Namespace`.

    Parameters
    ----------
    argv:
        Argument list to parse.  Defaults to ``sys.argv[1:]`` when *None*.

    Returns
    -------
    argparse.Namespace
        Parsed arguments with field names in snake_case matching
        :class:`~vpn007.models.DeployConfig` fields.
    """
    parser = argparse.ArgumentParser(
        prog="vpn007",
        description=(
            "CLI deployer for multiple anti-censorship VPN services on a single Linux VM."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {vpn007.__version__}",
    )

    # -- Meta / operational flags ------------------------------------------
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the .env configuration file (default: .env)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=None,
        help="Generate configuration files without deploying",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=None,
        help="Enable verbose debug logging",
    )

    # -- General -----------------------------------------------------------
    general = parser.add_argument_group("general")
    general.add_argument("--domain", default=None, help="Primary domain name")
    general.add_argument(
        "--reality-sni",
        default=None,
        help="SNI target for Xray Reality (default: www.microsoft.com)",
    )
    general.add_argument(
        "--cover-site-mode",
        default=None,
        help="Cover site mode: 'static' or 'proxy'",
    )
    general.add_argument(
        "--cover-site-url",
        default=None,
        help="URL to proxy when cover-site-mode is 'proxy'",
    )
    general.add_argument(
        "--cover-site-static-path",
        default=None,
        help="Path to static files when cover-site-mode is 'static'",
    )

    # -- Routing -----------------------------------------------------------
    routing = parser.add_argument_group("routing")
    routing.add_argument(
        "--xui-path-prefix",
        default=None,
        help="URL path prefix for 3x-ui panel (default: /secretpanel)",
    )
    routing.add_argument(
        "--awg-panel-path-prefix",
        default=None,
        help="URL path prefix for AmneziaWG panel (default: /awgadmin)",
    )
    routing.add_argument(
        "--enable-port-8443",
        default=None,
        help="Enable secondary HTTPS port 8443 (true/false)",
    )

    # -- Xray --------------------------------------------------------------
    xray = parser.add_argument_group("xray")
    xray.add_argument(
        "--xray-internal-port",
        type=int,
        default=None,
        help="Internal port for Xray (default: 10443)",
    )

    # -- AmneziaWG ---------------------------------------------------------
    awg = parser.add_argument_group("amneziawg")
    awg.add_argument(
        "--awg-listen-port",
        type=int,
        default=None,
        help="AmneziaWG UDP listen port (default: random 10000-65535)",
    )
    awg.add_argument(
        "--awg-panel-port",
        type=int,
        default=None,
        help="AmneziaWG panel port (default: 51821)",
    )

    # -- Tailscale ---------------------------------------------------------
    ts = parser.add_argument_group("tailscale")
    ts.add_argument(
        "--tailscale-auth-key",
        default=None,
        help="Tailscale auth key for automatic node registration",
    )
    ts.add_argument(
        "--tailscale-hostname",
        default=None,
        help="Hostname for this node in the tailnet",
    )
    ts.add_argument(
        "--tailscale-extra-args",
        default=None,
        help="Extra arguments for Tailscale daemon (default: --advertise-exit-node)",
    )

    # -- Multi-IP ----------------------------------------------------------
    ip = parser.add_argument_group("multi-ip")
    ip.add_argument(
        "--incoming-ip",
        default=None,
        help="IP address for incoming connections (bind address)",
    )
    ip.add_argument(
        "--outgoing-ip",
        default=None,
        help="IP address for outgoing connections (SNAT)",
    )
    ip.add_argument(
        "--public-ipv4",
        default=None,
        help="Public IPv4 address (auto-detected if omitted)",
    )
    ip.add_argument(
        "--public-ipv6",
        default=None,
        help="Public IPv6 address (auto-detected if omitted)",
    )

    # -- TLS ---------------------------------------------------------------
    tls = parser.add_argument_group("tls")
    tls.add_argument(
        "--tls-versions",
        default=None,
        help="Comma-separated TLS versions to accept (default: 1.2,1.3)",
    )
    tls.add_argument(
        "--skip-certbot",
        action="store_true",
        default=None,
        help="Skip Let's Encrypt certificate acquisition; keep self-signed cert",
    )
    tls.add_argument(
        "--https-port",
        type=int,
        default=None,
        help="Main HTTPS listen port (default: 443). Use a non-standard port for lab/staging",
    )

    # -- Access control ----------------------------------------------------
    acl = parser.add_argument_group("access control")
    acl.add_argument(
        "--approved-ips",
        default=None,
        help="Comma-separated list of approved IPs/CIDRs for panel access",
    )
    acl.add_argument(
        "--approved-hostnames",
        default=None,
        help="Comma-separated list of hostnames for panel access",
    )
    acl.add_argument(
        "--ssh-approved-ips",
        default=None,
        help="Comma-separated list of approved IPs/CIDRs for SSH access",
    )
    acl.add_argument(
        "--ssh-approved-hostnames",
        default=None,
        help="Comma-separated list of hostnames for SSH access (resolved periodically)",
    )
    acl.add_argument(
        "--hostname-resolve-interval-min",
        type=int,
        default=None,
        help="Hostname resolution interval in minutes (default: 30)",
    )

    # -- Blocking ----------------------------------------------------------
    block = parser.add_argument_group("blocking")
    block.add_argument(
        "--blocked-as-numbers",
        default=None,
        help="Comma-separated AS numbers to block (e.g. AS196747,AS61280,AS213853,AS196641)",
    )
    block.add_argument(
        "--blocked-subnets",
        default=None,
        help="Comma-separated CIDR subnets to block",
    )
    block.add_argument(
        "--blocklist-update-interval-hours",
        type=int,
        default=None,
        help="Blocklist update interval in hours (default: 6)",
    )

    # -- Forwarding --------------------------------------------------------
    fwd = parser.add_argument_group("forwarding")
    fwd.add_argument(
        "--forwarding-enabled",
        default=None,
        help="Enable inter-VM forwarding (true/false)",
    )
    fwd.add_argument(
        "--forwarding-mode",
        default=None,
        help="Forwarding mode: 'ports' (forward specific ports via DNAT) or 'all' (route all VPN client traffic through tunnel)",
    )
    fwd.add_argument(
        "--tunnel-type",
        default=None,
        help="Tunnel type: wireguard, ssh, or tailscale",
    )
    fwd.add_argument(
        "--secondary-vm-ip",
        default=None,
        help="IP address of the secondary VM",
    )
    fwd.add_argument(
        "--reverse-initiated",
        default=None,
        help="Enable reverse-initiated connections (true/false)",
    )
    fwd.add_argument(
        "--forwarding-ports",
        default=None,
        help=(
            "Comma-separated port forwards "
            "(format: protocol:listen_port:forward_port[:description])"
        ),
    )
    fwd.add_argument(
        "--reconnect-initial-delay-sec",
        type=int,
        default=None,
        help="Initial reconnection delay in seconds (default: 5)",
    )
    fwd.add_argument(
        "--reconnect-max-delay-sec",
        type=int,
        default=None,
        help="Maximum reconnection delay in seconds (default: 300)",
    )
    fwd.add_argument(
        "--tunnel-subnet",
        default=None,
        help="Tunnel subnet for inter-VM WireGuard link (default: 10.99.0.0/30)",
    )
    fwd.add_argument(
        "--tunnel-xray-sni",
        default=None,
        help="SNI target for inter-node VLESS+Reality tunnel (default: same as --reality-sni)",
    )
    fwd.add_argument(
        "--tunnel-xray-port",
        type=int,
        default=None,
        help="Port on exit node for VLESS+Reality tunnel (default: 443)",
    )

    # -- Exit node role ----------------------------------------------------
    exit_node = parser.add_argument_group("exit node role")
    exit_node.add_argument(
        "--exit-node-enabled",
        default=None,
        help="Enable exit node role: accept forwarded traffic from another node (true/false)",
    )
    exit_node.add_argument(
        "--exit-node-tunnel-type",
        default=None,
        help="Tunnel type for exit node role: wireguard, ssh, tailscale, or xray",
    )
    exit_node.add_argument(
        "--exit-node-peer-ip",
        default=None,
        help="IP of the peer VM that forwards traffic to this exit node",
    )
    exit_node.add_argument(
        "--exit-node-tunnel-subnet",
        default=None,
        help="Tunnel subnet for exit node role (default: 10.99.1.0/30)",
    )
    exit_node.add_argument(
        "--exit-node-listen-port",
        type=int,
        default=None,
        help="WireGuard listen port for exit node tunnel (default: 51822)",
    )
    exit_node.add_argument(
        "--exit-node-reverse-initiated",
        default=None,
        help="Peer VM initiates the tunnel connection to this exit node (true/false)",
    )

    # -- Output ------------------------------------------------------------
    output = parser.add_argument_group("output")
    output.add_argument(
        "--xray-initial-client",
        default=None,
        help="Name for the initial Xray VLESS+Reality client (default: default-client)",
    )
    output.add_argument(
        "--awg-initial-peer",
        default=None,
        help="Name for the initial AmneziaWG peer (default: default-peer)",
    )
    output.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for generated files (default: ./deploy)",
    )
    output.add_argument(
        "--deployment-log-path",
        default=None,
        help="Path for the deployment log file (default: ./deploy/deploy.log)",
    )

    return parser.parse_args(argv)
