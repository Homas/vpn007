# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Data models for VPN007 deployment configuration and results."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class TunnelType(Enum):
    """Supported tunnel types for inter-VM encrypted forwarding."""

    WIREGUARD = "wireguard"
    SSH = "ssh"
    TAILSCALE = "tailscale"


class CoverSiteMode(Enum):
    """Cover site serving mode."""

    STATIC = "static"  # Serve local static files
    PROXY = "proxy"  # Reverse proxy to external site


@dataclass
class AwgObfuscation:
    """AmneziaWG 2.0 obfuscation parameters."""

    # Packet size parameters (must match between server and clients)
    s1: int  # Init packet magic header (15-150)
    s2: int  # Response packet magic header (15-150)
    s3: int  # Init packet junk size (15-150, added in 2.0)
    s4: int  # Response packet junk size (15-150, added in 2.0)
    h1: int  # Header transform param 1 (5-2147483647)
    h2: int  # Header transform param 2 (5-2147483647)
    h3: int  # Header transform param 3 (5-2147483647)
    h4: int  # Header transform param 4 (5-2147483647)
    # Junk packet parameters (can differ between server and clients)
    jc: int = 4  # Junk packet count (1-128)
    jmin: int = 50  # Min junk packet size (1-1280)
    jmax: int = 1000  # Max junk packet size (1-1280, Jmin <= Jmax)
    # Init packet junk sizes (added in 2.0, can differ between server and clients)
    i1: int = 0  # Init packet junk size 1
    i2: int = 0  # Init packet junk size 2
    i3: int = 0  # Init packet junk size 3
    i4: int = 0  # Init packet junk size 4
    i5: int = 0  # Init packet junk size 5


@dataclass
class PortForward:
    """A single port forwarding rule for inter-VM traffic."""

    protocol: str  # "tcp" or "udp"
    listen_port: int  # Port on primary VM
    forward_port: int  # Port on secondary VM
    description: str = ""


@dataclass
class RealityKeys:
    """Xray Reality key pair."""

    private_key: str
    public_key: str
    short_id: str  # 8-char hex


@dataclass
class XrayClientConfig:
    """Generated Xray VLESS+Reality client configuration."""

    client_name: str
    uuid: str
    vless_share_link: str  # vless://... URI for client import
    qr_code_data: str  # Data string for QR code generation
    reality_public_key: str
    short_id: str
    sni: str
    server_address: str
    server_port: int


@dataclass
class AwgPeerConfig:
    """Generated AmneziaWG peer configuration."""

    peer_name: str
    private_key: str
    public_key: str
    preshared_key: str | None
    allowed_ips: str
    endpoint: str
    conf_content: str  # Full .conf file content for client import


@dataclass
class TunnelConfig:
    """Configuration for an encrypted inter-VM tunnel."""

    tunnel_type: TunnelType
    primary_ip: str
    secondary_ip: str
    reverse_initiated: bool
    # WireGuard/AmneziaWG specific
    wg_private_key: str | None = None
    wg_public_key: str | None = None
    wg_peer_public_key: str | None = None
    wg_listen_port: int = 51821
    wg_tunnel_subnet: str = "10.99.0.0/30"
    # SSH specific
    ssh_key_path: str | None = None
    ssh_port: int = 22
    autossh_monitor_port: int = 20000
    # Tailscale specific
    tailscale_primary_hostname: str | None = None
    tailscale_secondary_hostname: str | None = None
    # Reconnection
    reconnect_initial_delay: int = 5
    reconnect_max_delay: int = 300


@dataclass
class DeployConfig:
    """Complete validated deployment configuration."""

    # General
    domain: str
    reality_sni: str = "www.microsoft.com"
    cover_site_mode: CoverSiteMode = CoverSiteMode.STATIC
    cover_site_url: str | None = None
    cover_site_static_path: Path | None = None

    # Routing paths
    xui_path_prefix: str = "/secretpanel"
    awg_panel_path_prefix: str = "/awgadmin"
    enable_port_8443: bool = False

    # Xray / Reality
    xray_internal_port: int = 10443
    reality_keys: RealityKeys | None = None

    # AmneziaWG
    awg_listen_port: int | None = None
    awg_obfuscation: AwgObfuscation | None = None
    awg_panel_port: int = 51821
    use_custom_awg_image: bool = False  # Fallback: build from Dockerfile.amneziawg

    # Tailscale
    tailscale_auth_key: str | None = None

    # Multi-IP
    incoming_ip: str | None = None
    outgoing_ip: str | None = None
    public_ipv4: str | None = None
    public_ipv6: str | None = None

    # TLS configuration
    tls_versions: list[str] = field(default_factory=lambda: ["1.2", "1.3"])

    # Access control
    approved_ips: list[str] = field(default_factory=list)
    approved_hostnames: list[str] = field(default_factory=list)
    ssh_approved_ips: list[str] = field(default_factory=list)
    hostname_resolve_interval_min: int = 30

    # AS/Subnet blocking
    blocked_as_numbers: list[str] = field(default_factory=list)
    blocked_subnets: list[str] = field(default_factory=list)
    blocklist_update_interval_hours: int = 6

    # Forwarding
    forwarding_enabled: bool = False
    tunnel_type: TunnelType | None = None
    secondary_vm_ip: str | None = None
    reverse_initiated: bool = False
    forwarding_ports: list[PortForward] = field(default_factory=list)
    reconnect_initial_delay_sec: int = 5
    reconnect_max_delay_sec: int = 300

    # Output
    output_dir: Path = Path("./deploy")
    deployment_log_path: Path = Path("./deploy/deploy.log")


class DeployError(Exception):
    """Base error with context for structured logging."""

    def __init__(
        self,
        service: str,
        step: str,
        message: str,
        remediation: str | None = None,
    ):
        self.service = service
        self.step = step
        self.message = message
        self.remediation = remediation
        super().__init__(f"[{service}] {step}: {message}")


@dataclass
class ServiceResult:
    """Result of deploying a single service."""

    success: bool
    error: DeployError | None = None


@dataclass
class DeployResult:
    """Result of the full deployment."""

    services: dict[str, ServiceResult] = field(default_factory=dict)
