# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Unit tests for vpn007.docs — Documentation generation."""

from __future__ import annotations

from vpn007.docs import generate_docs
from vpn007.models import (
    AwgObfuscation,
    CoverSiteMode,
    DeployConfig,
    PortForward,
    TunnelType,
)


class TestGenerateDocs:
    """Unit tests for the generate_docs function."""

    def test_returns_three_files(self, valid_config: DeployConfig) -> None:
        """generate_docs returns exactly three documentation files."""
        docs = generate_docs(valid_config)
        assert set(docs.keys()) == {"README.md", "troubleshooting.md", "client-guides.md"}

    def test_all_values_are_non_empty_strings(self, valid_config: DeployConfig) -> None:
        """All generated documents are non-empty strings."""
        docs = generate_docs(valid_config)
        for filename, content in docs.items():
            assert isinstance(content, str), f"{filename} is not a string"
            assert len(content) > 0, f"{filename} is empty"

    def test_readme_contains_copyright(self, valid_config: DeployConfig) -> None:
        """README.md includes the required copyright notice."""
        docs = generate_docs(valid_config)
        assert "© Vadim Pavlov 2026" in docs["README.md"]

    def test_troubleshooting_contains_copyright(self, valid_config: DeployConfig) -> None:
        """troubleshooting.md includes the required copyright notice."""
        docs = generate_docs(valid_config)
        assert "© Vadim Pavlov 2026" in docs["troubleshooting.md"]

    def test_client_guides_contains_copyright(self, valid_config: DeployConfig) -> None:
        """client-guides.md includes the required copyright notice."""
        docs = generate_docs(valid_config)
        assert "© Vadim Pavlov 2026" in docs["client-guides.md"]

    def test_readme_contains_architecture_overview(self, valid_config: DeployConfig) -> None:
        """README.md includes the architecture overview section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Architecture Overview" in readme
        assert "Two-Layer Routing" in readme

    def test_readme_contains_all_services(self, valid_config: DeployConfig) -> None:
        """README.md references all 5 deployed services."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Reverse Proxy" in readme
        assert "Xray" in readme or "VLESS+Reality" in readme
        assert "3x-ui" in readme
        assert "AmneziaWG" in readme
        assert "Tailscale" in readme
        assert "Cover Site" in readme

    def test_readme_contains_hardware_requirements(self, valid_config: DeployConfig) -> None:
        """README.md includes hardware requirements with min and recommended specs."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Hardware Requirements" in readme
        assert "1 vCPU" in readme
        assert "2 GB" in readme
        assert "15 GB" in readme
        assert "2+ vCPU" in readme
        assert "4 GB" in readme
        assert "30 GB" in readme

    def test_readme_contains_supported_os(self, valid_config: DeployConfig) -> None:
        """README.md lists supported operating systems."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Debian" in readme and "11+" in readme
        assert "Ubuntu" in readme and "22.04+" in readme
        assert "Alpine" in readme and "3.18+" in readme

    def test_readme_contains_dependencies(self, valid_config: DeployConfig) -> None:
        """README.md lists all required dependencies."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Docker Engine" in readme
        assert "Docker Compose" in readme
        assert "Python" in readme and "3.12+" in readme
        assert "nftables" in readme
        assert "curl" in readme
        assert "git" in readme

    def test_readme_contains_tls_section(self, valid_config: DeployConfig) -> None:
        """README.md includes TLS configuration section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "TLS Configuration" in readme

    def test_readme_contains_firewall_section(self, valid_config: DeployConfig) -> None:
        """README.md includes firewall section with nftables overview."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Firewall" in readme
        assert "nftables" in readme

    def test_readme_contains_multi_ip_section(self, valid_config: DeployConfig) -> None:
        """README.md includes multi-IP configuration section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Multi-IP" in readme

    def test_readme_contains_forwarding_section(self, valid_config: DeployConfig) -> None:
        """README.md includes inter-VM forwarding section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Inter-VM Forwarding" in readme

    def test_readme_contains_certificate_section(self, valid_config: DeployConfig) -> None:
        """README.md includes certificate management section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Certificate Management" in readme

    def test_readme_contains_systemd_timers_section(self, valid_config: DeployConfig) -> None:
        """README.md includes systemd timers section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Systemd Timers" in readme

    def test_readme_contains_maintenance_section(self, valid_config: DeployConfig) -> None:
        """README.md includes maintenance section."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "Maintenance" in readme

    def test_readme_contains_sni_guidance(self, valid_config: DeployConfig) -> None:
        """README.md includes SNI selection guidance."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "SNI Selection Guidance" in readme

    def test_readme_contains_license_section(self, valid_config: DeployConfig) -> None:
        """README.md includes license section with GPL-3.0 and component licenses."""
        docs = generate_docs(valid_config)
        readme = docs["README.md"]
        assert "License" in readme
        assert "GPL-3.0" in readme
        assert "© Vadim Pavlov 2026" in readme
        assert "Xray-core" in readme and "MPL-2.0" in readme
        assert "3x-ui" in readme and "GPL-3.0" in readme
        assert "AmneziaWG" in readme and "GPL-2.0" in readme
        assert "Tailscale" in readme and "BSD-3-Clause" in readme
        assert "WireGuard" in readme and "GPL-2.0" in readme

    def test_readme_renders_domain(self, valid_config: DeployConfig) -> None:
        """README.md renders the configured domain name."""
        docs = generate_docs(valid_config)
        assert valid_config.domain in docs["README.md"]

    def test_troubleshooting_contains_common_failures(
        self, valid_config: DeployConfig
    ) -> None:
        """troubleshooting.md covers common failure scenarios."""
        docs = generate_docs(valid_config)
        ts = docs["troubleshooting.md"]
        assert "Container Won't Start" in ts
        assert "TLS Certificate Errors" in ts
        assert "Panel Inaccessible" in ts
        assert "Kernel Module" in ts
        assert "Blocklist Updater" in ts

    def test_troubleshooting_contains_diagnostic_commands(
        self, valid_config: DeployConfig
    ) -> None:
        """troubleshooting.md includes diagnostic commands."""
        docs = generate_docs(valid_config)
        ts = docs["troubleshooting.md"]
        assert "docker compose logs" in ts
        assert "nft list ruleset" in ts
        assert "systemctl status" in ts
        assert "journalctl" in ts
        assert "curl" in ts
        assert "openssl s_client" in ts

    def test_troubleshooting_contains_dpi_notes(
        self, valid_config: DeployConfig
    ) -> None:
        """troubleshooting.md includes TSPU/DPI evasion notes."""
        docs = generate_docs(valid_config)
        ts = docs["troubleshooting.md"]
        assert "TSPU" in ts or "DPI" in ts
        assert "ECH" in ts or "ESNI" in ts
        assert "TLS 1.3" in ts
        assert "15-20" in ts or "15–20" in ts  # throttling threshold

    def test_troubleshooting_contains_awg_issues(
        self, valid_config: DeployConfig
    ) -> None:
        """troubleshooting.md covers AmneziaWG-specific issues."""
        docs = generate_docs(valid_config)
        ts = docs["troubleshooting.md"]
        assert "AmneziaWG" in ts
        assert "kernel module" in ts.lower() or "Kernel Module" in ts
        assert "amneziawg-go" in ts

    def test_troubleshooting_contains_forwarding_section(
        self, valid_config: DeployConfig
    ) -> None:
        """troubleshooting.md covers forwarding troubleshooting."""
        docs = generate_docs(valid_config)
        ts = docs["troubleshooting.md"]
        assert "Forwarding" in ts

    def test_client_guides_contains_vless_reality(
        self, valid_config: DeployConfig
    ) -> None:
        """client-guides.md covers VLESS+Reality clients."""
        docs = generate_docs(valid_config)
        cg = docs["client-guides.md"]
        assert "VLESS" in cg
        assert "Reality" in cg
        assert "v2rayNG" in cg
        assert "v2rayN" in cg
        assert "Nekoray" in cg
        assert "Shadowrocket" in cg

    def test_client_guides_contains_amneziawg(
        self, valid_config: DeployConfig
    ) -> None:
        """client-guides.md covers AmneziaWG clients."""
        docs = generate_docs(valid_config)
        cg = docs["client-guides.md"]
        assert "AmneziaWG" in cg
        assert "AmneziaVPN" in cg
        assert ".conf" in cg

    def test_client_guides_contains_tailscale(
        self, valid_config: DeployConfig
    ) -> None:
        """client-guides.md covers Tailscale setup."""
        docs = generate_docs(valid_config)
        cg = docs["client-guides.md"]
        assert "Tailscale" in cg
        assert "tailnet" in cg
        assert "authorization" in cg.lower() or "authorize" in cg.lower()

    def test_docs_with_forwarding_enabled(
        self, valid_config_with_forwarding: DeployConfig
    ) -> None:
        """Docs render correctly when forwarding is enabled."""
        docs = generate_docs(valid_config_with_forwarding)
        readme = docs["README.md"]
        ts = docs["troubleshooting.md"]
        assert "enabled" in readme.lower()
        assert valid_config_with_forwarding.secondary_vm_ip in readme
        # Troubleshooting should include forwarding-specific content
        assert "Forwarding" in ts

    def test_docs_with_multi_ip(
        self, valid_config_with_multi_ip: DeployConfig
    ) -> None:
        """Docs render correctly with multi-IP configuration."""
        docs = generate_docs(valid_config_with_multi_ip)
        readme = docs["README.md"]
        assert valid_config_with_multi_ip.incoming_ip in readme
        assert valid_config_with_multi_ip.outgoing_ip in readme

    def test_docs_with_full_config(self, valid_config_full: DeployConfig) -> None:
        """Docs render correctly with all optional fields populated."""
        docs = generate_docs(valid_config_full)
        # All three docs should render without errors
        assert len(docs) == 3
        for filename, content in docs.items():
            assert len(content) > 100, f"{filename} seems too short"

    def test_readme_with_port_8443_enabled(self) -> None:
        """README.md mentions port 8443 when enabled."""
        config = DeployConfig(domain="vpn.example.com", enable_port_8443=True)
        docs = generate_docs(config)
        assert "8443" in docs["README.md"]

    def test_client_guides_renders_awg_obfuscation_params(self) -> None:
        """client-guides.md renders AmneziaWG obfuscation parameters when set."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_obfuscation=AwgObfuscation(
                s1=30, s2=80, s3=40, s4=100,
                h1=100, h2=200, h3=300, h4=400,
                jc=4, jmin=50, jmax=1000,
            ),
        )
        docs = generate_docs(config)
        cg = docs["client-guides.md"]
        # Should contain the parameter table
        assert "S1" in cg
        assert "S3" in cg
        assert "H1" in cg


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------
from hypothesis import given, settings

# Import the valid_deploy_config strategy from conftest
from tests.conftest import valid_deploy_config


class TestProperty13DocumentationCoversAllServices:
    """**Validates: Requirements 12.1, 12.2, 12.4, 12.5**

    Property 13: Documentation generation covers all services.

    For any valid DeployConfig, the generated documentation should reference
    all five deployed services with their ports and access methods, include
    client connection guides for VLESS+Reality, AmneziaWG, and Tailscale,
    and the deployment summary should list all service endpoints.
    """

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_readme_references_all_five_services(self, config: DeployConfig) -> None:
        """Property13: README.md references all 5 services
        (reverse_proxy, three_x_ui/Xray, amneziawg, tailscale, cover_site).
        """
        docs = generate_docs(config)
        readme = docs["README.md"]

        # Reverse Proxy service
        assert "Reverse Proxy" in readme, "README must reference the Reverse Proxy service"

        # Xray / 3x-ui service (three_x_ui container runs embedded Xray)
        assert "Xray" in readme or "VLESS+Reality" in readme, (
            "README must reference the Xray/VLESS+Reality service"
        )
        assert "3x-ui" in readme or "three_x_ui" in readme, (
            "README must reference the 3x-ui panel"
        )

        # AmneziaWG service
        assert "AmneziaWG" in readme, "README must reference the AmneziaWG service"

        # Tailscale service
        assert "Tailscale" in readme, "README must reference the Tailscale service"

        # Cover Site service
        assert "Cover Site" in readme or "cover_site" in readme, (
            "README must reference the Cover Site service"
        )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_readme_includes_ports_and_access_methods(self, config: DeployConfig) -> None:
        """Property13: README.md includes ports and access methods for each service."""
        docs = generate_docs(config)
        readme = docs["README.md"]

        # Port 443 for the reverse proxy
        assert "443" in readme, "README must mention port 443"

        # AmneziaWG UDP port
        awg_port_str = str(config.awg_listen_port) if config.awg_listen_port else "random"
        assert awg_port_str in readme or "udp" in readme.lower(), (
            "README must mention the AmneziaWG UDP port or indicate it's random"
        )

        # Xray internal port or SNI-based access
        assert str(config.xray_internal_port) in readme or config.reality_sni in readme, (
            "README must mention Xray internal port or Reality SNI access method"
        )

        # Panel access paths
        assert config.xui_path_prefix in readme, (
            "README must include the 3x-ui panel path prefix"
        )
        assert config.awg_panel_path_prefix in readme, (
            "README must include the AmneziaWG panel path prefix"
        )

        # Tailscale overlay network mention
        assert "overlay" in readme.lower() or "mesh" in readme.lower() or "tailnet" in readme.lower(), (
            "README must describe Tailscale's access method (overlay/mesh network)"
        )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_client_guides_includes_vless_reality_guide(self, config: DeployConfig) -> None:
        """Property13: client-guides.md includes a guide for VLESS+Reality."""
        docs = generate_docs(config)
        cg = docs["client-guides.md"]

        assert "VLESS" in cg, "Client guides must cover VLESS protocol"
        assert "Reality" in cg, "Client guides must cover Reality protocol"
        # Should mention at least one VLESS+Reality client app
        assert any(app in cg for app in ("v2rayNG", "v2rayN", "Nekoray", "Shadowrocket")), (
            "Client guides must mention at least one VLESS+Reality client application"
        )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_client_guides_includes_amneziawg_guide(self, config: DeployConfig) -> None:
        """Property13: client-guides.md includes a guide for AmneziaWG."""
        docs = generate_docs(config)
        cg = docs["client-guides.md"]

        assert "AmneziaWG" in cg, "Client guides must cover AmneziaWG"
        # Should mention the AmneziaVPN client or .conf import
        assert "AmneziaVPN" in cg or ".conf" in cg, (
            "Client guides must mention AmneziaVPN client or .conf file import"
        )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_client_guides_includes_tailscale_guide(self, config: DeployConfig) -> None:
        """Property13: client-guides.md includes a guide for Tailscale."""
        docs = generate_docs(config)
        cg = docs["client-guides.md"]

        assert "Tailscale" in cg, "Client guides must cover Tailscale"
        assert "tailnet" in cg or "authorization" in cg.lower() or "authorize" in cg.lower(), (
            "Client guides must describe Tailscale tailnet joining or authorization"
        )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_all_docs_include_copyright_notice(self, config: DeployConfig) -> None:
        """Property13: All generated docs include the copyright notice."""
        docs = generate_docs(config)

        for filename, content in docs.items():
            assert "© Vadim Pavlov 2026" in content, (
                f"{filename} must include the copyright notice '© Vadim Pavlov 2026'"
            )

    @given(config=valid_deploy_config)
    @settings(deadline=None)
    def test_readme_includes_domain_from_config(self, config: DeployConfig) -> None:
        """Property13: README.md includes the domain name from config."""
        docs = generate_docs(config)
        readme = docs["README.md"]

        assert config.domain in readme, (
            f"README must include the configured domain '{config.domain}'"
        )
