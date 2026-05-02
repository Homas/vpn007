# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for the VPN007 post-install summary generator."""

from __future__ import annotations

from pathlib import Path

import pytest

from vpn007.models import (
    DeployConfig,
    DeployError,
    DeployResult,
    ServiceResult,
    XrayClientConfig,
    AwgPeerConfig,
)
from vpn007.summary import generate_summary, save_summary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def all_ok_result() -> DeployResult:
    """DeployResult where every service succeeded."""
    return DeployResult(
        services={
            "reverse_proxy": ServiceResult(success=True),
            "three_x_ui": ServiceResult(success=True),
            "amneziawg": ServiceResult(success=True),
            "tailscale": ServiceResult(success=True),
            "cover_site": ServiceResult(success=True),
            "certbot": ServiceResult(success=True),
        }
    )


@pytest.fixture()
def partial_failure_result() -> DeployResult:
    """DeployResult with one failed service."""
    return DeployResult(
        services={
            "reverse_proxy": ServiceResult(success=True),
            "three_x_ui": ServiceResult(
                success=False,
                error=DeployError(
                    service="three_x_ui",
                    step="container_start",
                    message="Container exited with code 1",
                    remediation="Check 3x-ui container logs for startup errors.",
                ),
            ),
            "amneziawg": ServiceResult(success=True),
            "tailscale": ServiceResult(success=True),
            "cover_site": ServiceResult(success=True),
            "certbot": ServiceResult(success=True),
        }
    )


@pytest.fixture()
def sample_xray_client() -> XrayClientConfig:
    return XrayClientConfig(
        client_name="default-client",
        uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        vless_share_link="vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@203.0.113.10:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=TESTKEY&sid=abcd1234#default-client",
        qr_code_data="vless://...",
        reality_public_key="TESTKEY",
        short_id="abcd1234",
        sni="www.microsoft.com",
        server_address="203.0.113.10",
        server_port=443,
    )


@pytest.fixture()
def sample_awg_peer() -> AwgPeerConfig:
    return AwgPeerConfig(
        peer_name="default-peer",
        private_key="PEER_PRIVATE_KEY",
        public_key="PEER_PUBLIC_KEY",
        preshared_key=None,
        allowed_ips="0.0.0.0/0, ::/0",
        endpoint="203.0.113.10:34567",
        conf_content="[Interface]\nPrivateKey = PEER_PRIVATE_KEY\n",
    )


# ---------------------------------------------------------------------------
# generate_summary tests
# ---------------------------------------------------------------------------


class TestGenerateSummary:
    """Tests for generate_summary()."""

    def test_returns_string(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        result = generate_summary(valid_config, all_ok_result, {})
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_header(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        result = generate_summary(valid_config, all_ok_result, {})
        assert "# VPN007 — Post-Install Summary" in result

    def test_contains_copyright_footer(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        result = generate_summary(valid_config, all_ok_result, {})
        assert "© Vadim Pavlov 2026" in result
        assert "GPL-3.0" in result

    def test_service_status_all_running(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.1 — all services show running."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "## Service Status" in result
        for svc in [
            "reverse_proxy",
            "three_x_ui",
            "amneziawg",
            "tailscale",
            "cover_site",
            "certbot",
        ]:
            assert svc in result
        assert "✅ running" in result
        assert "❌ failed" not in result

    def test_service_status_with_failure(
        self,
        valid_config: DeployConfig,
        partial_failure_result: DeployResult,
    ) -> None:
        """Req 19.1 — failed service shows failed."""
        result = generate_summary(valid_config, partial_failure_result, {})
        assert "❌ failed" in result
        assert "✅ running" in result

    def test_public_endpoints_domain(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.1 — public endpoints include domain."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "## Public Endpoints" in result
        assert valid_config.domain in result
        assert "443" in result

    def test_public_endpoints_port_8443(
        self, all_ok_result: DeployResult
    ) -> None:
        """Req 19.1 — port 8443 shown when enabled."""
        config = DeployConfig(domain="vpn.example.com", enable_port_8443=True)
        result = generate_summary(config, all_ok_result, {})
        assert "8443" in result

    def test_public_endpoints_no_8443_by_default(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Port 8443 not shown when disabled."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "8443" not in result

    def test_public_endpoints_awg_port(
        self, all_ok_result: DeployResult
    ) -> None:
        """Req 19.1 — AmneziaWG UDP port shown."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=34567)
        result = generate_summary(config, all_ok_result, {})
        assert "34567" in result

    def test_vpn_client_xray_share_link(
        self,
        valid_config: DeployConfig,
        all_ok_result: DeployResult,
        sample_xray_client: XrayClientConfig,
    ) -> None:
        """Req 19.2 — VLESS share link included."""
        result = generate_summary(
            valid_config, all_ok_result, {"xray": sample_xray_client}
        )
        assert "### Xray VLESS+Reality" in result
        assert sample_xray_client.vless_share_link in result

    def test_vpn_client_awg_config_path(
        self,
        valid_config: DeployConfig,
        all_ok_result: DeployResult,
        sample_awg_peer: AwgPeerConfig,
    ) -> None:
        """Req 19.2 — AmneziaWG config file path included."""
        result = generate_summary(
            valid_config, all_ok_result, {"awg": sample_awg_peer}
        )
        assert "### AmneziaWG" in result
        assert f"awg-{sample_awg_peer.peer_name}.conf" in result

    def test_vpn_client_tailscale_no_key(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.2 — Tailscale join instructions when no auth key."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "### Tailscale" in result
        assert "docker compose logs tailscale" in result

    def test_vpn_client_tailscale_with_key(
        self, all_ok_result: DeployResult
    ) -> None:
        """Req 19.2 — Tailscale message when auth key provided."""
        config = DeployConfig(
            domain="vpn.example.com",
            tailscale_auth_key="tskey-auth-example1234567890",
        )
        result = generate_summary(config, all_ok_result, {})
        assert "already be joined" in result

    def test_web_panel_urls(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.3 — panel URLs with path prefixes."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "## Web Panel Access" in result
        assert valid_config.xui_path_prefix in result
        assert valid_config.awg_panel_path_prefix in result
        assert "restricted to approved IPs" in result

    def test_web_panel_approved_ips_shown(
        self, all_ok_result: DeployResult
    ) -> None:
        """Req 19.3 — approved IPs listed in panel section."""
        config = DeployConfig(
            domain="vpn.example.com",
            approved_ips=["10.0.0.1", "192.168.1.0/24"],
        )
        result = generate_summary(config, all_ok_result, {})
        assert "10.0.0.1" in result
        assert "192.168.1.0/24" in result

    def test_management_commands(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.4 — common management commands present."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "## Common Management Commands" in result
        assert "docker compose restart" in result
        assert "docker compose logs" in result
        assert "docker compose pull" in result
        assert "docker compose up -d" in result

    def test_management_add_remove_clients(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Req 19.4 — add/remove client instructions."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "Add / Remove VPN Clients" in result

    def test_security_reminder(
        self, all_ok_result: DeployResult
    ) -> None:
        """Req 19.5 — security reminder with approved IPs and blocked ASNs."""
        config = DeployConfig(
            domain="vpn.example.com",
            approved_ips=["10.0.0.1"],
            blocked_as_numbers=["AS196747"],
            blocked_subnets=["198.51.100.0/24"],
        )
        result = generate_summary(config, all_ok_result, {})
        assert "## Security Reminder" in result
        assert "10.0.0.1" in result
        assert "AS196747" in result
        assert "198.51.100.0/24" in result
        assert "nftables" in result

    def test_failed_services_section_present(
        self,
        valid_config: DeployConfig,
        partial_failure_result: DeployResult,
    ) -> None:
        """Req 19.7 — failed services section with error and remediation."""
        result = generate_summary(
            valid_config, partial_failure_result, {}
        )
        assert "Failed Services" in result
        assert "three_x_ui" in result
        assert "Container exited with code 1" in result
        assert "Check 3x-ui container logs" in result

    def test_no_failed_section_when_all_ok(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """No failed-services section when everything succeeded."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "Failed Services" not in result

    def test_failed_services_troubleshooting_steps(
        self,
        valid_config: DeployConfig,
        partial_failure_result: DeployResult,
    ) -> None:
        """Req 19.7 — troubleshooting steps for failed services."""
        result = generate_summary(
            valid_config, partial_failure_result, {}
        )
        assert "docker compose logs three_x_ui" in result
        assert "docker compose restart three_x_ui" in result

    def test_public_ipv4_shown(
        self, all_ok_result: DeployResult
    ) -> None:
        config = DeployConfig(
            domain="vpn.example.com", public_ipv4="203.0.113.10"
        )
        result = generate_summary(config, all_ok_result, {})
        assert "203.0.113.10" in result

    def test_public_ipv6_shown(
        self, all_ok_result: DeployResult
    ) -> None:
        config = DeployConfig(
            domain="vpn.example.com", public_ipv6="2001:db8::1"
        )
        result = generate_summary(config, all_ok_result, {})
        assert "2001:db8::1" in result

    def test_empty_client_configs(
        self, valid_config: DeployConfig, all_ok_result: DeployResult
    ) -> None:
        """Summary works with no client configs."""
        result = generate_summary(valid_config, all_ok_result, {})
        assert "## VPN Client Connection Instructions" in result
        # Should still have Tailscale section
        assert "### Tailscale" in result

    def test_both_client_configs(
        self,
        valid_config: DeployConfig,
        all_ok_result: DeployResult,
        sample_xray_client: XrayClientConfig,
        sample_awg_peer: AwgPeerConfig,
    ) -> None:
        """Summary includes both Xray and AWG when provided."""
        result = generate_summary(
            valid_config,
            all_ok_result,
            {"xray": sample_xray_client, "awg": sample_awg_peer},
        )
        assert "### Xray VLESS+Reality" in result
        assert "### AmneziaWG" in result
        assert "### Tailscale" in result


# ---------------------------------------------------------------------------
# save_summary tests
# ---------------------------------------------------------------------------


class TestSaveSummary:
    """Tests for save_summary()."""

    def test_creates_file(self, tmp_path: Path) -> None:
        """Req 19.6 — summary saved to POST_INSTALL.md."""
        text = "# Test Summary\nHello"
        path = save_summary(tmp_path, text)
        assert path == tmp_path / "POST_INSTALL.md"
        assert path.exists()
        assert path.read_text(encoding="utf-8") == text

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "a" / "b"
        text = "# Nested"
        path = save_summary(nested, text)
        assert path.exists()
        assert path.read_text(encoding="utf-8") == text

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        first = save_summary(tmp_path, "first")
        save_summary(tmp_path, "second")
        assert first.read_text(encoding="utf-8") == "second"

    def test_returns_path_object(self, tmp_path: Path) -> None:
        path = save_summary(tmp_path, "content")
        assert isinstance(path, Path)
        assert path.name == "POST_INSTALL.md"


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------

from hypothesis import given, settings, strategies as st


# Known service names used by the summary generator
_KNOWN_SERVICES = [
    "reverse_proxy",
    "three_x_ui",
    "amneziawg",
    "tailscale",
    "cover_site",
    "certbot",
]

# Strategy for non-empty printable strings (service names, steps, messages)
_nonempty_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Z")),
    min_size=1,
    max_size=80,
).filter(lambda s: s.strip())


class TestProperty15ErrorReportingIncludesContext:
    """Property 15: Error reporting includes context.

    **Validates: Requirements 13.1, 13.5**
    """

    @given(
        service_name=_nonempty_text,
        step_name=_nonempty_text,
        error_message=_nonempty_text,
    )
    def test_deploy_error_str_contains_service_and_step(
        self,
        service_name: str,
        step_name: str,
        error_message: str,
    ) -> None:
        """For any DeployError, str(error) contains the service name and step.

        **Validates: Requirements 13.1**
        """
        error = DeployError(
            service=service_name,
            step=step_name,
            message=error_message,
        )
        error_str = str(error)
        assert service_name in error_str, (
            f"Service name {service_name!r} not found in error string: {error_str!r}"
        )
        assert step_name in error_str, (
            f"Step name {step_name!r} not found in error string: {error_str!r}"
        )

    @given(
        known_service=st.sampled_from(_KNOWN_SERVICES),
        step_name=_nonempty_text,
        error_message=_nonempty_text,
        remediation=_nonempty_text,
    )
    def test_summary_includes_error_and_remediation_for_failed_service(
        self,
        known_service: str,
        step_name: str,
        error_message: str,
        remediation: str,
    ) -> None:
        """For any failed service, generate_summary includes the error message
        and remediation suggestion.

        **Validates: Requirements 13.1, 13.5**
        """
        deploy_error = DeployError(
            service=known_service,
            step=step_name,
            message=error_message,
            remediation=remediation,
        )
        # Build a DeployResult with one failed service among otherwise-OK services
        services: dict[str, ServiceResult] = {}
        for svc in _KNOWN_SERVICES:
            if svc == known_service:
                services[svc] = ServiceResult(success=False, error=deploy_error)
            else:
                services[svc] = ServiceResult(success=True)
        deploy_result = DeployResult(services=services)

        config = DeployConfig(domain="vpn.example.com")
        summary = generate_summary(config, deploy_result, {})

        # The error message must appear in the summary
        assert error_message in summary, (
            f"Error message {error_message!r} not found in summary for service {known_service!r}"
        )
        # The remediation suggestion must appear in the summary
        assert remediation in summary, (
            f"Remediation {remediation!r} not found in summary for service {known_service!r}"
        )

    @given(
        known_service=st.sampled_from(_KNOWN_SERVICES),
        step_name=_nonempty_text,
        error_message=_nonempty_text,
    )
    def test_summary_includes_troubleshooting_steps_for_failed_service(
        self,
        known_service: str,
        step_name: str,
        error_message: str,
    ) -> None:
        """For any failed service, generate_summary includes troubleshooting
        steps (docker compose logs, docker compose restart).

        **Validates: Requirements 13.5**
        """
        deploy_error = DeployError(
            service=known_service,
            step=step_name,
            message=error_message,
            remediation="Try restarting the service.",
        )
        services: dict[str, ServiceResult] = {}
        for svc in _KNOWN_SERVICES:
            if svc == known_service:
                services[svc] = ServiceResult(success=False, error=deploy_error)
            else:
                services[svc] = ServiceResult(success=True)
        deploy_result = DeployResult(services=services)

        config = DeployConfig(domain="vpn.example.com")
        summary = generate_summary(config, deploy_result, {})

        # Troubleshooting steps must reference the failed service by name
        assert f"docker compose logs {known_service}" in summary, (
            f"Missing 'docker compose logs {known_service}' in summary"
        )
        assert f"docker compose restart {known_service}" in summary, (
            f"Missing 'docker compose restart {known_service}' in summary"
        )
