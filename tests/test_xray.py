# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based and unit tests for vpn007.xray — Xray config generation."""

from __future__ import annotations

import json
from unittest.mock import patch

from hypothesis import given
from hypothesis import strategies as st

from vpn007.crypto import generate_reality_keypair
from vpn007.models import DeployConfig, RealityKeys
from vpn007.xray import generate_xray_config, validate_reality_sni

from tests.conftest import valid_deploy_config, valid_domain


# ---------------------------------------------------------------------------
# Hypothesis strategy for DeployConfig with explicit Reality keys
# ---------------------------------------------------------------------------

def _valid_deploy_config_with_keys():
    """Strategy that produces a DeployConfig with pre-generated Reality keys."""
    return valid_deploy_config.map(_attach_reality_keys)


def _attach_reality_keys(config: DeployConfig) -> DeployConfig:
    """Attach a freshly generated Reality key pair to a config."""
    config.reality_keys = generate_reality_keypair()
    return config


# ---------------------------------------------------------------------------
# Property 4: Xray config preserves Reality parameters
# ---------------------------------------------------------------------------


class TestProperty4XrayConfigPreservesRealityParams:
    """**Property 4: Xray config preserves Reality parameters**

    For any valid DeployConfig with a Reality SNI domain and key pair,
    the generated config.json contains a VLESS inbound with Reality
    security, the correct SNI in serverNames, and the correct private key.

    **Validates: Requirements 3.1, 3.3**
    """

    @given(config=_valid_deploy_config_with_keys())
    def test_output_is_valid_json(self, config: DeployConfig) -> None:
        """Generated Xray config must be valid, parseable JSON."""
        output = generate_xray_config(config)
        parsed = json.loads(output)
        assert isinstance(parsed, dict), "Parsed JSON must be a dict"

    @given(config=_valid_deploy_config_with_keys())
    def test_has_vless_inbound(self, config: DeployConfig) -> None:
        """Config must contain at least one VLESS inbound."""
        parsed = json.loads(generate_xray_config(config))
        inbounds = parsed.get("inbounds", [])
        assert len(inbounds) >= 1, "Must have at least one inbound"
        vless_inbounds = [ib for ib in inbounds if ib.get("protocol") == "vless"]
        assert len(vless_inbounds) >= 1, "Must have at least one VLESS inbound"

    @given(config=_valid_deploy_config_with_keys())
    def test_reality_security_configured(self, config: DeployConfig) -> None:
        """The VLESS inbound must use Reality security."""
        parsed = json.loads(generate_xray_config(config))
        inbound = parsed["inbounds"][0]
        stream = inbound.get("streamSettings", {})
        assert stream.get("security") == "reality", (
            "VLESS inbound must use 'reality' security"
        )
        assert "realitySettings" in stream, (
            "streamSettings must contain realitySettings"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_sni_in_server_names(self, config: DeployConfig) -> None:
        """The configured Reality SNI must appear in serverNames."""
        parsed = json.loads(generate_xray_config(config))
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        server_names = reality.get("serverNames", [])
        assert config.reality_sni in server_names, (
            f"Expected SNI {config.reality_sni!r} in serverNames {server_names}"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_private_key_preserved(self, config: DeployConfig) -> None:
        """The Reality private key must match the config's key pair."""
        assert config.reality_keys is not None
        parsed = json.loads(generate_xray_config(config))
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality.get("privateKey") == config.reality_keys.private_key, (
            "Reality privateKey must match the provided key"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_short_id_preserved(self, config: DeployConfig) -> None:
        """The Reality short_id must appear in shortIds."""
        assert config.reality_keys is not None
        parsed = json.loads(generate_xray_config(config))
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        short_ids = reality.get("shortIds", [])
        assert config.reality_keys.short_id in short_ids, (
            f"Expected short_id {config.reality_keys.short_id!r} in {short_ids}"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_internal_port_matches(self, config: DeployConfig) -> None:
        """The inbound listen port must match xray_internal_port."""
        parsed = json.loads(generate_xray_config(config))
        inbound = parsed["inbounds"][0]
        assert inbound.get("port") == config.xray_internal_port, (
            f"Expected port {config.xray_internal_port}, "
            f"got {inbound.get('port')}"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_accept_proxy_protocol_enabled(self, config: DeployConfig) -> None:
        """The VLESS inbound must have acceptProxyProtocol: true."""
        parsed = json.loads(generate_xray_config(config))
        stream = parsed["inbounds"][0]["streamSettings"]
        tcp_settings = stream.get("tcpSettings", {})
        assert tcp_settings.get("acceptProxyProtocol") is True, (
            "tcpSettings.acceptProxyProtocol must be true"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_dest_includes_sni(self, config: DeployConfig) -> None:
        """The Reality dest field must point to the SNI target on port 443."""
        parsed = json.loads(generate_xray_config(config))
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        expected_dest = f"{config.reality_sni}:443"
        assert reality.get("dest") == expected_dest, (
            f"Expected dest {expected_dest!r}, got {reality.get('dest')!r}"
        )

    @given(config=_valid_deploy_config_with_keys())
    def test_has_direct_and_blocked_outbounds(self, config: DeployConfig) -> None:
        """Config must have 'direct' (freedom) and 'blocked' (blackhole) outbounds."""
        parsed = json.loads(generate_xray_config(config))
        outbounds = parsed.get("outbounds", [])
        tags = {ob.get("tag") for ob in outbounds}
        assert "direct" in tags, "Must have a 'direct' outbound"
        assert "blocked" in tags, "Must have a 'blocked' outbound"

        direct = next(ob for ob in outbounds if ob["tag"] == "direct")
        assert direct["protocol"] == "freedom"

        blocked = next(ob for ob in outbounds if ob["tag"] == "blocked")
        assert blocked["protocol"] == "blackhole"


# ---------------------------------------------------------------------------
# Unit tests for auto-generation of Reality keys
# ---------------------------------------------------------------------------


class TestXrayAutoKeyGeneration:
    """When reality_keys is None, generate_xray_config should auto-generate."""

    def test_auto_generates_keys_when_none(self) -> None:
        config = DeployConfig(domain="vpn.example.com", reality_keys=None)
        output = generate_xray_config(config)
        parsed = json.loads(output)
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        # Keys should be present and non-empty
        assert reality["privateKey"], "Auto-generated privateKey must be non-empty"
        assert reality["shortIds"][0], "Auto-generated shortId must be non-empty"

    def test_uses_provided_keys(self) -> None:
        keys = RealityKeys(
            private_key="dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2",
            public_key="dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY3",
            short_id="abcd1234",
        )
        config = DeployConfig(
            domain="vpn.example.com",
            reality_sni="www.cloudflare.com",
            reality_keys=keys,
        )
        output = generate_xray_config(config)
        parsed = json.loads(output)
        reality = parsed["inbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["privateKey"] == keys.private_key
        assert keys.short_id in reality["shortIds"]
        assert "www.cloudflare.com" in reality["serverNames"]


# ---------------------------------------------------------------------------
# Unit tests for validate_reality_sni
# ---------------------------------------------------------------------------


class TestValidateRealitySni:
    """Tests for the SNI TLS 1.3 validation function."""

    def test_returns_false_for_nonexistent_domain(self) -> None:
        """A domain that doesn't resolve should return False."""
        result = validate_reality_sni(
            "this-domain-does-not-exist-vpn007.example", timeout=2.0
        )
        assert result is False

    def test_returns_bool(self) -> None:
        """validate_reality_sni must always return a bool."""
        result = validate_reality_sni("localhost", timeout=1.0)
        assert isinstance(result, bool)

    @patch("vpn007.xray.socket.create_connection")
    def test_returns_false_on_connection_error(self, mock_conn) -> None:
        """OSError during connection should return False."""
        mock_conn.side_effect = OSError("Connection refused")
        result = validate_reality_sni("www.example.com", timeout=1.0)
        assert result is False
