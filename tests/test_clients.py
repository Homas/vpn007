# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for VPN007 client provisioning module."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from vpn007.clients import (
    generate_3xui_admin_credentials,
    provision_awg_peer,
    provision_xray_client,
    save_client_configs,
)
from vpn007.models import (
    AwgObfuscation,
    DeployConfig,
    RealityKeys,
)


# ---------------------------------------------------------------------------
# provision_xray_client tests
# ---------------------------------------------------------------------------


class TestProvisionXrayClient:
    """Tests for provision_xray_client."""

    def test_returns_xray_client_config(self, valid_config: DeployConfig) -> None:
        """Basic provisioning returns a valid XrayClientConfig."""
        result = provision_xray_client(valid_config)
        assert result.client_name == "default-client"
        assert result.uuid  # non-empty
        assert result.vless_share_link.startswith("vless://")
        assert result.qr_code_data == result.vless_share_link
        assert result.sni == valid_config.reality_sni

    def test_custom_client_name(self, valid_config: DeployConfig) -> None:
        """Client name is reflected in the result and share link."""
        result = provision_xray_client(valid_config, client_name="my-phone")
        assert result.client_name == "my-phone"
        assert "my-phone" in result.vless_share_link

    def test_uuid_is_valid(self, valid_config: DeployConfig) -> None:
        """Generated UUID is a valid UUID4."""
        result = provision_xray_client(valid_config)
        parsed = uuid.UUID(result.uuid)
        assert parsed.version == 4

    def test_unique_uuids(self, valid_config: DeployConfig) -> None:
        """Each call generates a unique UUID."""
        r1 = provision_xray_client(valid_config)
        r2 = provision_xray_client(valid_config)
        assert r1.uuid != r2.uuid

    def test_uses_provided_reality_keys(self) -> None:
        """When reality_keys are set on config, they are used in the share link."""
        keys = RealityKeys(
            private_key="test_priv_key_base64",
            public_key="test_pub_key_base64",
            short_id="abcd1234",
        )
        config = DeployConfig(domain="vpn.example.com", reality_keys=keys)
        result = provision_xray_client(config)
        assert result.reality_public_key == "test_pub_key_base64"
        assert result.short_id == "abcd1234"
        assert "test_pub_key_base64" in result.vless_share_link
        assert "abcd1234" in result.vless_share_link

    def test_auto_generates_reality_keys(self, valid_config: DeployConfig) -> None:
        """When reality_keys is None, keys are auto-generated."""
        assert valid_config.reality_keys is None
        result = provision_xray_client(valid_config)
        assert result.reality_public_key  # non-empty
        assert result.short_id  # non-empty

    def test_vless_link_format(self) -> None:
        """VLESS share link has the correct URI structure."""
        keys = RealityKeys(
            private_key="privkey",
            public_key="pubkey123",
            short_id="aabb0011",
        )
        config = DeployConfig(
            domain="vpn.example.com",
            reality_sni="www.microsoft.com",
            reality_keys=keys,
            public_ipv4="1.2.3.4",
        )
        result = provision_xray_client(config, client_name="test")

        # Parse the VLESS URI
        assert result.vless_share_link.startswith("vless://")
        # Extract the part after vless://
        uri_body = result.vless_share_link[len("vless://"):]
        # UUID@server:port?params#fragment
        assert "@1.2.3.4:443" in uri_body
        assert "type=tcp" in uri_body
        assert "security=reality" in uri_body
        assert "sni=www.microsoft.com" in uri_body
        assert "fp=chrome" in uri_body
        assert "pbk=pubkey123" in uri_body
        assert "sid=aabb0011" in uri_body
        assert uri_body.endswith("#test")

    def test_server_address_priority(self) -> None:
        """Server address prefers public_ipv4 > incoming_ip > domain."""
        # public_ipv4 takes priority
        config = DeployConfig(
            domain="vpn.example.com",
            public_ipv4="1.2.3.4",
            incoming_ip="5.6.7.8",
        )
        result = provision_xray_client(config)
        assert result.server_address == "1.2.3.4"

        # incoming_ip when no public_ipv4
        config2 = DeployConfig(
            domain="vpn.example.com",
            incoming_ip="5.6.7.8",
        )
        result2 = provision_xray_client(config2)
        assert result2.server_address == "5.6.7.8"

        # domain as fallback
        config3 = DeployConfig(domain="vpn.example.com")
        result3 = provision_xray_client(config3)
        assert result3.server_address == "vpn.example.com"

    def test_server_port_is_443(self, valid_config: DeployConfig) -> None:
        """Server port is always 443 (standard HTTPS)."""
        result = provision_xray_client(valid_config)
        assert result.server_port == 443


# ---------------------------------------------------------------------------
# provision_awg_peer tests
# ---------------------------------------------------------------------------


class TestProvisionAwgPeer:
    """Tests for provision_awg_peer."""

    def test_returns_awg_peer_config(self, valid_config: DeployConfig) -> None:
        """Basic provisioning returns a valid AwgPeerConfig."""
        result = provision_awg_peer(valid_config)
        assert result.peer_name == "default-peer"
        assert result.private_key  # non-empty
        assert result.public_key  # non-empty
        assert result.conf_content  # non-empty
        assert result.allowed_ips == "0.0.0.0/0, ::/0"

    def test_custom_peer_name(self, valid_config: DeployConfig) -> None:
        """Peer name is reflected in the result."""
        result = provision_awg_peer(valid_config, peer_name="my-laptop")
        assert result.peer_name == "my-laptop"

    def test_generates_wg_keypair(self, valid_config: DeployConfig) -> None:
        """Each call generates a unique WireGuard key pair."""
        r1 = provision_awg_peer(valid_config)
        r2 = provision_awg_peer(valid_config)
        assert r1.private_key != r2.private_key
        assert r1.public_key != r2.public_key

    def test_conf_has_interface_and_peer_sections(
        self, valid_config: DeployConfig
    ) -> None:
        """Generated .conf has [Interface] and [Peer] sections."""
        result = provision_awg_peer(valid_config)
        assert "[Interface]" in result.conf_content
        assert "[Peer]" in result.conf_content

    def test_conf_contains_private_key(self, valid_config: DeployConfig) -> None:
        """Generated .conf contains the peer's private key."""
        result = provision_awg_peer(valid_config)
        assert f"PrivateKey = {result.private_key}" in result.conf_content

    def test_conf_contains_endpoint(self, valid_config: DeployConfig) -> None:
        """Generated .conf contains the server endpoint."""
        config = DeployConfig(
            domain="vpn.example.com",
            public_ipv4="1.2.3.4",
            awg_listen_port=34567,
        )
        result = provision_awg_peer(config)
        assert "Endpoint = 1.2.3.4:34567" in result.conf_content
        assert result.endpoint == "1.2.3.4:34567"

    def test_conf_without_obfuscation(self) -> None:
        """Without AWG obfuscation, conf has no S/H/J/I params."""
        config = DeployConfig(domain="vpn.example.com", awg_obfuscation=None)
        result = provision_awg_peer(config)
        assert "S1 =" not in result.conf_content
        assert "H1 =" not in result.conf_content
        assert "Jc =" not in result.conf_content

    def test_conf_with_obfuscation(self) -> None:
        """With AWG obfuscation, conf includes all 2.0 params."""
        obfs = AwgObfuscation(
            s1=30, s2=80, s3=40, s4=20,
            h1=100, h2=200, h3=300, h4=400,
            jc=4, jmin=50, jmax=1000,
            i1="", i2="", i3="", i4="", i5="",
        )
        config = DeployConfig(domain="vpn.example.com", awg_obfuscation=obfs)
        result = provision_awg_peer(config)
        conf = result.conf_content
        assert "S1 = 30" in conf
        assert "S2 = 80" in conf
        assert "S3 = 40" in conf
        assert "S4 = 20" in conf
        assert "H1 = 100" in conf
        assert "H2 = 200" in conf
        assert "H3 = 300" in conf
        assert "H4 = 400" in conf
        assert "Jc = 4" in conf
        assert "Jmin = 50" in conf
        assert "Jmax = 1000" in conf

    def test_default_port_fallback(self) -> None:
        """When awg_listen_port is None, falls back to 51820."""
        config = DeployConfig(domain="vpn.example.com", awg_listen_port=None)
        result = provision_awg_peer(config)
        assert ":51820" in result.endpoint


# ---------------------------------------------------------------------------
# generate_3xui_admin_credentials tests
# ---------------------------------------------------------------------------


class TestGenerate3xuiAdminCredentials:
    """Tests for generate_3xui_admin_credentials."""

    def test_returns_tuple(self) -> None:
        """Returns a (username, password) tuple."""
        result = generate_3xui_admin_credentials()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_username_length(self) -> None:
        """Username is 8-12 characters."""
        username, _ = generate_3xui_admin_credentials()
        assert 8 <= len(username) <= 12

    def test_password_length(self) -> None:
        """Password is 16-24 characters."""
        _, password = generate_3xui_admin_credentials()
        assert 16 <= len(password) <= 24

    def test_username_is_alphanumeric(self) -> None:
        """Username contains only alphanumeric characters."""
        username, _ = generate_3xui_admin_credentials()
        assert username.isalnum()

    def test_password_charset(self) -> None:
        """Password contains only allowed characters."""
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*")
        _, password = generate_3xui_admin_credentials()
        assert all(ch in allowed for ch in password)

    def test_unique_credentials(self) -> None:
        """Each call generates different credentials."""
        r1 = generate_3xui_admin_credentials()
        r2 = generate_3xui_admin_credentials()
        # Extremely unlikely to be the same
        assert r1 != r2


# ---------------------------------------------------------------------------
# save_client_configs tests
# ---------------------------------------------------------------------------


class TestSaveClientConfigs:
    """Tests for save_client_configs."""

    def test_saves_xray_config(self, output_dir: Path) -> None:
        """Saves Xray client config to the correct path."""
        config = DeployConfig(domain="vpn.example.com")
        xray = provision_xray_client(config, client_name="test-client")
        saved = save_client_configs(output_dir, xray_client=xray)

        assert "xray" in saved
        xray_path = saved["xray"]
        assert xray_path.name == "xray-test-client.txt"
        assert xray_path.exists()
        content = xray_path.read_text(encoding="utf-8")
        assert content.strip().startswith("vless://")

    def test_saves_awg_config(self, output_dir: Path) -> None:
        """Saves AmneziaWG peer config to the correct path."""
        config = DeployConfig(domain="vpn.example.com")
        awg = provision_awg_peer(config, peer_name="test-peer")
        saved = save_client_configs(output_dir, awg_peer=awg)

        assert "awg" in saved
        awg_path = saved["awg"]
        assert awg_path.name == "awg-test-peer.conf"
        assert awg_path.exists()
        content = awg_path.read_text(encoding="utf-8")
        assert "[Interface]" in content
        assert "[Peer]" in content

    def test_saves_both(self, output_dir: Path) -> None:
        """Saves both configs when both are provided."""
        config = DeployConfig(domain="vpn.example.com")
        xray = provision_xray_client(config)
        awg = provision_awg_peer(config)
        saved = save_client_configs(output_dir, xray_client=xray, awg_peer=awg)
        assert "xray" in saved
        assert "awg" in saved

    def test_creates_clients_directory(self, output_dir: Path) -> None:
        """Creates the clients/ subdirectory if it doesn't exist."""
        config = DeployConfig(domain="vpn.example.com")
        xray = provision_xray_client(config)
        save_client_configs(output_dir, xray_client=xray)
        assert (output_dir / "clients").is_dir()

    def test_skips_none_configs(self, output_dir: Path) -> None:
        """Returns empty dict when no configs are provided."""
        saved = save_client_configs(output_dir)
        assert saved == {}
