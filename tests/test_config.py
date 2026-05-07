# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.config — config loading, merging, and IP detection."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from vpn007.config import (
    _parse_awg_obfuscation,
    _parse_bool,
    _parse_comma_list,
    _parse_cover_site_mode,
    _parse_int_or_none,
    _parse_port_forwards,
    _parse_tunnel_type,
    _read_env_file,
    load_config,
)
from vpn007.models import CoverSiteMode, PortForward, TunnelType


# ---------------------------------------------------------------------------
# Type converter unit tests
# ---------------------------------------------------------------------------


class TestParseBool:
    @pytest.mark.parametrize("val", ["true", "True", "TRUE", "yes", "1", "y", "on"])
    def test_truthy_values(self, val: str) -> None:
        assert _parse_bool(val) is True

    @pytest.mark.parametrize("val", ["false", "False", "FALSE", "no", "0", "n", "off"])
    def test_falsy_values(self, val: str) -> None:
        assert _parse_bool(val) is False

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_bool("maybe")

    def test_whitespace_stripped(self) -> None:
        assert _parse_bool("  yes  ") is True


class TestParseIntOrNone:
    def test_valid_int(self) -> None:
        assert _parse_int_or_none("42") == 42

    def test_empty_returns_none(self) -> None:
        assert _parse_int_or_none("") is None
        assert _parse_int_or_none("   ") is None

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_int_or_none("abc")


class TestParseCommaList:
    def test_basic(self) -> None:
        assert _parse_comma_list("a,b,c") == ["a", "b", "c"]

    def test_whitespace(self) -> None:
        assert _parse_comma_list(" a , b , c ") == ["a", "b", "c"]

    def test_empty_items_filtered(self) -> None:
        assert _parse_comma_list("a,,b,") == ["a", "b"]

    def test_empty_string(self) -> None:
        assert _parse_comma_list("") == []

    def test_single_item(self) -> None:
        assert _parse_comma_list("10.0.0.1") == ["10.0.0.1"]


class TestParsePortForwards:
    def test_single_entry(self) -> None:
        result = _parse_port_forwards("tcp:443:443:HTTPS")
        assert len(result) == 1
        assert result[0] == PortForward("tcp", 443, 443, "HTTPS")

    def test_multiple_entries(self) -> None:
        result = _parse_port_forwards("tcp:443:443:HTTPS,udp:51820:51820:WG")
        assert len(result) == 2
        assert result[0].protocol == "tcp"
        assert result[1].protocol == "udp"

    def test_no_description(self) -> None:
        result = _parse_port_forwards("tcp:80:8080")
        assert result[0].description == ""

    def test_empty_string(self) -> None:
        assert _parse_port_forwards("") == []

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_port_forwards("tcp:443")


class TestParseCoverSiteMode:
    def test_static(self) -> None:
        assert _parse_cover_site_mode("static") == CoverSiteMode.STATIC

    def test_proxy(self) -> None:
        assert _parse_cover_site_mode("proxy") == CoverSiteMode.PROXY

    def test_case_insensitive(self) -> None:
        assert _parse_cover_site_mode("STATIC") == CoverSiteMode.STATIC

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_cover_site_mode("invalid")


class TestParseTunnelType:
    def test_wireguard(self) -> None:
        assert _parse_tunnel_type("wireguard") == TunnelType.WIREGUARD

    def test_ssh(self) -> None:
        assert _parse_tunnel_type("ssh") == TunnelType.SSH

    def test_tailscale(self) -> None:
        assert _parse_tunnel_type("tailscale") == TunnelType.TAILSCALE

    def test_empty_returns_none(self) -> None:
        assert _parse_tunnel_type("") is None
        assert _parse_tunnel_type("   ") is None


# ---------------------------------------------------------------------------
# AWG obfuscation parsing
# ---------------------------------------------------------------------------


class TestParseAwgObfuscation:
    def test_full_config(self) -> None:
        env = {
            "AWG_S1": "30", "AWG_S2": "80", "AWG_S3": "40", "AWG_S4": "20",
            "AWG_H1": "100", "AWG_H2": "200", "AWG_H3": "300", "AWG_H4": "400",
            "AWG_JC": "4", "AWG_JMIN": "50", "AWG_JMAX": "1000",
            "AWG_I1": "<b 0xd100000001><r 50>", "AWG_I2": "", "AWG_I3": "", "AWG_I4": "", "AWG_I5": "",
        }
        result = _parse_awg_obfuscation(env)
        assert result is not None
        assert result.s1 == 30
        assert result.s4 == 20
        assert result.h4 == 400
        assert result.jmax == 1000
        assert result.i1 == "<b 0xd100000001><r 50>"
        assert result.i5 == ""

    def test_minimal_config_uses_defaults(self) -> None:
        env = {
            "AWG_S1": "30", "AWG_S2": "80", "AWG_S3": "40", "AWG_S4": "20",
            "AWG_H1": "100", "AWG_H2": "200", "AWG_H3": "300", "AWG_H4": "400",
        }
        result = _parse_awg_obfuscation(env)
        assert result is not None
        assert result.jc == 4  # default
        assert result.jmin == 50  # default
        assert result.i1 == "<b 0x000100002112a442><r 12>"  # WebRTC/STUN default (key absent from env)

    def test_no_vars_returns_none(self) -> None:
        assert _parse_awg_obfuscation({}) is None

    def test_partial_config_raises(self) -> None:
        env = {"AWG_S1": "30", "AWG_S2": "80"}
        with pytest.raises(ValueError, match="Partial"):
            _parse_awg_obfuscation(env)


# ---------------------------------------------------------------------------
# .env file reading
# ---------------------------------------------------------------------------


class TestReadEnvFile:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = _read_env_file(tmp_path / "nonexistent.env")
        assert result == {}

    def test_reads_existing_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOMAIN=vpn.example.com\nREALITY_SNI=www.microsoft.com\n")
        result = _read_env_file(env_file)
        assert result["DOMAIN"] == "vpn.example.com"
        assert result["REALITY_SNI"] == "www.microsoft.com"


# ---------------------------------------------------------------------------
# load_config integration tests
# ---------------------------------------------------------------------------


def _make_namespace(**kwargs: object) -> argparse.Namespace:
    """Create an argparse.Namespace with given kwargs, defaulting others to None."""
    defaults = {"env_file": ".env"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestLoadConfig:
    """Tests for the full load_config flow."""

    @patch("vpn007.config._resolve_public_ips")
    def test_loads_from_env_file(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "REALITY_SNI=www.cloudflare.com\n"
            "AWG_LISTEN_PORT=34567\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.domain == "vpn.example.com"
        assert config.reality_sni == "www.cloudflare.com"
        assert config.awg_listen_port == 34567

    @patch("vpn007.config._resolve_public_ips")
    def test_cli_overrides_env(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOMAIN=env.example.com\nREALITY_SNI=www.google.com\n")
        ns = _make_namespace(
            env_file=str(env_file),
            domain="cli.example.com",
        )
        config = load_config(ns)
        assert config.domain == "cli.example.com"
        assert config.reality_sni == "www.google.com"  # from env

    @patch("vpn007.config._resolve_public_ips")
    def test_auto_randomize_awg_port(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOMAIN=vpn.example.com\n")
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.awg_listen_port is not None
        assert 10000 <= config.awg_listen_port <= 65535

    @patch("vpn007.config._resolve_public_ips")
    def test_comma_separated_lists(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "APPROVED_IPS=10.0.0.1,10.0.0.2,10.0.0.3\n"
            "BLOCKED_AS_NUMBERS=AS196747,AS12345\n"
            "SSH_APPROVED_IPS=192.168.1.1\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.approved_ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert config.blocked_as_numbers == ["AS196747", "AS12345"]
        assert config.ssh_approved_ips == ["192.168.1.1"]

    @patch("vpn007.config._resolve_public_ips")
    def test_port_forward_parsing(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "FORWARDING_PORTS=tcp:443:443:HTTPS,udp:51820:51820:WG\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert len(config.forwarding_ports) == 2
        assert config.forwarding_ports[0].protocol == "tcp"
        assert config.forwarding_ports[1].listen_port == 51820

    @patch("vpn007.config._resolve_public_ips")
    def test_boolean_parsing(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "ENABLE_PORT_8443=true\n"
            "FORWARDING_ENABLED=yes\n"
            "REVERSE_INITIATED=0\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.enable_port_8443 is True
        assert config.forwarding_enabled is True
        assert config.reverse_initiated is False

    @patch("vpn007.config._resolve_public_ips")
    def test_enum_parsing(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "COVER_SITE_MODE=proxy\n"
            "TUNNEL_TYPE=ssh\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.cover_site_mode == CoverSiteMode.PROXY
        assert config.tunnel_type == TunnelType.SSH

    @patch("vpn007.config._resolve_public_ips")
    def test_missing_env_file_uses_defaults(self, mock_resolve: object, tmp_path: Path) -> None:
        ns = _make_namespace(
            env_file=str(tmp_path / "nonexistent.env"),
            domain="vpn.example.com",
        )
        config = load_config(ns)
        assert config.domain == "vpn.example.com"
        assert config.reality_sni == "www.microsoft.com"  # default

    @patch("vpn007.config._resolve_public_ips")
    def test_awg_obfuscation_from_env(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "AWG_S1=30\nAWG_S2=80\nAWG_S3=40\nAWG_S4=100\n"
            "AWG_H1=100\nAWG_H2=200\nAWG_H3=300\nAWG_H4=400\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.awg_obfuscation is not None
        assert config.awg_obfuscation.s1 == 30
        assert config.awg_obfuscation.h4 == 400

    @patch("vpn007.config._resolve_public_ips")
    def test_invalid_env_value_exits(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOMAIN=vpn.example.com\nXRAY_INTERNAL_PORT=not_a_number\n")
        ns = _make_namespace(env_file=str(env_file))
        with pytest.raises(SystemExit):
            load_config(ns)

    @patch("vpn007.config._resolve_public_ips")
    def test_tls_versions_parsing(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("DOMAIN=vpn.example.com\nTLS_VERSIONS=1.2,1.3\n")
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.tls_versions == ["1.2", "1.3"]

    @patch("vpn007.config._resolve_public_ips")
    def test_path_parsing(self, mock_resolve: object, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(
            "DOMAIN=vpn.example.com\n"
            "OUTPUT_DIR=/opt/deploy\n"
            "COVER_SITE_STATIC_PATH=/var/www/html\n"
        )
        ns = _make_namespace(env_file=str(env_file))
        config = load_config(ns)
        assert config.output_dir == Path("/opt/deploy")
        assert config.cover_site_static_path == Path("/var/www/html")


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------
# Feature: vpn007, Property 1: Config loading round-trip
# **Validates: Requirements 1.1, 1.3**

from hypothesis import given, assume, settings as h_settings
from hypothesis import strategies as st

from tests.conftest import (
    valid_awg_obfuscation,
    valid_domain,
    valid_port,
)
from vpn007.models import AwgObfuscation

# Re-derive IP and AS strategies with .map(str.strip) to avoid trailing
# newlines that from_regex can produce (the conftest strategies use ^...$
# anchors but not fullmatch=True).
_valid_ipv4 = st.from_regex(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
).map(str.strip)

_valid_as_number = st.integers(1, 4294967295).map(lambda n: f"AS{n}")


# ---------------------------------------------------------------------------
# Serialization helpers: convert Python values → .env file format
# ---------------------------------------------------------------------------

def _serialize_env_value(value: object) -> str | None:
    """Serialize a Python value to its .env file string representation.

    Returns None for values that should be omitted from the .env file.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        if not value:
            return None
        # Check if it's a list of PortForward objects
        if value and isinstance(value[0], PortForward):
            parts = []
            for pf in value:
                if pf.description:
                    parts.append(f"{pf.protocol}:{pf.listen_port}:{pf.forward_port}:{pf.description}")
                else:
                    parts.append(f"{pf.protocol}:{pf.listen_port}:{pf.forward_port}")
            return ",".join(parts)
        return ",".join(str(item) for item in value)
    if isinstance(value, CoverSiteMode):
        return value.value
    if isinstance(value, TunnelType):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return str(value)


def _awg_obfuscation_to_env_lines(awg: AwgObfuscation) -> str:
    """Serialize AwgObfuscation to individual AWG_* env var lines."""
    return (
        f"AWG_S1={awg.s1}\n"
        f"AWG_S2={awg.s2}\n"
        f"AWG_S3={awg.s3}\n"
        f"AWG_S4={awg.s4}\n"
        f"AWG_H1={awg.h1}\n"
        f"AWG_H2={awg.h2}\n"
        f"AWG_H3={awg.h3}\n"
        f"AWG_H4={awg.h4}\n"
        f"AWG_JC={awg.jc}\n"
        f"AWG_JMIN={awg.jmin}\n"
        f"AWG_JMAX={awg.jmax}\n"
        f"AWG_I1={awg.i1}\n"
        f"AWG_I2={awg.i2}\n"
        f"AWG_I3={awg.i3}\n"
        f"AWG_I4={awg.i4}\n"
        f"AWG_I5={awg.i5}\n"
    )


# ---------------------------------------------------------------------------
# Strategies for property tests
# ---------------------------------------------------------------------------

# Port forward descriptions must not contain colons or commas (they break parsing)
_safe_pf_description = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "Zs"),
        whitelist_characters="-_",
    ),
    min_size=0,
    max_size=30,
)

_safe_port_forward = st.builds(
    PortForward,
    protocol=st.sampled_from(["tcp", "udp"]),
    listen_port=valid_port,
    forward_port=valid_port,
    description=_safe_pf_description,
)

# Strategy for a subset of fields that round-trip cleanly through .env
_env_roundtrip_params = st.fixed_dictionaries(
    {
        "domain": valid_domain,
        "reality_sni": valid_domain,
        "xui_path_prefix": st.just("/secretpanel"),
        "awg_panel_path_prefix": st.just("/awgadmin"),
        "enable_port_8443": st.booleans(),
        "xray_internal_port": st.integers(1024, 65535),
        "awg_listen_port": valid_port,
        "awg_panel_port": valid_port,
        "public_ipv4": _valid_ipv4,
        "cover_site_mode": st.sampled_from(CoverSiteMode),
        "forwarding_enabled": st.booleans(),
        "reverse_initiated": st.booleans(),
        "hostname_resolve_interval_min": st.integers(1, 1440),
        "blocklist_update_interval_hours": st.integers(1, 168),
        "reconnect_initial_delay_sec": st.integers(1, 60),
        "reconnect_max_delay_sec": st.integers(60, 600),
    },
    optional={
        "cover_site_url": valid_domain.map(lambda d: f"https://{d}"),
        "tailscale_auth_key": st.text(
            alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_"),
            min_size=5,
            max_size=40,
        ),
        "incoming_ip": _valid_ipv4,
        "outgoing_ip": _valid_ipv4,
        "public_ipv6": st.just("2001:db8::1"),
        "secondary_vm_ip": _valid_ipv4,
        "tunnel_type": st.sampled_from(TunnelType),
    },
)

# Mapping from DeployConfig field name → env var name
_FIELD_TO_ENV_NAME: dict[str, str] = {
    "domain": "DOMAIN",
    "reality_sni": "REALITY_SNI",
    "cover_site_mode": "COVER_SITE_MODE",
    "cover_site_url": "COVER_SITE_URL",
    "cover_site_static_path": "COVER_SITE_STATIC_PATH",
    "xui_path_prefix": "XUI_PATH_PREFIX",
    "awg_panel_path_prefix": "AWG_PANEL_PATH_PREFIX",
    "enable_port_8443": "ENABLE_PORT_8443",
    "xray_internal_port": "XRAY_INTERNAL_PORT",
    "awg_listen_port": "AWG_LISTEN_PORT",
    "awg_panel_port": "AWG_PANEL_PORT",
    "tailscale_auth_key": "TAILSCALE_AUTH_KEY",
    "incoming_ip": "INCOMING_IP",
    "outgoing_ip": "OUTGOING_IP",
    "public_ipv4": "PUBLIC_IPV4",
    "public_ipv6": "PUBLIC_IPV6",
    "tls_versions": "TLS_VERSIONS",
    "approved_ips": "APPROVED_IPS",
    "approved_hostnames": "APPROVED_HOSTNAMES",
    "ssh_approved_ips": "SSH_APPROVED_IPS",
    "hostname_resolve_interval_min": "HOSTNAME_RESOLVE_INTERVAL_MIN",
    "blocked_as_numbers": "BLOCKED_AS_NUMBERS",
    "blocked_subnets": "BLOCKED_SUBNETS",
    "blocklist_update_interval_hours": "BLOCKLIST_UPDATE_INTERVAL_HOURS",
    "forwarding_enabled": "FORWARDING_ENABLED",
    "tunnel_type": "TUNNEL_TYPE",
    "secondary_vm_ip": "SECONDARY_VM_IP",
    "reverse_initiated": "REVERSE_INITIATED",
    "forwarding_ports": "FORWARDING_PORTS",
    "reconnect_initial_delay_sec": "RECONNECT_INITIAL_DELAY_SEC",
    "reconnect_max_delay_sec": "RECONNECT_MAX_DELAY_SEC",
    "output_dir": "OUTPUT_DIR",
    "deployment_log_path": "DEPLOYMENT_LOG_PATH",
}


def _write_params_to_env(
    env_path: Path,
    params: dict[str, object],
    awg_obfuscation: AwgObfuscation | None = None,
    extra_lists: dict[str, list[str]] | None = None,
    port_forwards: list[PortForward] | None = None,
) -> None:
    """Write a dict of field_name→value pairs to a .env file."""
    lines: list[str] = []
    for field_name, value in params.items():
        env_name = _FIELD_TO_ENV_NAME.get(field_name)
        if env_name is None:
            continue
        serialized = _serialize_env_value(value)
        if serialized is not None:
            lines.append(f"{env_name}={serialized}")

    if extra_lists:
        for field_name, items in extra_lists.items():
            env_name = _FIELD_TO_ENV_NAME.get(field_name)
            if env_name and items:
                lines.append(f"{env_name}={','.join(items)}")

    if port_forwards:
        serialized_pf = _serialize_env_value(port_forwards)
        if serialized_pf:
            lines.append(f"FORWARDING_PORTS={serialized_pf}")

    if awg_obfuscation is not None:
        lines.append(_awg_obfuscation_to_env_lines(awg_obfuscation).rstrip())

    env_path.write_text("\n".join(lines) + "\n")


class TestConfigLoadingRoundTrip:
    """Property 1: Config loading round-trip.

    For any valid deployment parameters written to a .env file, loading
    produces identical values; CLI args override .env values.

    **Validates: Requirements 1.1, 1.3**
    """

    @given(params=_env_roundtrip_params)
    @h_settings(max_examples=100)
    def test_env_roundtrip_scalar_fields(
        self,
        params: dict[str, object],
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        """For any valid scalar parameters written to .env, loading produces
        identical values."""
        tmp_path = tmp_path_factory.mktemp("env")
        env_file = tmp_path / ".env"
        _write_params_to_env(env_file, params)

        ns = _make_namespace(env_file=str(env_file))
        with patch("vpn007.config._resolve_public_ips"):
            config = load_config(ns)

        # Verify each parameter round-trips correctly
        for field_name, expected in params.items():
            actual = getattr(config, field_name)
            assert actual == expected, (
                f"Field {field_name!r}: expected {expected!r}, got {actual!r}"
            )

    @given(
        params=_env_roundtrip_params,
        approved_ips=st.lists(_valid_ipv4, min_size=0, max_size=3),
        blocked_as=st.lists(_valid_as_number, min_size=0, max_size=3),
        ssh_ips=st.lists(_valid_ipv4, min_size=0, max_size=3),
        tls_vers=st.just(["1.2", "1.3"]),
    )
    @h_settings(max_examples=100)
    def test_env_roundtrip_list_fields(
        self,
        params: dict[str, object],
        approved_ips: list[str],
        blocked_as: list[str],
        ssh_ips: list[str],
        tls_vers: list[str],
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        """For any valid list parameters written to .env, loading produces
        identical list values."""
        tmp_path = tmp_path_factory.mktemp("env")
        env_file = tmp_path / ".env"

        extra_lists = {
            "approved_ips": approved_ips,
            "blocked_as_numbers": blocked_as,
            "ssh_approved_ips": ssh_ips,
            "tls_versions": tls_vers,
        }
        _write_params_to_env(env_file, params, extra_lists=extra_lists)

        ns = _make_namespace(env_file=str(env_file))
        with patch("vpn007.config._resolve_public_ips"):
            config = load_config(ns)

        # Verify list fields
        if approved_ips:
            assert config.approved_ips == approved_ips
        if blocked_as:
            assert config.blocked_as_numbers == blocked_as
        if ssh_ips:
            assert config.ssh_approved_ips == ssh_ips
        assert config.tls_versions == tls_vers

    @given(
        params=_env_roundtrip_params,
        port_forwards=st.lists(_safe_port_forward, min_size=1, max_size=3),
    )
    @h_settings(max_examples=100)
    def test_env_roundtrip_port_forwards(
        self,
        params: dict[str, object],
        port_forwards: list[PortForward],
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        """For any valid port forwards written to .env, loading produces
        identical PortForward objects."""
        # Descriptions with colons/commas break the format — filter them out
        for pf in port_forwards:
            assume(":" not in pf.description and "," not in pf.description)

        tmp_path = tmp_path_factory.mktemp("env")
        env_file = tmp_path / ".env"
        _write_params_to_env(env_file, params, port_forwards=port_forwards)

        ns = _make_namespace(env_file=str(env_file))
        with patch("vpn007.config._resolve_public_ips"):
            config = load_config(ns)

        assert len(config.forwarding_ports) == len(port_forwards)
        for actual, expected in zip(config.forwarding_ports, port_forwards):
            assert actual.protocol == expected.protocol
            assert actual.listen_port == expected.listen_port
            assert actual.forward_port == expected.forward_port
            # Description is stripped during parsing
            assert actual.description == expected.description.strip()

    @given(
        params=_env_roundtrip_params,
        awg=valid_awg_obfuscation,
    )
    @h_settings(max_examples=100)
    def test_env_roundtrip_awg_obfuscation(
        self,
        params: dict[str, object],
        awg: AwgObfuscation,
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        """For any valid AWG obfuscation params written to .env, loading
        produces identical AwgObfuscation."""
        tmp_path = tmp_path_factory.mktemp("env")
        env_file = tmp_path / ".env"
        _write_params_to_env(env_file, params, awg_obfuscation=awg)

        ns = _make_namespace(env_file=str(env_file))
        with patch("vpn007.config._resolve_public_ips"):
            config = load_config(ns)

        assert config.awg_obfuscation is not None
        assert config.awg_obfuscation.s1 == awg.s1
        assert config.awg_obfuscation.s2 == awg.s2
        assert config.awg_obfuscation.s3 == awg.s3
        assert config.awg_obfuscation.s4 == awg.s4
        assert config.awg_obfuscation.h1 == awg.h1
        assert config.awg_obfuscation.h2 == awg.h2
        assert config.awg_obfuscation.h3 == awg.h3
        assert config.awg_obfuscation.h4 == awg.h4
        assert config.awg_obfuscation.jc == awg.jc
        assert config.awg_obfuscation.jmin == awg.jmin
        assert config.awg_obfuscation.jmax == awg.jmax
        assert config.awg_obfuscation.i1 == awg.i1
        assert config.awg_obfuscation.i2 == awg.i2
        assert config.awg_obfuscation.i3 == awg.i3
        assert config.awg_obfuscation.i4 == awg.i4
        assert config.awg_obfuscation.i5 == awg.i5

    @given(
        env_domain=valid_domain,
        cli_domain=valid_domain,
        env_port=valid_port,
        cli_port=valid_port,
        env_sni=valid_domain,
        cli_sni=valid_domain,
    )
    @h_settings(max_examples=100)
    def test_cli_overrides_env_values(
        self,
        env_domain: str,
        cli_domain: str,
        env_port: int,
        cli_port: int,
        env_sni: str,
        cli_sni: str,
        tmp_path_factory: pytest.TempPathFactory,
    ) -> None:
        """For any parameter present in both .env and CLI args, the CLI value
        takes precedence."""
        # Ensure CLI and env values differ so we can verify override
        assume(env_domain != cli_domain)
        assume(env_port != cli_port)
        assume(env_sni != cli_sni)

        tmp_path = tmp_path_factory.mktemp("env")
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"DOMAIN={env_domain}\n"
            f"AWG_LISTEN_PORT={env_port}\n"
            f"REALITY_SNI={env_sni}\n"
            f"PUBLIC_IPV4=203.0.113.1\n"
        )

        ns = _make_namespace(
            env_file=str(env_file),
            domain=cli_domain,
            awg_listen_port=cli_port,
            reality_sni=cli_sni,
        )
        with patch("vpn007.config._resolve_public_ips"):
            config = load_config(ns)

        # CLI values must win
        assert config.domain == cli_domain
        assert config.awg_listen_port == cli_port
        assert config.reality_sni == cli_sni
