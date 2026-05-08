# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.validator — parameter validation logic."""

from __future__ import annotations

import copy

import pytest
from hypothesis import given, assume, settings as h_settings
from hypothesis import strategies as st

from vpn007.models import AwgObfuscation, DeployConfig, PortForward, TunnelType
from vpn007.validator import validate_config

from tests.conftest import (
    valid_awg_obfuscation,
    valid_deploy_config,
    valid_domain,
    valid_ipv4,
    valid_port,
    valid_as_number,
    valid_cidr,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _config(**overrides: object) -> DeployConfig:
    """Create a DeployConfig with sensible defaults, applying *overrides*."""
    defaults: dict[str, object] = {"domain": "vpn.example.com"}
    defaults.update(overrides)
    return DeployConfig(**defaults)  # type: ignore[arg-type]


def _valid_awg() -> AwgObfuscation:
    """Return a valid AwgObfuscation instance."""
    return AwgObfuscation(
        s1=30, s2=80, s3=40, s4=20,
        h1=100, h2=200, h3=300, h4=400,
        jc=4, jmin=50, jmax=1000,
        i1="", i2="", i3="", i4="", i5="",
    )


# ---------------------------------------------------------------------------
# Valid configs produce no errors
# ---------------------------------------------------------------------------


class TestValidConfig:
    def test_minimal_valid_config(self) -> None:
        errors = validate_config(_config())
        assert errors == []

    def test_full_valid_config(self) -> None:
        cfg = _config(
            reality_sni="www.microsoft.com",
            incoming_ip="203.0.113.10",
            outgoing_ip="203.0.113.20",
            public_ipv4="203.0.113.10",
            public_ipv6="2001:db8::1",
            awg_listen_port=34567,
            awg_obfuscation=_valid_awg(),
            blocked_as_numbers=["AS196747", "AS12345"],
            blocked_subnets=["198.51.100.0/24", "2001:db8::/32"],
            approved_ips=["10.0.0.1", "192.168.1.0/24"],
            ssh_approved_ips=["192.168.1.100"],
            forwarding_enabled=True,
            tunnel_type=TunnelType.WIREGUARD,
            secondary_vm_ip="10.0.0.2",
            forwarding_ports=[
                PortForward(protocol="tcp", listen_port=443, forward_port=443),
            ],
        )
        errors = validate_config(cfg)
        assert errors == []

    def test_awg_listen_port_none_is_valid(self) -> None:
        """awg_listen_port=None means auto-randomize — should not error."""
        cfg = _config(awg_listen_port=None)
        errors = validate_config(cfg)
        assert errors == []


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------


class TestDomainValidation:
    def test_single_label_rejected(self) -> None:
        errors = validate_config(_config(domain="localhost"))
        assert any("at least 2 labels" in e for e in errors)

    def test_empty_domain_rejected(self) -> None:
        errors = validate_config(_config(domain=""))
        assert any("domain" in e.lower() for e in errors)

    def test_label_starting_with_hyphen(self) -> None:
        errors = validate_config(_config(domain="-bad.example.com"))
        assert any("bad label" in e.lower() for e in errors)

    def test_label_ending_with_hyphen(self) -> None:
        errors = validate_config(_config(domain="bad-.example.com"))
        assert any("bad label" in e.lower() for e in errors)

    def test_label_too_long(self) -> None:
        long_label = "a" * 64
        errors = validate_config(_config(domain=f"{long_label}.example.com"))
        assert any("63 chars" in e for e in errors)

    def test_empty_label_in_domain(self) -> None:
        errors = validate_config(_config(domain="vpn..example.com"))
        assert any("empty label" in e.lower() for e in errors)

    def test_valid_subdomain(self) -> None:
        errors = validate_config(_config(domain="sub.vpn.example.com"))
        assert errors == []

    def test_hyphen_in_middle_is_valid(self) -> None:
        errors = validate_config(_config(domain="my-vpn.example.com"))
        assert errors == []

    def test_numeric_label_is_valid(self) -> None:
        errors = validate_config(_config(domain="123.example.com"))
        assert errors == []

    def test_special_chars_rejected(self) -> None:
        errors = validate_config(_config(domain="vpn_server.example.com"))
        assert any("bad label" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# IP address validation
# ---------------------------------------------------------------------------


class TestIPValidation:
    def test_invalid_incoming_ip(self) -> None:
        errors = validate_config(_config(incoming_ip="not-an-ip"))
        assert any("incoming_ip" in e for e in errors)

    def test_invalid_outgoing_ip(self) -> None:
        errors = validate_config(_config(outgoing_ip="999.999.999.999"))
        assert any("outgoing_ip" in e for e in errors)

    def test_invalid_public_ipv4(self) -> None:
        errors = validate_config(_config(public_ipv4="abc"))
        assert any("public_ipv4" in e for e in errors)

    def test_invalid_public_ipv6(self) -> None:
        errors = validate_config(_config(public_ipv6="not-ipv6"))
        assert any("public_ipv6" in e for e in errors)

    def test_invalid_secondary_vm_ip(self) -> None:
        errors = validate_config(_config(
            forwarding_enabled=True,
            tunnel_type=TunnelType.SSH,
            secondary_vm_ip="bad-ip",
        ))
        assert any("secondary_vm_ip" in e for e in errors)

    def test_valid_ipv4_addresses(self) -> None:
        cfg = _config(
            incoming_ip="10.0.0.1",
            outgoing_ip="192.168.1.1",
            public_ipv4="203.0.113.5",
        )
        errors = validate_config(cfg)
        assert not any("ip" in e.lower() and "invalid" in e.lower() for e in errors)

    def test_valid_ipv6_address(self) -> None:
        cfg = _config(public_ipv6="2001:db8::1")
        errors = validate_config(cfg)
        assert errors == []


# ---------------------------------------------------------------------------
# CIDR subnet validation
# ---------------------------------------------------------------------------


class TestCIDRValidation:
    def test_invalid_cidr_subnet(self) -> None:
        errors = validate_config(_config(blocked_subnets=["not-a-cidr"]))
        assert any("CIDR" in e for e in errors)

    def test_invalid_cidr_prefix_length(self) -> None:
        errors = validate_config(_config(blocked_subnets=["10.0.0.0/33"]))
        assert any("CIDR" in e for e in errors)

    def test_valid_ipv4_cidr(self) -> None:
        errors = validate_config(_config(blocked_subnets=["198.51.100.0/24"]))
        assert errors == []

    def test_valid_ipv6_cidr(self) -> None:
        errors = validate_config(_config(blocked_subnets=["2001:db8::/32"]))
        assert errors == []

    def test_bare_ip_not_valid_cidr(self) -> None:
        """A bare IP without /prefix is not a valid CIDR."""
        errors = validate_config(_config(blocked_subnets=["10.0.0.1"]))
        assert any("CIDR" in e for e in errors)

    def test_invalid_approved_ip(self) -> None:
        errors = validate_config(_config(approved_ips=["not-valid"]))
        assert any("approved_ips" in e for e in errors)

    def test_approved_ips_accepts_cidr(self) -> None:
        errors = validate_config(_config(approved_ips=["192.168.1.0/24"]))
        assert errors == []

    def test_invalid_ssh_approved_ip(self) -> None:
        errors = validate_config(_config(ssh_approved_ips=["garbage"]))
        assert any("ssh_approved_ips" in e for e in errors)


# ---------------------------------------------------------------------------
# Port number validation
# ---------------------------------------------------------------------------


class TestPortValidation:
    def test_port_zero_rejected(self) -> None:
        errors = validate_config(_config(xray_internal_port=0))
        assert any("xray_internal_port" in e for e in errors)

    def test_port_negative_rejected(self) -> None:
        errors = validate_config(_config(awg_panel_port=-1))
        assert any("awg_panel_port" in e for e in errors)

    def test_port_too_high_rejected(self) -> None:
        errors = validate_config(_config(xray_internal_port=65536))
        assert any("xray_internal_port" in e for e in errors)

    def test_valid_port_boundaries(self) -> None:
        cfg = _config(xray_internal_port=1, awg_panel_port=65535)
        errors = validate_config(cfg)
        assert not any("port" in e.lower() for e in errors)

    def test_forwarding_port_invalid(self) -> None:
        cfg = _config(
            forwarding_ports=[
                PortForward(protocol="tcp", listen_port=0, forward_port=443),
            ],
        )
        errors = validate_config(cfg)
        assert any("forwarding_ports[0].listen_port" in e for e in errors)

    def test_forwarding_forward_port_invalid(self) -> None:
        cfg = _config(
            forwarding_ports=[
                PortForward(protocol="tcp", listen_port=443, forward_port=70000),
            ],
        )
        errors = validate_config(cfg)
        assert any("forwarding_ports[0].forward_port" in e for e in errors)


# ---------------------------------------------------------------------------
# AS number validation
# ---------------------------------------------------------------------------


class TestASNumberValidation:
    def test_valid_as_numbers(self) -> None:
        errors = validate_config(_config(blocked_as_numbers=["AS196747", "AS1"]))
        assert errors == []

    def test_missing_as_prefix(self) -> None:
        errors = validate_config(_config(blocked_as_numbers=["196747"]))
        assert any("AS number" in e for e in errors)

    def test_lowercase_as_rejected(self) -> None:
        errors = validate_config(_config(blocked_as_numbers=["as196747"]))
        assert any("AS number" in e for e in errors)

    def test_as_with_non_digits(self) -> None:
        errors = validate_config(_config(blocked_as_numbers=["ASabc"]))
        assert any("AS number" in e for e in errors)

    def test_empty_as_rejected(self) -> None:
        errors = validate_config(_config(blocked_as_numbers=["AS"]))
        assert any("AS number" in e for e in errors)


# ---------------------------------------------------------------------------
# Path prefix validation
# ---------------------------------------------------------------------------


class TestPathPrefixValidation:
    def test_missing_leading_slash_xui(self) -> None:
        errors = validate_config(_config(xui_path_prefix="noslash"))
        assert any("xui_path_prefix" in e for e in errors)

    def test_missing_leading_slash_awg(self) -> None:
        errors = validate_config(_config(awg_panel_path_prefix="noslash"))
        assert any("awg_panel_path_prefix" in e for e in errors)

    def test_valid_path_prefixes(self) -> None:
        cfg = _config(xui_path_prefix="/panel", awg_panel_path_prefix="/awg")
        errors = validate_config(cfg)
        assert not any("path prefix" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# AWG obfuscation parameter validation
# ---------------------------------------------------------------------------


class TestAwgObfuscationValidation:
    def test_valid_obfuscation(self) -> None:
        errors = validate_config(_config(awg_obfuscation=_valid_awg()))
        assert errors == []

    def test_s1_below_range(self) -> None:
        obf = _valid_awg()
        obf.s1 = -1
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("S1" in e and "0-1132" in e for e in errors)

    def test_s2_above_range(self) -> None:
        obf = _valid_awg()
        obf.s2 = 1189
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("S2" in e and "0-1188" in e for e in errors)

    def test_s1_plus_56_equals_s2(self) -> None:
        obf = _valid_awg()
        obf.s1 = 20
        obf.s2 = 76  # 20 + 56 = 76
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("S1+56" in e for e in errors)

    def test_s2_plus_56_equals_s1(self) -> None:
        obf = _valid_awg()
        obf.s2 = 20
        obf.s1 = 76  # 20 + 56 = 76
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("S2+56" in e for e in errors)

    def test_s4_above_range(self) -> None:
        obf = _valid_awg()
        obf.s4 = 33
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("S4" in e and "0-32" in e for e in errors)

    def test_h_below_range(self) -> None:
        obf = _valid_awg()
        obf.h1 = 4
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("H1" in e and "5-2147483647" in e for e in errors)

    def test_h_values_must_not_overlap(self) -> None:
        obf = _valid_awg()
        obf.h1 = 100
        obf.h2 = 100  # same as h1
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("H1" in e and "H2" in e and "overlap" in e for e in errors)

    def test_jc_below_range(self) -> None:
        obf = _valid_awg()
        obf.jc = 0
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("Jc" in e and "1-128" in e for e in errors)

    def test_jc_above_range(self) -> None:
        obf = _valid_awg()
        obf.jc = 129
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("Jc" in e and "1-128" in e for e in errors)

    def test_jmin_greater_than_jmax(self) -> None:
        obf = _valid_awg()
        obf.jmin = 500
        obf.jmax = 100
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("Jmin" in e and "Jmax" in e for e in errors)

    def test_jmax_above_1280(self) -> None:
        obf = _valid_awg()
        obf.jmax = 1281
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("Jmax" in e and "1280" in e for e in errors)

    def test_jmin_below_0(self) -> None:
        obf = _valid_awg()
        obf.jmin = -1
        errors = validate_config(_config(awg_obfuscation=obf))
        assert any("Jmin" in e and ">= 0" in e for e in errors)

    def test_none_obfuscation_is_valid(self) -> None:
        errors = validate_config(_config(awg_obfuscation=None))
        assert errors == []


# ---------------------------------------------------------------------------
# Forwarding config consistency
# ---------------------------------------------------------------------------


class TestForwardingConsistency:
    def test_forwarding_without_tunnel_type(self) -> None:
        cfg = _config(
            forwarding_enabled=True,
            tunnel_type=None,
            secondary_vm_ip="10.0.0.2",
        )
        errors = validate_config(cfg)
        assert any("tunnel_type" in e for e in errors)

    def test_forwarding_without_secondary_ip(self) -> None:
        cfg = _config(
            forwarding_enabled=True,
            tunnel_type=TunnelType.SSH,
            secondary_vm_ip=None,
        )
        errors = validate_config(cfg)
        assert any("secondary_vm_ip" in e for e in errors)

    def test_forwarding_missing_both(self) -> None:
        cfg = _config(
            forwarding_enabled=True,
            tunnel_type=None,
            secondary_vm_ip=None,
        )
        errors = validate_config(cfg)
        assert any("tunnel_type" in e for e in errors)
        assert any("secondary_vm_ip" in e for e in errors)

    def test_forwarding_disabled_no_checks(self) -> None:
        """When forwarding is disabled, tunnel_type and secondary_vm_ip are not required."""
        cfg = _config(
            forwarding_enabled=False,
            tunnel_type=None,
            secondary_vm_ip=None,
        )
        errors = validate_config(cfg)
        assert errors == []

    def test_valid_forwarding_config(self) -> None:
        cfg = _config(
            forwarding_enabled=True,
            tunnel_type=TunnelType.WIREGUARD,
            secondary_vm_ip="10.0.0.2",
            forwarding_ports=[PortForward(protocol="tcp", listen_port=443, forward_port=443, description="HTTPS")],
        )
        errors = validate_config(cfg)
        assert errors == []


# ---------------------------------------------------------------------------
# Missing required parameters
# ---------------------------------------------------------------------------


class TestMissingRequired:
    def test_empty_domain_reports_missing(self) -> None:
        errors = validate_config(_config(domain=""))
        assert any("domain" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Multiple errors collected
# ---------------------------------------------------------------------------


class TestMultipleErrors:
    def test_collects_all_errors(self) -> None:
        """Validator should report ALL errors, not stop at the first."""
        cfg = _config(
            domain="",
            incoming_ip="bad-ip",
            xray_internal_port=0,
            blocked_as_numbers=["INVALID"],
            xui_path_prefix="noslash",
        )
        errors = validate_config(cfg)
        # Should have at least 4 distinct errors
        assert len(errors) >= 4


# ---------------------------------------------------------------------------
# Property-based tests (Hypothesis)
# ---------------------------------------------------------------------------
# Feature: vpn007, Property 2: Config validation rejects invalid input
# **Validates: Requirements 1.5, 1.6, 9.4, 10.2**


# ---------------------------------------------------------------------------
# Strategies for generating invalid values
# ---------------------------------------------------------------------------

# Invalid IP addresses — strings that are definitely not valid IPs
_invalid_ip = st.one_of(
    st.just("not-an-ip"),
    st.just("999.999.999.999"),
    st.just("abc.def.ghi.jkl"),
    st.just("256.1.1.1"),
    st.just("1.2.3.4.5"),
    st.just(""),
    st.just("::gggg"),
    st.text(
        alphabet=st.characters(whitelist_categories=("L",)),
        min_size=3,
        max_size=15,
    ).filter(lambda s: not s.replace(".", "").isdigit()),
)

# Invalid CIDR subnets
_invalid_cidr = st.one_of(
    st.just("not-a-cidr"),
    st.just("10.0.0.0/33"),
    st.just("10.0.0.1"),  # bare IP, no prefix
    st.just("garbage/24"),
    st.just("/24"),
)

# Invalid AS numbers — missing prefix, lowercase, non-digits
_invalid_as_number = st.one_of(
    st.just("196747"),       # missing AS prefix
    st.just("as196747"),     # lowercase
    st.just("ASabc"),        # non-digits
    st.just("AS"),           # no digits
    st.just(""),
    st.just("BOGUS12345"),
)

# Invalid port numbers — outside 1-65535
_invalid_port = st.one_of(
    st.integers(max_value=0),
    st.integers(min_value=65536, max_value=200000),
)

# Invalid domain names
_invalid_domain = st.one_of(
    st.just(""),
    st.just("localhost"),           # single label
    st.just("-bad.example.com"),    # starts with hyphen
    st.just("bad-.example.com"),    # ends with hyphen
    st.just("vpn..example.com"),    # empty label
    st.just("a" * 64 + ".com"),    # label > 63 chars
    st.just("under_score.com"),    # underscore
)

# Path prefixes that don't start with /
_invalid_path_prefix = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="-_"),
    min_size=1,
    max_size=30,
).filter(lambda s: not s.startswith("/"))


class TestProperty2ValidConfigAccepted:
    """Property 2 baseline: any valid DeployConfig passes validation."""

    @given(config=valid_deploy_config)
    @h_settings(max_examples=100)
    def test_valid_config_produces_no_errors(self, config: DeployConfig) -> None:
        """For any valid DeployConfig generated by our strategy, the validator
        returns an empty error list."""
        errors = validate_config(config)
        assert errors == [], f"Unexpected errors for valid config: {errors}"


class TestProperty2MissingRequiredParameter:
    """Property 2: For any missing required parameter, the validator returns
    an error naming that parameter.

    **Validates: Requirements 1.5**
    """

    @given(config=valid_deploy_config)
    @h_settings(max_examples=100)
    def test_empty_domain_reports_missing(self, config: DeployConfig) -> None:
        """When domain is empty, validator reports 'domain' in the error."""
        config.domain = ""
        errors = validate_config(config)
        assert any("domain" in e.lower() for e in errors), (
            f"Expected error mentioning 'domain', got: {errors}"
        )

    @given(config=valid_deploy_config)
    @h_settings(max_examples=100)
    def test_forwarding_without_tunnel_type_names_parameter(
        self, config: DeployConfig
    ) -> None:
        """When forwarding is enabled but tunnel_type is None, validator
        reports 'tunnel_type' in the error."""
        config.forwarding_enabled = True
        config.tunnel_type = None
        config.secondary_vm_ip = "10.0.0.2"
        errors = validate_config(config)
        assert any("tunnel_type" in e for e in errors), (
            f"Expected error mentioning 'tunnel_type', got: {errors}"
        )

    @given(config=valid_deploy_config)
    @h_settings(max_examples=100)
    def test_forwarding_without_secondary_ip_names_parameter(
        self, config: DeployConfig
    ) -> None:
        """When forwarding is enabled but secondary_vm_ip is None, validator
        reports 'secondary_vm_ip' in the error."""
        config.forwarding_enabled = True
        config.tunnel_type = TunnelType.WIREGUARD
        config.secondary_vm_ip = None
        errors = validate_config(config)
        assert any("secondary_vm_ip" in e for e in errors), (
            f"Expected error mentioning 'secondary_vm_ip', got: {errors}"
        )


class TestProperty2InvalidIPAddresses:
    """Property 2: For any invalid IP address value, validator rejects with
    a descriptive message naming the field.

    **Validates: Requirements 1.6, 9.4**
    """

    @given(config=valid_deploy_config, bad_ip=_invalid_ip)
    @h_settings(max_examples=100)
    def test_invalid_incoming_ip_rejected(
        self, config: DeployConfig, bad_ip: str
    ) -> None:
        config.incoming_ip = bad_ip
        errors = validate_config(config)
        assert any("incoming_ip" in e for e in errors), (
            f"Expected error for incoming_ip={bad_ip!r}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_ip=_invalid_ip)
    @h_settings(max_examples=100)
    def test_invalid_outgoing_ip_rejected(
        self, config: DeployConfig, bad_ip: str
    ) -> None:
        config.outgoing_ip = bad_ip
        errors = validate_config(config)
        assert any("outgoing_ip" in e for e in errors), (
            f"Expected error for outgoing_ip={bad_ip!r}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_ip=_invalid_ip)
    @h_settings(max_examples=100)
    def test_invalid_public_ipv4_rejected(
        self, config: DeployConfig, bad_ip: str
    ) -> None:
        config.public_ipv4 = bad_ip
        errors = validate_config(config)
        assert any("public_ipv4" in e for e in errors), (
            f"Expected error for public_ipv4={bad_ip!r}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_ip=_invalid_ip)
    @h_settings(max_examples=100)
    def test_invalid_public_ipv6_rejected(
        self, config: DeployConfig, bad_ip: str
    ) -> None:
        config.public_ipv6 = bad_ip
        errors = validate_config(config)
        assert any("public_ipv6" in e for e in errors), (
            f"Expected error for public_ipv6={bad_ip!r}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_ip=_invalid_ip)
    @h_settings(max_examples=100)
    def test_invalid_secondary_vm_ip_rejected(
        self, config: DeployConfig, bad_ip: str
    ) -> None:
        config.forwarding_enabled = True
        config.tunnel_type = TunnelType.SSH
        config.secondary_vm_ip = bad_ip
        errors = validate_config(config)
        assert any("secondary_vm_ip" in e for e in errors), (
            f"Expected error for secondary_vm_ip={bad_ip!r}, got: {errors}"
        )


class TestProperty2InvalidCIDRSubnets:
    """Property 2: For any invalid CIDR subnet, validator rejects with
    a descriptive message.

    **Validates: Requirements 1.6**
    """

    @given(config=valid_deploy_config, bad_cidr=_invalid_cidr)
    @h_settings(max_examples=100)
    def test_invalid_blocked_subnet_rejected(
        self, config: DeployConfig, bad_cidr: str
    ) -> None:
        config.blocked_subnets = [bad_cidr]
        errors = validate_config(config)
        assert any("CIDR" in e or "subnet" in e.lower() for e in errors), (
            f"Expected CIDR error for {bad_cidr!r}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        bad_entry=_invalid_ip.filter(lambda s: s != ""),
    )
    @h_settings(max_examples=100)
    def test_invalid_approved_ip_rejected(
        self, config: DeployConfig, bad_entry: str
    ) -> None:
        config.approved_ips = [bad_entry]
        errors = validate_config(config)
        assert any("approved_ips" in e for e in errors), (
            f"Expected error for approved_ips entry {bad_entry!r}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        bad_entry=_invalid_ip.filter(lambda s: s != ""),
    )
    @h_settings(max_examples=100)
    def test_invalid_ssh_approved_ip_rejected(
        self, config: DeployConfig, bad_entry: str
    ) -> None:
        config.ssh_approved_ips = [bad_entry]
        errors = validate_config(config)
        assert any("ssh_approved_ips" in e for e in errors), (
            f"Expected error for ssh_approved_ips entry {bad_entry!r}, got: {errors}"
        )


class TestProperty2InvalidPortNumbers:
    """Property 2: For any invalid port number, validator rejects with
    a descriptive message naming the field.

    **Validates: Requirements 1.6**
    """

    @given(config=valid_deploy_config, bad_port=_invalid_port)
    @h_settings(max_examples=100)
    def test_invalid_xray_port_rejected(
        self, config: DeployConfig, bad_port: int
    ) -> None:
        config.xray_internal_port = bad_port
        errors = validate_config(config)
        assert any("xray_internal_port" in e for e in errors), (
            f"Expected error for xray_internal_port={bad_port}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_port=_invalid_port)
    @h_settings(max_examples=100)
    def test_invalid_awg_panel_port_rejected(
        self, config: DeployConfig, bad_port: int
    ) -> None:
        config.awg_panel_port = bad_port
        errors = validate_config(config)
        assert any("awg_panel_port" in e for e in errors), (
            f"Expected error for awg_panel_port={bad_port}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_port=_invalid_port)
    @h_settings(max_examples=100)
    def test_invalid_awg_listen_port_rejected(
        self, config: DeployConfig, bad_port: int
    ) -> None:
        config.awg_listen_port = bad_port
        errors = validate_config(config)
        assert any("awg_listen_port" in e for e in errors), (
            f"Expected error for awg_listen_port={bad_port}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        bad_listen=_invalid_port,
        bad_forward=_invalid_port,
    )
    @h_settings(max_examples=100)
    def test_invalid_forwarding_ports_rejected(
        self, config: DeployConfig, bad_listen: int, bad_forward: int
    ) -> None:
        config.forwarding_ports = [
            PortForward(protocol="tcp", listen_port=bad_listen, forward_port=bad_forward)
        ]
        errors = validate_config(config)
        assert any("forwarding_ports" in e for e in errors), (
            f"Expected error for forwarding_ports listen={bad_listen} "
            f"forward={bad_forward}, got: {errors}"
        )


class TestProperty2InvalidASNumbers:
    """Property 2: For any invalid AS number format, validator rejects with
    a descriptive message.

    **Validates: Requirements 1.6**
    """

    @given(config=valid_deploy_config, bad_asn=_invalid_as_number)
    @h_settings(max_examples=100)
    def test_invalid_as_number_rejected(
        self, config: DeployConfig, bad_asn: str
    ) -> None:
        config.blocked_as_numbers = [bad_asn]
        errors = validate_config(config)
        assert any("AS number" in e for e in errors), (
            f"Expected AS number error for {bad_asn!r}, got: {errors}"
        )


class TestProperty2InvalidDomains:
    """Property 2: For any invalid domain format, validator rejects with
    a descriptive message.

    **Validates: Requirements 1.6**
    """

    @given(config=valid_deploy_config, bad_domain=_invalid_domain)
    @h_settings(max_examples=100)
    def test_invalid_domain_rejected(
        self, config: DeployConfig, bad_domain: str
    ) -> None:
        config.domain = bad_domain
        errors = validate_config(config)
        assert any("domain" in e.lower() for e in errors), (
            f"Expected domain error for {bad_domain!r}, got: {errors}"
        )


class TestProperty2InvalidPathPrefixes:
    """Property 2: For any path prefix not starting with '/', validator
    rejects with a descriptive message.

    **Validates: Requirements 1.6**
    """

    @given(config=valid_deploy_config, bad_prefix=_invalid_path_prefix)
    @h_settings(max_examples=100)
    def test_invalid_xui_path_prefix_rejected(
        self, config: DeployConfig, bad_prefix: str
    ) -> None:
        config.xui_path_prefix = bad_prefix
        errors = validate_config(config)
        assert any("xui_path_prefix" in e for e in errors), (
            f"Expected error for xui_path_prefix={bad_prefix!r}, got: {errors}"
        )

    @given(config=valid_deploy_config, bad_prefix=_invalid_path_prefix)
    @h_settings(max_examples=100)
    def test_invalid_awg_panel_path_prefix_rejected(
        self, config: DeployConfig, bad_prefix: str
    ) -> None:
        config.awg_panel_path_prefix = bad_prefix
        errors = validate_config(config)
        assert any("awg_panel_path_prefix" in e for e in errors), (
            f"Expected error for awg_panel_path_prefix={bad_prefix!r}, got: {errors}"
        )


class TestProperty2InvalidAwgObfuscation:
    """Property 2: For any AWG obfuscation parameter outside valid ranges,
    validator rejects with a descriptive message.

    **Validates: Requirements 10.2**
    """

    @given(
        config=valid_deploy_config,
        s_val=st.one_of(st.integers(max_value=-1), st.integers(min_value=1133, max_value=5000)),
    )
    @h_settings(max_examples=100)
    def test_s_param_out_of_range_rejected(
        self, config: DeployConfig, s_val: int
    ) -> None:
        """S1 must be 0-1132; any value outside is rejected."""
        obf = _valid_awg()
        obf.s1 = s_val
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("S1" in e and "0-1132" in e for e in errors), (
            f"Expected S1 range error for {s_val}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        h_val=st.one_of(st.integers(max_value=4), st.integers(min_value=2147483648, max_value=2147483700)),
    )
    @h_settings(max_examples=100)
    def test_h_param_out_of_range_rejected(
        self, config: DeployConfig, h_val: int
    ) -> None:
        """H1-H4 must be 5-2147483647; any value outside is rejected."""
        obf = _valid_awg()
        obf.h1 = h_val
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("H1" in e and "5-2147483647" in e for e in errors), (
            f"Expected H1 range error for {h_val}, got: {errors}"
        )

    @given(config=valid_deploy_config)
    @h_settings(max_examples=50)
    def test_s1_plus_56_equals_s2_rejected(self, config: DeployConfig) -> None:
        """The bidirectional constraint S1+56 != S2 must be enforced."""
        obf = _valid_awg()
        obf.s1 = 20
        obf.s2 = 76  # 20 + 56 = 76
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("S1+56" in e for e in errors), (
            f"Expected S1+56 constraint error, got: {errors}"
        )

    @given(config=valid_deploy_config)
    @h_settings(max_examples=50)
    def test_s4_above_range_rejected(self, config: DeployConfig) -> None:
        """S4 must be 0-32; values above 32 are rejected."""
        obf = _valid_awg()
        obf.s4 = 33
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("S4" in e and "0-32" in e for e in errors), (
            f"Expected S4 range error for 33, got: {errors}"
        )

    @given(config=valid_deploy_config)
    @h_settings(max_examples=50)
    def test_h_values_overlap_rejected(self, config: DeployConfig) -> None:
        """H1-H4 must be non-overlapping (distinct values)."""
        obf = _valid_awg()
        obf.h1 = 42
        obf.h2 = 42  # same as h1
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("overlap" in e.lower() for e in errors), (
            f"Expected H overlap error, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        jc_val=st.one_of(st.integers(max_value=0), st.integers(min_value=129, max_value=500)),
    )
    @h_settings(max_examples=100)
    def test_jc_out_of_range_rejected(
        self, config: DeployConfig, jc_val: int
    ) -> None:
        """Jc must be 1-128; any value outside is rejected."""
        obf = _valid_awg()
        obf.jc = jc_val
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("Jc" in e and "1-128" in e for e in errors), (
            f"Expected Jc range error for {jc_val}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        jmin=st.integers(min_value=100, max_value=1280),
        jmax=st.integers(min_value=1, max_value=99),
    )
    @h_settings(max_examples=100)
    def test_jmin_greater_than_jmax_rejected(
        self, config: DeployConfig, jmin: int, jmax: int
    ) -> None:
        """Jmin must be <= Jmax."""
        assume(jmin > jmax)
        obf = _valid_awg()
        obf.jmin = jmin
        obf.jmax = jmax
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("Jmin" in e and "Jmax" in e for e in errors), (
            f"Expected Jmin/Jmax error for jmin={jmin} jmax={jmax}, got: {errors}"
        )

    @given(
        config=valid_deploy_config,
        jmax=st.integers(min_value=1281, max_value=5000),
    )
    @h_settings(max_examples=100)
    def test_jmax_above_1280_rejected(
        self, config: DeployConfig, jmax: int
    ) -> None:
        """Jmax must be <= 1280."""
        obf = _valid_awg()
        obf.jmax = jmax
        config.awg_obfuscation = obf
        errors = validate_config(config)
        assert any("Jmax" in e and "1280" in e for e in errors), (
            f"Expected Jmax range error for {jmax}, got: {errors}"
        )


class TestProperty2MultipleErrorsCollected:
    """Property 2: The validator collects ALL errors rather than stopping
    at the first one.

    **Validates: Requirements 1.5, 1.6**
    """

    @given(
        config=valid_deploy_config,
        bad_ip=_invalid_ip,
        bad_port=_invalid_port,
        bad_asn=_invalid_as_number,
    )
    @h_settings(max_examples=100)
    def test_multiple_invalid_fields_all_reported(
        self,
        config: DeployConfig,
        bad_ip: str,
        bad_port: int,
        bad_asn: str,
    ) -> None:
        """When multiple fields are invalid, all errors are reported."""
        config.domain = ""
        config.incoming_ip = bad_ip
        config.xray_internal_port = bad_port
        config.blocked_as_numbers = [bad_asn]
        config.xui_path_prefix = "noslash"

        errors = validate_config(config)

        # Should have at least 4 distinct errors (domain, IP, port, AS, path)
        assert len(errors) >= 4, (
            f"Expected at least 4 errors, got {len(errors)}: {errors}"
        )
        # Each category should be represented
        assert any("domain" in e.lower() for e in errors)
        assert any("incoming_ip" in e for e in errors)
        assert any("xray_internal_port" in e for e in errors)
        assert any("AS number" in e for e in errors)
        assert any("xui_path_prefix" in e for e in errors)
