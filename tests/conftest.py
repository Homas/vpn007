# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Pytest configuration and Hypothesis strategies for VPN007 property tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import settings, strategies as st

from vpn007.models import (
    AwgObfuscation,
    CoverSiteMode,
    DeployConfig,
    PortForward,
    TunnelType,
)

# ---------------------------------------------------------------------------
# Hypothesis profiles
# ---------------------------------------------------------------------------
# default: local development (100 examples)
settings.register_profile("default", max_examples=100)
# ci: CI pipelines (50 examples, faster)
settings.register_profile("ci", max_examples=50)
# thorough: nightly runs (500 examples)
settings.register_profile("thorough", max_examples=500)

# Select profile from HYPOTHESIS_PROFILE env var, falling back to "default"
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))

# ---------------------------------------------------------------------------
# Custom Hypothesis strategies
# ---------------------------------------------------------------------------

# Strategy for valid IP addresses (use [0-9] to avoid Unicode digits from \d)
valid_ipv4 = st.from_regex(
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])",
    fullmatch=True,
)

# Strategy for valid CIDR subnets
valid_cidr = st.tuples(valid_ipv4, st.integers(8, 32)).map(
    lambda t: f"{t[0]}/{t[1]}"
)

# Strategy for valid domain names
# Each label: starts with alnum, optionally has alnum/hyphen in the middle,
# ends with alnum. This prevents labels that start or end with hyphens.
valid_domain = st.from_regex(
    r"^[a-z][a-z0-9]{0,5}(\.[a-z][a-z0-9]{0,5})+$", fullmatch=True
)

# Strategy for valid port numbers
valid_port = st.integers(min_value=1, max_value=65535)

# Strategy for valid AS numbers
valid_as_number = st.integers(1, 4294967295).map(lambda n: f"AS{n}")

# Strategy for valid AwgObfuscation (2.0 full parameter set)
valid_awg_obfuscation = (
    st.builds(
        AwgObfuscation,
        s1=st.integers(15, 150),
        s2=st.integers(15, 150),
        s3=st.integers(15, 150),
        s4=st.integers(15, 150),
        h1=st.integers(5, 2147483647),
        h2=st.integers(5, 2147483647),
        h3=st.integers(5, 2147483647),
        h4=st.integers(5, 2147483647),
        jc=st.integers(1, 128),
        jmin=st.integers(1, 1279),
        jmax=st.integers(1, 1280),
        i1=st.integers(0, 1280),
        i2=st.integers(0, 1280),
        i3=st.integers(0, 1280),
        i4=st.integers(0, 1280),
        i5=st.integers(0, 1280),
    )
    .filter(lambda o: o.jmin <= o.jmax)
    .filter(lambda o: o.s1 + 56 != o.s2 and o.s2 + 56 != o.s1)
    .filter(lambda o: o.s3 + 56 != o.s4 and o.s4 + 56 != o.s3)
    .filter(lambda o: len({o.h1, o.h2, o.h3, o.h4}) == 4)  # H values must be distinct
)

# Strategy for valid PortForward entries
valid_port_forward = st.builds(
    PortForward,
    protocol=st.sampled_from(["tcp", "udp"]),
    listen_port=valid_port,
    forward_port=valid_port,
    description=st.text(min_size=0, max_size=50),
)

# Strategy for valid DeployConfig
valid_deploy_config = st.builds(
    DeployConfig,
    domain=valid_domain,
    reality_sni=valid_domain,
    cover_site_mode=st.sampled_from(CoverSiteMode),
    cover_site_url=st.none() | valid_domain.map(lambda d: f"https://{d}"),
    cover_site_static_path=st.none(),
    xui_path_prefix=st.just("/secretpanel"),
    awg_panel_path_prefix=st.just("/awgadmin"),
    enable_port_8443=st.booleans(),
    xray_internal_port=st.just(10443),
    reality_keys=st.none(),
    awg_listen_port=valid_port,
    awg_obfuscation=st.none() | valid_awg_obfuscation,
    awg_panel_port=st.just(51821),
    use_custom_awg_image=st.booleans(),
    tailscale_auth_key=st.none() | st.from_regex(r"tskey-auth-[a-zA-Z0-9]{10,40}", fullmatch=True),
    incoming_ip=st.none() | valid_ipv4,
    outgoing_ip=st.none() | valid_ipv4,
    public_ipv4=st.none() | valid_ipv4,
    public_ipv6=st.none(),
    tls_versions=st.just(["1.2", "1.3"]),
    skip_certbot=st.booleans(),
    https_port=st.sampled_from([443, 8443, 9443]),
    approved_ips=st.lists(valid_ipv4, max_size=5),
    approved_hostnames=st.lists(valid_domain, max_size=3),
    ssh_approved_ips=st.lists(valid_ipv4, max_size=3),
    hostname_resolve_interval_min=st.integers(1, 1440),
    blocked_as_numbers=st.lists(valid_as_number, max_size=5),
    blocked_subnets=st.lists(valid_cidr, max_size=5),
    blocklist_update_interval_hours=st.integers(1, 168),
    forwarding_enabled=st.just(False),
    tunnel_type=st.none(),
    secondary_vm_ip=st.none(),
    reverse_initiated=st.just(False),
    forwarding_ports=st.just([]),
    reconnect_initial_delay_sec=st.integers(1, 60),
    reconnect_max_delay_sec=st.integers(60, 600),
    output_dir=st.just(Path("./deploy")),
    deployment_log_path=st.just(Path("./deploy/deploy.log")),
)


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_config() -> DeployConfig:
    """A basic valid DeployConfig with minimal required fields."""
    return DeployConfig(domain="vpn.example.com")


@pytest.fixture()
def valid_config_with_forwarding() -> DeployConfig:
    """DeployConfig with forwarding enabled."""
    return DeployConfig(
        domain="vpn.example.com",
        forwarding_enabled=True,
        tunnel_type=TunnelType.WIREGUARD,
        secondary_vm_ip="10.0.0.2",
        forwarding_ports=[
            PortForward(protocol="tcp", listen_port=443, forward_port=443),
            PortForward(protocol="udp", listen_port=51820, forward_port=51820),
        ],
        reconnect_initial_delay_sec=5,
        reconnect_max_delay_sec=300,
    )


@pytest.fixture()
def valid_config_with_multi_ip() -> DeployConfig:
    """DeployConfig with incoming/outgoing IPs configured."""
    return DeployConfig(
        domain="vpn.example.com",
        incoming_ip="203.0.113.10",
        outgoing_ip="203.0.113.20",
        public_ipv4="203.0.113.10",
    )


@pytest.fixture()
def valid_config_full() -> DeployConfig:
    """DeployConfig with all optional fields populated."""
    return DeployConfig(
        domain="vpn.example.com",
        reality_sni="www.microsoft.com",
        cover_site_mode=CoverSiteMode.PROXY,
        cover_site_url="https://example.org",
        xui_path_prefix="/secretpanel",
        awg_panel_path_prefix="/awgadmin",
        enable_port_8443=True,
        xray_internal_port=10443,
        awg_listen_port=34567,
        awg_obfuscation=AwgObfuscation(
            s1=30, s2=80, s3=40, s4=100,
            h1=100, h2=200, h3=300, h4=400,
            jc=4, jmin=50, jmax=1000,
            i1=10, i2=20, i3=30, i4=40, i5=50,
        ),
        awg_panel_port=51821,
        tailscale_auth_key="tskey-auth-example1234567890",
        incoming_ip="203.0.113.10",
        outgoing_ip="203.0.113.20",
        public_ipv4="203.0.113.10",
        public_ipv6="2001:db8::1",
        tls_versions=["1.2", "1.3"],
        approved_ips=["192.168.1.0/24", "10.0.0.1"],
        approved_hostnames=["admin.example.com"],
        ssh_approved_ips=["192.168.1.100"],
        hostname_resolve_interval_min=30,
        blocked_as_numbers=["AS196747"],
        blocked_subnets=["198.51.100.0/24"],
        blocklist_update_interval_hours=6,
        forwarding_enabled=True,
        tunnel_type=TunnelType.WIREGUARD,
        secondary_vm_ip="10.0.0.2",
        reverse_initiated=False,
        forwarding_ports=[
            PortForward(protocol="tcp", listen_port=443, forward_port=443),
        ],
        reconnect_initial_delay_sec=5,
        reconnect_max_delay_sec=300,
        output_dir=Path("./deploy"),
        deployment_log_path=Path("./deploy/deploy.log"),
    )


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    """Temporary directory fixture for output file generation."""
    return tmp_path
