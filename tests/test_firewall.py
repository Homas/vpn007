# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based and unit tests for vpn007.firewall, vpn007.blocklist,
and vpn007.hostname_resolver — nftables, blocklist updater, and hostname
resolver generation.
"""

from __future__ import annotations

import re

from hypothesis import given
from hypothesis import strategies as st

from vpn007.blocklist import generate_blocklist_updater
from vpn007.firewall import generate_nftables_config
from vpn007.hostname_resolver import generate_hostname_resolver
from vpn007.models import DeployConfig
from vpn007.nginx import generate_nginx_stream_config

from tests.conftest import valid_cidr, valid_deploy_config, valid_ipv4


# ---------------------------------------------------------------------------
# Property 9: nftables blocking configuration
# ---------------------------------------------------------------------------


class TestProperty9NftablesBlockingConfiguration:
    """**Property 9: nftables blocking configuration**

    For any list of valid CIDR subnets and blocklist update interval,
    the generated nftables configuration contains all subnets in named
    sets, references those sets in both input and output chains, and the
    generated systemd timer has OnUnitActiveSec matching the configured
    interval.

    **Validates: Requirements 8.2, 8.3, 8.4, 8.7**
    """

    @given(config=valid_deploy_config)
    def test_blocked_subnets_in_named_sets(self, config: DeployConfig) -> None:
        """All configured blocked subnets must appear in nftables named sets."""
        output = generate_nftables_config(config)
        for subnet in config.blocked_subnets:
            # Normalize the subnet for comparison (ipaddress may normalize)
            import ipaddress

            try:
                net = ipaddress.ip_network(subnet, strict=False)
                assert str(net) in output, (
                    f"Blocked subnet {net} must appear in nftables config"
                )
            except ValueError:
                pass  # Invalid subnets are skipped by the generator

    @given(config=valid_deploy_config)
    def test_blocked_sets_referenced_in_input_chain(
        self, config: DeployConfig
    ) -> None:
        """Input chain must reference blocked_v4 and blocked_v6 sets."""
        output = generate_nftables_config(config)
        assert "ip saddr @blocked_v4 drop" in output
        assert "ip6 saddr @blocked_v6 drop" in output

    @given(config=valid_deploy_config)
    def test_blocked_sets_referenced_in_output_chain(
        self, config: DeployConfig
    ) -> None:
        """Output chain must reference blocked_v4 and blocked_v6 sets."""
        output = generate_nftables_config(config)
        assert "ip daddr @blocked_v4 drop" in output
        assert "ip6 daddr @blocked_v6 drop" in output

    @given(config=valid_deploy_config)
    def test_blocklist_timer_interval_matches(
        self, config: DeployConfig
    ) -> None:
        """Blocklist timer OnUnitActiveSec must match configured interval."""
        _, _, timer = generate_blocklist_updater(config)
        expected = f"OnUnitActiveSec={config.blocklist_update_interval_hours}h"
        assert expected in timer, (
            f"Expected {expected!r} in timer, got:\n{timer}"
        )

    @given(config=valid_deploy_config)
    def test_blocklist_service_requires_docker(
        self, config: DeployConfig
    ) -> None:
        """Blocklist service must require docker.service."""
        _, service, _ = generate_blocklist_updater(config)
        assert "Requires=docker.service" in service
        assert "After=docker.service containerd.service" in service

    @given(config=valid_deploy_config)
    def test_blocklist_script_contains_as_numbers(
        self, config: DeployConfig
    ) -> None:
        """Blocklist script must contain all configured AS numbers."""
        script, _, _ = generate_blocklist_updater(config)
        for asn in config.blocked_as_numbers:
            assert asn in script, (
                f"AS number {asn} must appear in blocklist script"
            )

    @given(config=valid_deploy_config)
    def test_blocklist_script_uses_atomic_nft_load(
        self, config: DeployConfig
    ) -> None:
        """Blocklist script must use atomic nft -f for updates."""
        script, _, _ = generate_blocklist_updater(config)
        assert "nft -f" in script, (
            "Blocklist script must use atomic nft -f for set updates"
        )
        assert "flush set inet filter blocked_v4" in script
        assert "flush set inet filter blocked_v6" in script


# ---------------------------------------------------------------------------
# Property 10: nftables base firewall enforces default-deny
# ---------------------------------------------------------------------------


class TestProperty10NftablesDefaultDeny:
    """**Property 10: nftables base firewall enforces default-deny**

    For any valid DeployConfig, the generated nftables has policy drop
    on input, accept only for 443/tcp, 8443/tcp (if enabled), AWG UDP,
    SSH from approved set; port 80 is NOT in the base accept rules.

    **Validates: Requirements 11.1, 11.2, 11.3, 7.1**
    """

    @given(config=valid_deploy_config)
    def test_input_chain_policy_drop(self, config: DeployConfig) -> None:
        """Input chain must have policy drop."""
        output = generate_nftables_config(config)
        assert "policy drop;" in output

    @given(config=valid_deploy_config)
    def test_accepts_https_port(self, config: DeployConfig) -> None:
        """Input chain must accept TCP on the configured HTTPS port."""
        output = generate_nftables_config(config)
        assert f"tcp dport {config.https_port} accept" in output

    @given(config=valid_deploy_config)
    def test_port_8443_conditional(self, config: DeployConfig) -> None:
        """Port 8443 accept rule must be present only when enabled (and not the main HTTPS port)."""
        output = generate_nftables_config(config)
        if config.enable_port_8443:
            assert "tcp dport 8443 accept" in output
        elif config.https_port != 8443:
            # Only check absence if 8443 isn't the main HTTPS port
            assert "tcp dport 8443 accept" not in output

    @given(config=valid_deploy_config)
    def test_accepts_awg_udp_port(self, config: DeployConfig) -> None:
        """Input chain must accept the configured AmneziaWG UDP port."""
        output = generate_nftables_config(config)
        assert f"udp dport {config.awg_listen_port} accept" in output

    @given(config=valid_deploy_config)
    def test_ssh_restricted_to_approved_set(self, config: DeployConfig) -> None:
        """SSH must be allowed only from the approved_ssh_v4 set."""
        output = generate_nftables_config(config)
        assert "ip saddr @approved_ssh_v4 tcp dport 22 accept" in output

    @given(config=valid_deploy_config)
    def test_port_80_not_in_base_rules(self, config: DeployConfig) -> None:
        """Port 80 must NOT be in the base accept rules.

        Port 80 is opened dynamically by the certbot renewal script's
        pre/post-hook only during the brief renewal window.
        """
        import re

        output = generate_nftables_config(config)
        # Check that there's no accept rule for port 80 in the input chain
        # (comments mentioning port 80 are fine)
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # No accept rule should reference exactly port 80 (not 8080, 10080, 58000, etc.)
            if "accept" in stripped and "dport" in stripped:
                port_section = stripped.split("dport")[1].split("accept")[0]
                assert not re.search(r"\b80\b", port_section), (
                    f"Found port 80 accept rule in base config: {line!r}"
                )

    @given(config=valid_deploy_config)
    def test_ssh_approved_ips_in_set(self, config: DeployConfig) -> None:
        """All configured SSH approved IPs must appear in the approved_ssh_v4 set."""
        output = generate_nftables_config(config)
        for ip in config.ssh_approved_ips:
            assert ip in output, (
                f"SSH approved IP {ip} must appear in nftables config"
            )

    @given(config=valid_deploy_config)
    def test_allows_established_related(self, config: DeployConfig) -> None:
        """Input chain must allow established/related connections."""
        output = generate_nftables_config(config)
        assert "ct state established,related accept" in output

    @given(config=valid_deploy_config)
    def test_allows_loopback(self, config: DeployConfig) -> None:
        """Input chain must allow loopback traffic."""
        output = generate_nftables_config(config)
        assert "iif lo accept" in output

    @given(config=valid_deploy_config)
    def test_allows_icmp(self, config: DeployConfig) -> None:
        """Input chain must allow ICMP for diagnostics."""
        output = generate_nftables_config(config)
        assert "ip protocol icmp accept" in output
        assert "ip6 nexthdr icmpv6 accept" in output

    @given(config=valid_deploy_config)
    def test_output_chain_policy_accept(self, config: DeployConfig) -> None:
        """Output chain must have policy accept (with blocked set drops)."""
        output = generate_nftables_config(config)
        # The output chain should have policy accept
        assert re.search(
            r"chain output\s*\{[^}]*policy accept;", output, re.DOTALL
        ), "Output chain must have policy accept"


# ---------------------------------------------------------------------------
# Property 11: Multi-IP routing configuration
# ---------------------------------------------------------------------------


class TestProperty11MultiIpRouting:
    """**Property 11: Multi-IP routing configuration**

    For any valid incoming IP, Nginx stream listen binds to that IP;
    for any valid outgoing IP, nftables postrouting has SNAT rule with
    that IP.

    **Validates: Requirements 9.1, 9.2**
    """

    @given(config=valid_deploy_config)
    def test_nginx_stream_binds_to_incoming_ip(
        self, config: DeployConfig
    ) -> None:
        """When incoming_ip is set, Nginx stream must bind to that IP."""
        output = generate_nginx_stream_config(config)
        if config.incoming_ip:
            assert f"listen {config.incoming_ip}:{config.https_port};" in output, (
                f"Nginx stream must bind to incoming IP {config.incoming_ip}"
            )
        else:
            assert f"listen {config.https_port};" in output

    @given(config=valid_deploy_config)
    def test_nftables_snat_for_outgoing_ip(
        self, config: DeployConfig
    ) -> None:
        """When outgoing_ip is set, nftables must have SNAT rule."""
        output = generate_nftables_config(config)
        if config.outgoing_ip:
            assert f"snat to {config.outgoing_ip}" in output, (
                f"nftables must have SNAT rule for outgoing IP {config.outgoing_ip}"
            )
            assert "table ip nat" in output
            assert "chain postrouting" in output
        else:
            assert "snat to" not in output

    @given(
        incoming_ip=valid_ipv4,
        outgoing_ip=valid_ipv4,
    )
    def test_both_ips_configured(
        self, incoming_ip: str, outgoing_ip: str
    ) -> None:
        """When both IPs are set, both bindings must be present."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            incoming_ip=incoming_ip,
            outgoing_ip=outgoing_ip,
        )
        nft_output = generate_nftables_config(config)
        stream_output = generate_nginx_stream_config(config)

        assert f"listen {incoming_ip}:443;" in stream_output
        assert f"snat to {outgoing_ip}" in nft_output


# ---------------------------------------------------------------------------
# Property 16: Hostname resolver timer interval
# ---------------------------------------------------------------------------


class TestProperty16HostnameResolverTimerInterval:
    """**Property 16: Hostname resolver timer interval**

    For any hostname resolve interval in minutes, the generated systemd
    timer has matching OnUnitActiveSec.

    **Validates: Requirements 7.3**
    """

    @given(config=valid_deploy_config)
    def test_timer_interval_matches_config(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver timer OnUnitActiveSec must match configured interval."""
        _, _, timer = generate_hostname_resolver(config)
        expected = f"OnUnitActiveSec={config.hostname_resolve_interval_min}min"
        assert expected in timer, (
            f"Expected {expected!r} in timer, got:\n{timer}"
        )

    @given(interval=st.integers(min_value=1, max_value=1440))
    def test_timer_interval_direct(self, interval: int) -> None:
        """Direct test: any interval value produces correct timer."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            hostname_resolve_interval_min=interval,
        )
        _, _, timer = generate_hostname_resolver(config)
        expected = f"OnUnitActiveSec={interval}min"
        assert expected in timer

    @given(config=valid_deploy_config)
    def test_hostname_resolver_service_requires_docker(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver service must require docker.service."""
        _, service, _ = generate_hostname_resolver(config)
        assert "Requires=docker.service" in service
        assert "After=docker.service containerd.service" in service

    @given(config=valid_deploy_config)
    def test_hostname_resolver_script_contains_hostnames(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver script must contain all configured hostnames."""
        script, _, _ = generate_hostname_resolver(config)
        for hostname in config.approved_hostnames:
            assert hostname in script, (
                f"Hostname {hostname} must appear in resolver script"
            )

    @given(config=valid_deploy_config)
    def test_hostname_resolver_script_contains_static_ips(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver script must contain all static approved IPs."""
        script, _, _ = generate_hostname_resolver(config)
        for ip in config.approved_ips:
            assert ip in script, (
                f"Static approved IP {ip} must appear in resolver script"
            )

    @given(config=valid_deploy_config)
    def test_hostname_resolver_generates_nginx_allow_directives(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver script must generate Nginx allow directives."""
        script, _, _ = generate_hostname_resolver(config)
        if config.approved_ips or config.approved_hostnames:
            assert "allow" in script, (
                "Resolver script must generate Nginx allow directives"
            )

    @given(config=valid_deploy_config)
    def test_hostname_resolver_reloads_nginx_on_change(
        self, config: DeployConfig
    ) -> None:
        """Hostname resolver script must reload Nginx when IPs change."""
        script, _, _ = generate_hostname_resolver(config)
        assert "nginx -s reload" in script, (
            "Resolver script must reload Nginx when IPs change"
        )


# ---------------------------------------------------------------------------
# Unit tests for nftables generation
# ---------------------------------------------------------------------------


class TestNftablesGeneration:
    """Unit tests for specific nftables configuration scenarios."""

    def test_basic_config_generates_valid_nftables(self) -> None:
        """A basic config should produce valid nftables syntax."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        output = generate_nftables_config(config)
        assert "table inet filter" in output
        assert "chain input" in output
        assert "chain output" in output
        assert "chain forward" in output

    def test_blocked_subnets_appear_in_sets(self) -> None:
        """Explicitly blocked subnets must appear in the named sets."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            blocked_subnets=["198.51.100.0/24", "203.0.113.0/24"],
        )
        output = generate_nftables_config(config)
        assert "198.51.100.0/24" in output
        assert "203.0.113.0/24" in output

    def test_ssh_approved_ips_in_set(self) -> None:
        """SSH approved IPs must appear in the approved_ssh_v4 set."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            ssh_approved_ips=["192.168.1.100", "10.0.0.1"],
        )
        output = generate_nftables_config(config)
        assert "192.168.1.100" in output
        assert "10.0.0.1" in output

    def test_outgoing_ip_snat_rule(self) -> None:
        """When outgoing_ip is set, SNAT rule must be present."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            outgoing_ip="203.0.113.20",
        )
        output = generate_nftables_config(config)
        assert "snat to 203.0.113.20" in output
        assert "table ip nat" in output

    def test_no_outgoing_ip_no_nat_table(self) -> None:
        """When outgoing_ip is not set, no NAT table should be present."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        output = generate_nftables_config(config)
        assert "table ip nat" not in output
        assert "snat to" not in output

    def test_port_8443_enabled(self) -> None:
        """When port 8443 is enabled, accept rule must be present."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            enable_port_8443=True,
        )
        output = generate_nftables_config(config)
        assert "tcp dport 8443 accept" in output

    def test_port_8443_disabled(self) -> None:
        """When port 8443 is disabled, accept rule must not be present."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            enable_port_8443=False,
        )
        output = generate_nftables_config(config)
        assert "tcp dport 8443 accept" not in output

    def test_empty_blocked_subnets(self) -> None:
        """Empty blocked subnets should produce empty named sets."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            blocked_subnets=[],
        )
        output = generate_nftables_config(config)
        assert "set blocked_v4" in output
        assert "set blocked_v6" in output
        # Sets should be defined but empty (no elements block)
        assert "@blocked_v4" in output
        assert "@blocked_v6" in output


class TestBlocklistUpdaterGeneration:
    """Unit tests for blocklist updater generation."""

    def test_generates_three_artifacts(self) -> None:
        """generate_blocklist_updater must return script, service, timer."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            blocked_as_numbers=["AS196747"],
            blocklist_update_interval_hours=6,
        )
        script, service, timer = generate_blocklist_updater(config)
        assert isinstance(script, str)
        assert isinstance(service, str)
        assert isinstance(timer, str)
        assert len(script) > 0
        assert len(service) > 0
        assert len(timer) > 0

    def test_script_is_bash(self) -> None:
        """Blocklist script must start with bash shebang."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
        )
        script, _, _ = generate_blocklist_updater(config)
        assert script.strip().startswith("#!/usr/bin/env bash") or \
               script.strip().startswith("{#") and "#!/usr/bin/env bash" in script

    def test_static_subnets_in_script(self) -> None:
        """Static blocked subnets must appear in the script."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            blocked_subnets=["198.51.100.0/24"],
        )
        script, _, _ = generate_blocklist_updater(config)
        assert "198.51.100.0/24" in script


class TestHostnameResolverGeneration:
    """Unit tests for hostname resolver generation."""

    def test_generates_three_artifacts(self) -> None:
        """generate_hostname_resolver must return script, service, timer."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            approved_hostnames=["admin.example.com"],
            hostname_resolve_interval_min=30,
        )
        script, service, timer = generate_hostname_resolver(config)
        assert isinstance(script, str)
        assert isinstance(service, str)
        assert isinstance(timer, str)
        assert len(script) > 0
        assert len(service) > 0
        assert len(timer) > 0

    def test_script_contains_hostnames(self) -> None:
        """Resolver script must contain configured hostnames."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            approved_hostnames=["admin.example.com", "vpn.example.org"],
        )
        script, _, _ = generate_hostname_resolver(config)
        assert "admin.example.com" in script
        assert "vpn.example.org" in script

    def test_script_contains_static_ips(self) -> None:
        """Resolver script must contain static approved IPs."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            approved_ips=["192.168.1.100"],
        )
        script, _, _ = generate_hostname_resolver(config)
        assert "192.168.1.100" in script

    def test_timer_interval(self) -> None:
        """Timer must have correct OnUnitActiveSec."""
        config = DeployConfig(
            domain="vpn.example.com",
            awg_listen_port=34567,
            hostname_resolve_interval_min=45,
        )
        _, _, timer = generate_hostname_resolver(config)
        assert "OnUnitActiveSec=45min" in timer
