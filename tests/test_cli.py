# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Tests for vpn007.cli — CLI argument parsing."""

from __future__ import annotations

import pytest

from vpn007.cli import parse_args


class TestDefaults:
    """Verify default values when no arguments are provided."""

    def test_env_file_default(self) -> None:
        args = parse_args([])
        assert args.env_file == ".env"

    def test_dry_run_default(self) -> None:
        args = parse_args([])
        assert args.dry_run is None

    def test_debug_default(self) -> None:
        args = parse_args([])
        assert args.debug is None

    def test_domain_default_is_none(self) -> None:
        args = parse_args([])
        assert args.domain is None

    def test_output_dir_default_is_none(self) -> None:
        args = parse_args([])
        assert args.output_dir is None

    def test_reality_sni_default_is_none(self) -> None:
        args = parse_args([])
        assert args.reality_sni is None

    def test_xray_internal_port_default_is_none(self) -> None:
        args = parse_args([])
        assert args.xray_internal_port is None

    def test_awg_listen_port_default_is_none(self) -> None:
        args = parse_args([])
        assert args.awg_listen_port is None


class TestFlags:
    """Verify boolean flags."""

    def test_dry_run_flag(self) -> None:
        args = parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_debug_flag(self) -> None:
        args = parse_args(["--debug"])
        assert args.debug is True


class TestVersion:
    """Verify --version flag."""

    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "vpn007" in captured.out
        assert "0.1.0" in captured.out


class TestEnvFile:
    """Verify --env-file argument."""

    def test_custom_env_file(self) -> None:
        args = parse_args(["--env-file", "/path/to/custom.env"])
        assert args.env_file == "/path/to/custom.env"


class TestGeneralArguments:
    """Verify general configuration arguments."""

    def test_domain(self) -> None:
        args = parse_args(["--domain", "vpn.example.com"])
        assert args.domain == "vpn.example.com"

    def test_reality_sni(self) -> None:
        args = parse_args(["--reality-sni", "www.cloudflare.com"])
        assert args.reality_sni == "www.cloudflare.com"

    def test_cover_site_mode(self) -> None:
        args = parse_args(["--cover-site-mode", "proxy"])
        assert args.cover_site_mode == "proxy"

    def test_cover_site_url(self) -> None:
        args = parse_args(["--cover-site-url", "https://example.com"])
        assert args.cover_site_url == "https://example.com"

    def test_cover_site_static_path(self) -> None:
        args = parse_args(["--cover-site-static-path", "/var/www/html"])
        assert args.cover_site_static_path == "/var/www/html"


class TestRoutingArguments:
    """Verify routing configuration arguments."""

    def test_xui_path_prefix(self) -> None:
        args = parse_args(["--xui-path-prefix", "/mypanel"])
        assert args.xui_path_prefix == "/mypanel"

    def test_awg_panel_path_prefix(self) -> None:
        args = parse_args(["--awg-panel-path-prefix", "/awg"])
        assert args.awg_panel_path_prefix == "/awg"

    def test_enable_port_8443(self) -> None:
        args = parse_args(["--enable-port-8443", "true"])
        assert args.enable_port_8443 == "true"


class TestIntegerArguments:
    """Verify integer-typed arguments."""

    def test_xray_internal_port(self) -> None:
        args = parse_args(["--xray-internal-port", "10443"])
        assert args.xray_internal_port == 10443

    def test_awg_listen_port(self) -> None:
        args = parse_args(["--awg-listen-port", "34567"])
        assert args.awg_listen_port == 34567

    def test_awg_panel_port(self) -> None:
        args = parse_args(["--awg-panel-port", "8080"])
        assert args.awg_panel_port == 8080

    def test_hostname_resolve_interval_min(self) -> None:
        args = parse_args(["--hostname-resolve-interval-min", "60"])
        assert args.hostname_resolve_interval_min == 60

    def test_blocklist_update_interval_hours(self) -> None:
        args = parse_args(["--blocklist-update-interval-hours", "12"])
        assert args.blocklist_update_interval_hours == 12

    def test_reconnect_initial_delay_sec(self) -> None:
        args = parse_args(["--reconnect-initial-delay-sec", "10"])
        assert args.reconnect_initial_delay_sec == 10

    def test_reconnect_max_delay_sec(self) -> None:
        args = parse_args(["--reconnect-max-delay-sec", "600"])
        assert args.reconnect_max_delay_sec == 600


class TestMultiIpArguments:
    """Verify multi-IP arguments."""

    def test_incoming_ip(self) -> None:
        args = parse_args(["--incoming-ip", "10.0.0.1"])
        assert args.incoming_ip == "10.0.0.1"

    def test_outgoing_ip(self) -> None:
        args = parse_args(["--outgoing-ip", "10.0.0.2"])
        assert args.outgoing_ip == "10.0.0.2"

    def test_public_ipv4(self) -> None:
        args = parse_args(["--public-ipv4", "203.0.113.1"])
        assert args.public_ipv4 == "203.0.113.1"

    def test_public_ipv6(self) -> None:
        args = parse_args(["--public-ipv6", "2001:db8::1"])
        assert args.public_ipv6 == "2001:db8::1"


class TestCommaSeparatedArguments:
    """Verify comma-separated string arguments (parsed by config loader)."""

    def test_tls_versions(self) -> None:
        args = parse_args(["--tls-versions", "1.2,1.3"])
        assert args.tls_versions == "1.2,1.3"

    def test_approved_ips(self) -> None:
        args = parse_args(["--approved-ips", "10.0.0.1,10.0.0.2"])
        assert args.approved_ips == "10.0.0.1,10.0.0.2"

    def test_approved_hostnames(self) -> None:
        args = parse_args(["--approved-hostnames", "host1.example.com,host2.example.com"])
        assert args.approved_hostnames == "host1.example.com,host2.example.com"

    def test_ssh_approved_ips(self) -> None:
        args = parse_args(["--ssh-approved-ips", "192.168.1.0/24"])
        assert args.ssh_approved_ips == "192.168.1.0/24"

    def test_blocked_as_numbers(self) -> None:
        args = parse_args(["--blocked-as-numbers", "AS196747,AS12345"])
        assert args.blocked_as_numbers == "AS196747,AS12345"

    def test_blocked_subnets(self) -> None:
        args = parse_args(["--blocked-subnets", "10.0.0.0/8,172.16.0.0/12"])
        assert args.blocked_subnets == "10.0.0.0/8,172.16.0.0/12"


class TestForwardingArguments:
    """Verify forwarding-related arguments."""

    def test_forwarding_enabled(self) -> None:
        args = parse_args(["--forwarding-enabled", "true"])
        assert args.forwarding_enabled == "true"

    def test_tunnel_type(self) -> None:
        args = parse_args(["--tunnel-type", "wireguard"])
        assert args.tunnel_type == "wireguard"

    def test_exit_node_host(self) -> None:
        args = parse_args(["--exit-node-host", "10.0.0.5"])
        assert args.exit_node_host == "10.0.0.5"

    def test_reverse_initiated(self) -> None:
        args = parse_args(["--reverse-initiated", "true"])
        assert args.reverse_initiated == "true"

    def test_forwarding_ports(self) -> None:
        args = parse_args(["--forwarding-ports", "tcp:443:443:HTTPS,udp:51820:51820:WG"])
        assert args.forwarding_ports == "tcp:443:443:HTTPS,udp:51820:51820:WG"


class TestOutputArguments:
    """Verify output-related arguments."""

    def test_output_dir(self) -> None:
        args = parse_args(["--output-dir", "/opt/deploy"])
        assert args.output_dir == "/opt/deploy"

    def test_deployment_log_path(self) -> None:
        args = parse_args(["--deployment-log-path", "/var/log/vpn007.log"])
        assert args.deployment_log_path == "/var/log/vpn007.log"


class TestTailscaleArguments:
    """Verify Tailscale arguments."""

    def test_tailscale_auth_key(self) -> None:
        args = parse_args(["--tailscale-auth-key", "tskey-auth-abc123"])
        assert args.tailscale_auth_key == "tskey-auth-abc123"


class TestKebabToSnakeConversion:
    """Verify argparse converts kebab-case to snake_case in the Namespace."""

    def test_kebab_case_converted(self) -> None:
        args = parse_args([
            "--reality-sni", "www.google.com",
            "--awg-listen-port", "12345",
            "--cover-site-mode", "static",
            "--xui-path-prefix", "/panel",
            "--awg-panel-path-prefix", "/awg",
            "--enable-port-8443", "true",
            "--hostname-resolve-interval-min", "15",
            "--blocklist-update-interval-hours", "3",
            "--reconnect-initial-delay-sec", "10",
            "--reconnect-max-delay-sec", "600",
        ])
        # All should be accessible via snake_case attribute names
        assert args.reality_sni == "www.google.com"
        assert args.awg_listen_port == 12345
        assert args.cover_site_mode == "static"
        assert args.xui_path_prefix == "/panel"
        assert args.awg_panel_path_prefix == "/awg"
        assert args.enable_port_8443 == "true"
        assert args.hostname_resolve_interval_min == 15
        assert args.blocklist_update_interval_hours == 3
        assert args.reconnect_initial_delay_sec == 10
        assert args.reconnect_max_delay_sec == 600


class TestMultipleArgsCombined:
    """Verify multiple arguments can be provided together."""

    def test_full_config_via_cli(self) -> None:
        args = parse_args([
            "--domain", "vpn.example.com",
            "--reality-sni", "www.microsoft.com",
            "--output-dir", "/opt/deploy",
            "--dry-run",
            "--debug",
            "--env-file", "custom.env",
            "--awg-listen-port", "34567",
            "--approved-ips", "10.0.0.1,10.0.0.2",
        ])
        assert args.domain == "vpn.example.com"
        assert args.reality_sni == "www.microsoft.com"
        assert args.output_dir == "/opt/deploy"
        assert args.dry_run is True
        assert args.debug is True
        assert args.env_file == "custom.env"
        assert args.awg_listen_port == 34567
        assert args.approved_ips == "10.0.0.1,10.0.0.2"
