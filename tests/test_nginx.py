# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based and unit tests for vpn007.nginx — Nginx config generation."""

from __future__ import annotations

from hypothesis import given

from vpn007.models import CoverSiteMode, DeployConfig
from vpn007.nginx import (
    generate_nginx_http_config,
    generate_nginx_stream_config,
    _build_ssl_protocols,
    _extract_cover_site_domain,
)

from tests.conftest import valid_deploy_config


# ---------------------------------------------------------------------------
# Property 8: Nginx routing configuration completeness
# ---------------------------------------------------------------------------


class TestProperty8NginxRoutingCompleteness:
    """**Property 8: Nginx routing configuration completeness**

    For any valid DeployConfig, the generated Nginx config:
    - Listens on 443 (and optionally 8443) in the stream block
    - Routes Reality SNI to Xray without TLS termination
    - Routes path prefixes to correct backends
    - Routes default traffic to cover site
    - Includes TLS directives
    - Includes proxy headers

    **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 7.5**
    """

    # --- Stream block properties ---

    @given(config=valid_deploy_config)
    def test_stream_loads_stream_module(self, config: DeployConfig) -> None:
        """Stream config must load the ngx_stream_module."""
        output = generate_nginx_stream_config(config)
        assert "load_module modules/ngx_stream_module.so;" in output

    @given(config=valid_deploy_config)
    def test_stream_listens_on_https_port(self, config: DeployConfig) -> None:
        """Stream block must listen on the configured HTTPS port."""
        output = generate_nginx_stream_config(config)
        port = config.https_port
        if config.incoming_ip:
            assert f"{config.incoming_ip}:{port}" in output
        else:
            assert f"listen {port};" in output
        # IPv6 listener always present
        assert f"listen [::]:{port};" in output

    @given(config=valid_deploy_config)
    def test_stream_8443_conditional(self, config: DeployConfig) -> None:
        """Port 8443 must be present only when enable_port_8443 is True (and not the main HTTPS port)."""
        output = generate_nginx_stream_config(config)
        if config.enable_port_8443:
            assert "8443" in output
        elif config.https_port != 8443:
            assert "8443" not in output

    @given(config=valid_deploy_config)
    def test_stream_routes_reality_sni_to_xray(self, config: DeployConfig) -> None:
        """Stream SNI map must route Reality SNI to xray_backend."""
        output = generate_nginx_stream_config(config)
        assert config.reality_sni in output
        assert "xray_backend" in output
        # Xray upstream must point to three_x_ui container on the internal port
        assert f"three_x_ui:{config.xray_internal_port}" in output

    @given(config=valid_deploy_config)
    def test_stream_default_routes_to_http(self, config: DeployConfig) -> None:
        """Stream SNI map default must route to nginx_http_backend."""
        output = generate_nginx_stream_config(config)
        assert "default" in output
        assert "nginx_http_backend" in output
        assert "127.0.0.1:10080" in output

    @given(config=valid_deploy_config)
    def test_stream_has_ssl_preread(self, config: DeployConfig) -> None:
        """Stream block must enable ssl_preread for SNI inspection."""
        output = generate_nginx_stream_config(config)
        assert "ssl_preread on;" in output

    @given(config=valid_deploy_config)
    def test_stream_has_proxy_protocol(self, config: DeployConfig) -> None:
        """Stream block must enable proxy_protocol globally."""
        output = generate_nginx_stream_config(config)
        assert "proxy_protocol on;" in output

    @given(config=valid_deploy_config)
    def test_stream_incoming_ip_binding(self, config: DeployConfig) -> None:
        """When incoming_ip is set, stream must bind to that IP."""
        output = generate_nginx_stream_config(config)
        if config.incoming_ip:
            assert f"listen {config.incoming_ip}:{config.https_port};" in output
        else:
            assert f"listen {config.https_port};" in output

    # --- HTTP block properties ---

    @given(config=valid_deploy_config)
    def test_http_listens_on_10080_with_ssl_h2_proxy_protocol(
        self, config: DeployConfig
    ) -> None:
        """HTTP block must listen on 10080 with ssl, http2, and proxy_protocol."""
        output = generate_nginx_http_config(config)
        assert "listen 10080 ssl http2 proxy_protocol;" in output

    @given(config=valid_deploy_config)
    def test_http_has_real_ip_from_directives(self, config: DeployConfig) -> None:
        """HTTP block must extract real client IP from PROXY protocol."""
        output = generate_nginx_http_config(config)
        assert "set_real_ip_from 127.0.0.1;" in output
        assert "set_real_ip_from 172.20.0.0/16;" in output
        assert "real_ip_header proxy_protocol;" in output

    @given(config=valid_deploy_config)
    def test_http_has_tls_directives(self, config: DeployConfig) -> None:
        """HTTP block must include TLS certificate and protocol directives."""
        output = generate_nginx_http_config(config)
        assert "ssl_certificate" in output
        assert "ssl_certificate_key" in output
        assert "ssl_protocols" in output
        assert "ssl_ciphers" in output
        assert "ssl_prefer_server_ciphers on;" in output

    @given(config=valid_deploy_config)
    def test_http_no_ech_esni(self, config: DeployConfig) -> None:
        """HTTP block must NOT contain ssl_ech or ssl_esni directives.

        Comments mentioning ECH/ESNI are acceptable — only actual Nginx
        directives (lines starting with ``ssl_ech`` or ``ssl_esni`` after
        optional whitespace) are forbidden.
        """
        output = generate_nginx_http_config(config)
        for line in output.splitlines():
            stripped = line.strip()
            # Skip comment lines
            if stripped.startswith("#"):
                continue
            assert not stripped.startswith("ssl_ech"), (
                f"Found ssl_ech directive: {line!r}"
            )
            assert not stripped.startswith("ssl_esni"), (
                f"Found ssl_esni directive: {line!r}"
            )

    @given(config=valid_deploy_config)
    def test_http_has_alpn(self, config: DeployConfig) -> None:
        """HTTP block must advertise h2 and http/1.1 via ALPN."""
        output = generate_nginx_http_config(config)
        assert "ssl_alpn h2 http/1.1;" in output

    @given(config=valid_deploy_config)
    def test_http_routes_xui_path_to_three_x_ui(self, config: DeployConfig) -> None:
        """HTTP block must route xui_path_prefix to three_x_ui backend."""
        output = generate_nginx_http_config(config)
        assert f"location {config.xui_path_prefix}/" in output
        assert "proxy_pass http://three_x_ui:2053/;" in output

    @given(config=valid_deploy_config)
    def test_http_routes_awg_path_to_amneziawg(self, config: DeployConfig) -> None:
        """HTTP block must route awg_panel_path_prefix to AmneziaWG panel."""
        output = generate_nginx_http_config(config)
        assert f"location {config.awg_panel_path_prefix}/" in output
        assert f"proxy_pass http://host.docker.internal:{config.awg_panel_port}/;" in output

    @given(config=valid_deploy_config)
    def test_http_default_routes_to_cover_site(self, config: DeployConfig) -> None:
        """HTTP block must route default traffic to cover_site."""
        output = generate_nginx_http_config(config)
        assert "proxy_pass http://cover_site:80;" in output

    @given(config=valid_deploy_config)
    def test_http_panel_locations_have_ip_restriction(
        self, config: DeployConfig
    ) -> None:
        """Panel location blocks must include IP restriction."""
        output = generate_nginx_http_config(config)
        # Both panel locations must include the approved IPs conf and deny all
        assert output.count("include /etc/nginx/conf.d/approved_panel_ips.conf;") == 2
        assert output.count("deny all;") == 2

    @given(config=valid_deploy_config)
    def test_http_panel_locations_have_rate_limiting(
        self, config: DeployConfig
    ) -> None:
        """Panel location blocks must have rate limiting."""
        output = generate_nginx_http_config(config)
        assert "limit_req_zone" in output
        assert "limit_req zone=panel_limit burst=10 nodelay;" in output
        # Rate limit must appear in both panel locations
        assert output.count("limit_req zone=panel_limit burst=10 nodelay;") == 2

    @given(config=valid_deploy_config)
    def test_http_has_proxy_headers(self, config: DeployConfig) -> None:
        """HTTP block must include standard proxy headers."""
        output = generate_nginx_http_config(config)
        assert "X-Real-IP" in output
        assert "X-Forwarded-For" in output
        assert "X-Forwarded-Proto" in output

    @given(config=valid_deploy_config)
    def test_http_has_acme_challenge_location(self, config: DeployConfig) -> None:
        """HTTP block must serve ACME challenges on port 80."""
        output = generate_nginx_http_config(config)
        assert "listen 80;" in output
        assert "/.well-known/acme-challenge/" in output
        assert "/var/www/certbot" in output

    @given(config=valid_deploy_config)
    def test_http_port_80_redirects_to_https(self, config: DeployConfig) -> None:
        """Port 80 must redirect non-ACME traffic to HTTPS."""
        output = generate_nginx_http_config(config)
        assert "return 301 https://$host$request_uri;" in output

    @given(config=valid_deploy_config)
    def test_http_server_name_matches_domain(self, config: DeployConfig) -> None:
        """HTTP server_name must match the configured domain."""
        output = generate_nginx_http_config(config)
        assert f"server_name {config.domain};" in output


# ---------------------------------------------------------------------------
# Unit tests for cover site modes
# ---------------------------------------------------------------------------


class TestCoverSiteMode:
    """Verify cover site static vs proxy mode rendering."""

    def test_static_mode_no_cache_directives(self) -> None:
        """Static mode must not include proxy_cache directives."""
        config = DeployConfig(
            domain="vpn.example.com",
            cover_site_mode=CoverSiteMode.STATIC,
        )
        output = generate_nginx_http_config(config)
        assert "proxy_cache" not in output
        assert "proxy_cache_valid" not in output
        assert "proxy_intercept_errors" not in output
        assert "proxy_cache_path" not in output

    def test_proxy_mode_has_cache_directives(self) -> None:
        """Proxy mode must include proxy_cache and proxy_intercept_errors."""
        config = DeployConfig(
            domain="vpn.example.com",
            cover_site_mode=CoverSiteMode.PROXY,
            cover_site_url="https://example.org",
        )
        output = generate_nginx_http_config(config)
        assert "proxy_cache_path" in output
        assert "proxy_cache cover_cache;" in output
        assert "proxy_cache_valid 200 301 302 1h;" in output
        assert "proxy_intercept_errors on;" in output

    def test_proxy_mode_overwrites_host_header(self) -> None:
        """Proxy mode must overwrite Host header to match cover site domain."""
        config = DeployConfig(
            domain="vpn.example.com",
            cover_site_mode=CoverSiteMode.PROXY,
            cover_site_url="https://www.legit-site.com",
        )
        output = generate_nginx_http_config(config)
        assert "proxy_set_header Host www.legit-site.com;" in output

    def test_static_mode_preserves_host_header(self) -> None:
        """Static mode must pass $host as the Host header."""
        config = DeployConfig(
            domain="vpn.example.com",
            cover_site_mode=CoverSiteMode.STATIC,
        )
        output = generate_nginx_http_config(config)
        # The default location should use $host
        assert "proxy_set_header Host $host;" in output


# ---------------------------------------------------------------------------
# Unit tests for TLS version configuration
# ---------------------------------------------------------------------------


class TestTlsVersionConfig:
    """Verify TLS version configuration in HTTP block."""

    def test_default_tls_12_and_13(self) -> None:
        """Default config must accept TLS 1.2 and 1.3."""
        config = DeployConfig(domain="vpn.example.com")
        output = generate_nginx_http_config(config)
        assert "ssl_protocols TLSv1.2 TLSv1.3;" in output

    def test_tls_13_only(self) -> None:
        """When only TLS 1.3 is configured, ssl_protocols must reflect that."""
        config = DeployConfig(domain="vpn.example.com", tls_versions=["1.3"])
        output = generate_nginx_http_config(config)
        assert "ssl_protocols TLSv1.3;" in output

    def test_tls_12_only(self) -> None:
        """When only TLS 1.2 is configured, ssl_protocols must reflect that."""
        config = DeployConfig(domain="vpn.example.com", tls_versions=["1.2"])
        output = generate_nginx_http_config(config)
        assert "ssl_protocols TLSv1.2;" in output

    def test_empty_tls_versions_defaults(self) -> None:
        """Empty tls_versions list must default to TLS 1.2 + 1.3."""
        config = DeployConfig(domain="vpn.example.com", tls_versions=[])
        output = generate_nginx_http_config(config)
        assert "ssl_protocols TLSv1.2 TLSv1.3;" in output


# ---------------------------------------------------------------------------
# Unit tests for incoming IP binding
# ---------------------------------------------------------------------------


class TestIncomingIpBinding:
    """Verify incoming IP binding in stream config."""

    def test_incoming_ip_binds_to_specific_address(self) -> None:
        """When incoming_ip is set, stream must bind to that IP on https_port."""
        config = DeployConfig(
            domain="vpn.example.com", incoming_ip="203.0.113.10"
        )
        output = generate_nginx_stream_config(config)
        assert f"listen 203.0.113.10:{config.https_port};" in output

    def test_no_incoming_ip_binds_all_interfaces(self) -> None:
        """When incoming_ip is not set, stream must listen on all interfaces."""
        config = DeployConfig(domain="vpn.example.com")
        output = generate_nginx_stream_config(config)
        assert f"listen {config.https_port};" in output

    def test_incoming_ip_with_8443(self) -> None:
        """When incoming_ip and 8443 are set, both ports bind to the IP."""
        config = DeployConfig(
            domain="vpn.example.com",
            incoming_ip="203.0.113.10",
            enable_port_8443=True,
        )
        output = generate_nginx_stream_config(config)
        assert f"listen 203.0.113.10:{config.https_port};" in output
        assert "listen 203.0.113.10:8443;" in output


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


class TestBuildSslProtocols:
    """Tests for the _build_ssl_protocols helper."""

    def test_both_versions(self) -> None:
        assert _build_ssl_protocols(["1.2", "1.3"]) == "TLSv1.2 TLSv1.3"

    def test_only_13(self) -> None:
        assert _build_ssl_protocols(["1.3"]) == "TLSv1.3"

    def test_only_12(self) -> None:
        assert _build_ssl_protocols(["1.2"]) == "TLSv1.2"

    def test_empty_defaults(self) -> None:
        assert _build_ssl_protocols([]) == "TLSv1.2 TLSv1.3"

    def test_unknown_versions_ignored(self) -> None:
        assert _build_ssl_protocols(["1.1", "1.0"]) == "TLSv1.2 TLSv1.3"

    def test_mixed_known_unknown(self) -> None:
        assert _build_ssl_protocols(["1.1", "1.3"]) == "TLSv1.3"


class TestExtractCoverSiteDomain:
    """Tests for the _extract_cover_site_domain helper."""

    def test_https_url(self) -> None:
        assert _extract_cover_site_domain("https://example.org") == "example.org"

    def test_http_url(self) -> None:
        assert _extract_cover_site_domain("http://www.example.com") == "www.example.com"

    def test_url_with_path(self) -> None:
        assert _extract_cover_site_domain("https://example.org/path") == "example.org"

    def test_none_returns_empty(self) -> None:
        assert _extract_cover_site_domain(None) == ""

    def test_empty_string_returns_empty(self) -> None:
        assert _extract_cover_site_domain("") == ""
