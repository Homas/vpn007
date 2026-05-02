# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Nginx configuration generator for VPN007.

Generates two Nginx configuration files from Jinja2 templates:

- **stream.conf** (L4): SNI-based routing that sends Reality SNI traffic
  directly to Xray (raw TCP, no TLS termination) and everything else to
  the Nginx HTTP block.
- **http.conf** (L7): TLS termination with path-based routing to 3x-ui
  panel, AmneziaWG panel, and the cover site.  Accepts PROXY protocol
  headers from the stream block to extract real client IPs.

Both configs support:
- Incoming IP binding for multi-IP deployments
- Optional port 8443
- Configurable TLS versions (defaults to TLS 1.2 + 1.3)
- Strong cipher suites (TLS 1.3 preferred)
- No ECH/ESNI advertisement
- Rate limiting on panel endpoints
- Cover site in static or proxy mode
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.models import CoverSiteMode, DeployConfig

logger = logging.getLogger(__name__)

# Path to the templates directory within the vpn007 package.
_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _create_jinja_env() -> Environment:
    """Create a Jinja2 environment configured for VPN007 templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _build_ssl_protocols(tls_versions: list[str]) -> str:
    """Build the ``ssl_protocols`` directive value from configured TLS versions.

    Maps version strings like ``"1.2"`` and ``"1.3"`` to Nginx protocol
    names ``TLSv1.2`` and ``TLSv1.3``.  Defaults to ``TLSv1.2 TLSv1.3``
    if the input list is empty or contains no recognised versions.
    """
    version_map = {
        "1.2": "TLSv1.2",
        "1.3": "TLSv1.3",
    }
    protocols = [version_map[v] for v in tls_versions if v in version_map]
    if not protocols:
        protocols = ["TLSv1.2", "TLSv1.3"]
    return " ".join(protocols)


def _extract_cover_site_domain(cover_site_url: str | None) -> str:
    """Extract the hostname from a cover site URL for the Host header.

    Returns the hostname portion of the URL, or an empty string if the
    URL is ``None`` or cannot be parsed.
    """
    if not cover_site_url:
        return ""
    parsed = urlparse(cover_site_url)
    return parsed.hostname or ""


def generate_nginx_stream_config(config: DeployConfig) -> str:
    """Generate Nginx stream (L4) configuration for SNI-based routing.

    The stream block inspects the SNI field in the TLS ClientHello and
    routes Reality-destined traffic directly to Xray while forwarding
    all other traffic to the Nginx HTTP server block for TLS termination
    and Layer 7 path-based routing.

    PROXY protocol is enabled globally because Nginx stream cannot set
    ``proxy_protocol`` per-upstream in map mode.

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    str
        The rendered ``nginx-stream.conf`` content.
    """
    env = _create_jinja_env()
    template = env.get_template("nginx-stream.conf.j2")

    context = _build_stream_context(config)
    return template.render(context)


def generate_nginx_http_config(config: DeployConfig) -> str:
    """Generate Nginx HTTP (L7) configuration for path-based routing.

    The HTTP server block listens on port 10080 with TLS termination and
    accepts PROXY protocol headers from the stream block.  It routes
    traffic to the 3x-ui panel, AmneziaWG panel, or cover site based on
    URL path prefixes.

    Panel endpoints are protected by:
    - IP restriction via ``approved_panel_ips.conf`` include
    - Rate limiting (5 req/s with burst of 10)

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    str
        The rendered ``nginx-http.conf`` content.
    """
    env = _create_jinja_env()
    template = env.get_template("nginx-http.conf.j2")

    context = _build_http_context(config)
    return template.render(context)


def _build_stream_context(config: DeployConfig) -> dict:
    """Build the Jinja2 template context for the stream config."""
    return {
        "reality_sni": config.reality_sni,
        "xray_upstream": f"three_x_ui:{config.xray_internal_port}",
        "incoming_ip": config.incoming_ip,
        "enable_port_8443": config.enable_port_8443,
    }


def _build_http_context(config: DeployConfig) -> dict:
    """Build the Jinja2 template context for the HTTP config."""
    cover_site_domain = _extract_cover_site_domain(config.cover_site_url)

    return {
        "domain": config.domain,
        "xui_path_prefix": config.xui_path_prefix,
        "awg_panel_path_prefix": config.awg_panel_path_prefix,
        "awg_panel_port": config.awg_panel_port,
        "three_x_ui_upstream": "three_x_ui:2053",
        "ssl_protocols": _build_ssl_protocols(config.tls_versions),
        "cover_site_mode": config.cover_site_mode.value,
        "cover_site_url": config.cover_site_url,
        "cover_site_domain": cover_site_domain,
    }
