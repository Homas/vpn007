# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Xray VLESS+Reality configuration generator for VPN007.

Generates the Xray ``config.json`` that is mounted into the 3x-ui container
to pre-configure its embedded Xray instance with a VLESS inbound using
XTLS-Reality security settings.  Also provides SNI validation to verify
that the chosen Reality SNI target supports TLS 1.3.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.crypto import generate_reality_keypair
from vpn007.models import DeployConfig, RealityKeys

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


def generate_xray_config(
    config: DeployConfig,
    client_uuid: str | None = None,
    client_name: str | None = None,
) -> str:
    """Generate Xray ``config.json`` content from a deployment config.

    If ``config.reality_keys`` is ``None``, a new x25519 key pair and
    short_id are generated automatically.  The generated JSON configures
    a VLESS inbound with Reality security settings, the configured SNI in
    ``serverNames``, the private key, and ``"acceptProxyProtocol": true``
    so that Xray can see real client IPs forwarded by Nginx's PROXY
    protocol header.

    Parameters
    ----------
    config:
        The deployment configuration.
    client_uuid:
        Optional UUID for the initial client to embed in the config.
    client_name:
        Optional name/email for the initial client.

    Returns the rendered JSON string.
    """
    reality_keys = config.reality_keys
    if reality_keys is None:
        reality_keys = generate_reality_keypair()
        logger.info("Auto-generated Reality x25519 key pair and short_id")

    env = _create_jinja_env()
    template = env.get_template("xray-config.json.j2")

    context = _build_template_context(config, reality_keys, client_uuid, client_name)
    rendered = template.render(context)

    # Validate that the output is well-formed JSON.
    json.loads(rendered)

    return rendered


def _build_template_context(
    config: DeployConfig,
    keys: RealityKeys,
    client_uuid: str | None = None,
    client_name: str | None = None,
) -> dict:
    """Build the Jinja2 template context for the Xray config."""
    clients = []
    if client_uuid:
        clients.append({
            "uuid": client_uuid,
            "name": client_name or "default-client",
        })
    return {
        "xray_internal_port": config.xray_internal_port,
        "reality_sni": config.reality_sni,
        "reality_private_key": keys.private_key,
        "reality_public_key": keys.public_key,
        "reality_short_id": keys.short_id,
        "clients": clients,
    }


def validate_reality_sni(sni: str, timeout: float = 5.0) -> bool:
    """Validate that the Reality SNI target supports TLS 1.3.

    Performs a TLS handshake to *sni* on port 443 using Python's ``ssl``
    module.  Returns ``True`` if the connection succeeds with TLS 1.3,
    ``False`` otherwise.  Logs a warning when validation fails so the
    operator is aware but deployment can continue.

    Parameters
    ----------
    sni:
        The fully-qualified domain name to test (e.g. ``www.microsoft.com``).
    timeout:
        Socket timeout in seconds for the test connection.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # We only care about the TLS handshake, not certificate verification
    # against a specific hostname — the SNI target is a third-party site
    # whose certificate we trust via the system CA bundle.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()

    try:
        with socket.create_connection((sni, 443), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
                version = tls_sock.version()
                if version and "TLSv1.3" in version:
                    logger.info(
                        "Reality SNI validation passed: %s supports TLS 1.3", sni
                    )
                    return True
                logger.warning(
                    "Reality SNI validation: %s negotiated %s (expected TLS 1.3)",
                    sni,
                    version,
                )
                return False
    except ssl.SSLError as exc:
        logger.warning("Reality SNI validation failed for %s: %s", sni, exc)
        return False
    except OSError as exc:
        logger.warning(
            "Reality SNI validation: could not connect to %s:443: %s", sni, exc
        )
        return False
