# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Initial VPN client/peer provisioning for VPN007.

Generates initial client configurations for Xray VLESS+Reality and
AmneziaWG during deployment, plus random admin credentials for the
3x-ui web panel.  Client configs are saved to the output directory
under ``{output_dir}/clients/``.
"""

from __future__ import annotations

import logging
import os
import secrets
import string
import uuid
from pathlib import Path
from urllib.parse import quote

from vpn007.crypto import generate_reality_keypair, generate_wg_keypair
from vpn007.models import (
    AwgPeerConfig,
    DeployConfig,
    RealityKeys,
    XrayClientConfig,
)

logger = logging.getLogger(__name__)

# Default client/peer names when not specified in the Env_File.
_DEFAULT_XRAY_CLIENT_NAME = "default-client"
_DEFAULT_AWG_PEER_NAME = "default-peer"

# Admin credential generation parameters.
_ADMIN_USERNAME_MIN_LEN = 8
_ADMIN_USERNAME_MAX_LEN = 12
_ADMIN_PASSWORD_MIN_LEN = 16
_ADMIN_PASSWORD_MAX_LEN = 24
_ADMIN_USERNAME_CHARS = string.ascii_letters + string.digits
_ADMIN_PASSWORD_CHARS = string.ascii_letters + string.digits + "!@#$%^&*"


def provision_xray_client(
    config: DeployConfig,
    client_name: str = _DEFAULT_XRAY_CLIENT_NAME,
) -> XrayClientConfig:
    """Provision an initial Xray VLESS+Reality client.

    Generates a UUID for the client, resolves Reality keys from the config
    (auto-generating if ``config.reality_keys`` is ``None``), and builds
    a VLESS share link suitable for import into v2rayNG, v2rayN, Nekoray,
    or Shadowrocket.  The QR code data is the share link itself.

    This runs at config-generation time (before deployment), so the client
    entry is baked into the Xray config that gets mounted into the 3x-ui
    container.

    Parameters
    ----------
    config:
        The deployment configuration.
    client_name:
        Human-readable name for the client (used in the share link
        fragment and output filename).

    Returns
    -------
    XrayClientConfig
        The generated client configuration with share link and QR data.
    """
    client_uuid = str(uuid.uuid4())

    reality_keys: RealityKeys
    if config.reality_keys is not None:
        reality_keys = config.reality_keys
    else:
        reality_keys = generate_reality_keypair()
        logger.info("Auto-generated Reality keys for Xray client provisioning")

    # Determine the server address clients should connect to.
    server_address = config.public_ipv4 or config.incoming_ip or config.domain
    server_port = 443

    # Build the VLESS share link per the standard URI format:
    # vless://{uuid}@{server}:{port}?params#{name}
    vless_link = _build_vless_share_link(
        client_uuid=client_uuid,
        server_address=server_address,
        server_port=server_port,
        sni=config.reality_sni,
        public_key=reality_keys.public_key,
        short_id=reality_keys.short_id,
        client_name=client_name,
    )

    logger.info("Provisioned Xray client %r with UUID %s", client_name, client_uuid)

    return XrayClientConfig(
        client_name=client_name,
        uuid=client_uuid,
        vless_share_link=vless_link,
        qr_code_data=vless_link,
        reality_public_key=reality_keys.public_key,
        short_id=reality_keys.short_id,
        sni=config.reality_sni,
        server_address=server_address,
        server_port=server_port,
    )


def provision_awg_peer(
    config: DeployConfig,
    peer_name: str = _DEFAULT_AWG_PEER_NAME,
) -> AwgPeerConfig:
    """Provision an initial AmneziaWG peer.

    Generates a WireGuard key pair for the peer and builds a ``.conf``
    file compatible with AmneziaWG client apps (AmneziaVPN, official
    AmneziaWG clients).  The conf includes ``[Interface]`` and ``[Peer]``
    sections, plus AWG obfuscation parameters when present.

    In production, this is called post-deployment after containers are
    healthy, and the peer is registered via the running AmneziaWG web panel API.
    This function generates the client-side configuration.

    Parameters
    ----------
    config:
        The deployment configuration.
    peer_name:
        Human-readable name for the peer (used in output filename).

    Returns
    -------
    AwgPeerConfig
        The generated peer configuration with ``.conf`` content.
    """
    private_key, public_key = generate_wg_keypair()

    # Determine the server endpoint clients should connect to.
    server_address = config.public_ipv4 or config.incoming_ip or config.domain
    awg_port = config.awg_listen_port if config.awg_listen_port is not None else 51820
    endpoint = f"{server_address}:{awg_port}"

    # Build the .conf file content.
    conf_content = _build_awg_conf(
        private_key=private_key,
        server_public_key=public_key,  # placeholder; real server key comes from running service
        endpoint=endpoint,
        awg_obfuscation=config.awg_obfuscation,
    )

    logger.info("Provisioned AmneziaWG peer %r", peer_name)

    return AwgPeerConfig(
        peer_name=peer_name,
        private_key=private_key,
        public_key=public_key,
        preshared_key=None,
        allowed_ips="0.0.0.0/0, ::/0",
        endpoint=endpoint,
        conf_content=conf_content,
    )


def generate_3xui_admin_credentials() -> tuple[str, str]:
    """Generate random admin credentials for the 3x-ui web panel.

    Returns a ``(username, password)`` tuple where:

    - **username**: 8–12 alphanumeric characters
    - **password**: 16–24 characters from alphanumeric + special chars

    Uses :mod:`secrets` for cryptographically secure random generation.
    """
    username_length = secrets.randbelow(
        _ADMIN_USERNAME_MAX_LEN - _ADMIN_USERNAME_MIN_LEN + 1
    ) + _ADMIN_USERNAME_MIN_LEN
    password_length = secrets.randbelow(
        _ADMIN_PASSWORD_MAX_LEN - _ADMIN_PASSWORD_MIN_LEN + 1
    ) + _ADMIN_PASSWORD_MIN_LEN

    username = "".join(
        secrets.choice(_ADMIN_USERNAME_CHARS) for _ in range(username_length)
    )
    password = "".join(
        secrets.choice(_ADMIN_PASSWORD_CHARS) for _ in range(password_length)
    )

    return username, password


def save_client_configs(
    output_dir: Path,
    xray_client: XrayClientConfig | None = None,
    awg_peer: AwgPeerConfig | None = None,
) -> dict[str, Path]:
    """Save generated client configurations to the output directory.

    Creates ``{output_dir}/clients/`` and writes:

    - ``xray-{name}.txt`` — VLESS share link for Xray client import
    - ``awg-{name}.conf`` — AmneziaWG peer configuration file

    Parameters
    ----------
    output_dir:
        Base output directory for the deployment.
    xray_client:
        Xray client config to save (skipped if ``None``).
    awg_peer:
        AmneziaWG peer config to save (skipped if ``None``).

    Returns
    -------
    dict[str, Path]
        Mapping of config type to the saved file path.
    """
    clients_dir = output_dir / "clients"
    clients_dir.mkdir(parents=True, exist_ok=True)

    saved: dict[str, Path] = {}

    if xray_client is not None:
        xray_path = clients_dir / f"xray-{xray_client.client_name}.txt"
        xray_path.write_text(xray_client.vless_share_link + "\n", encoding="utf-8")
        saved["xray"] = xray_path
        logger.info("Saved Xray client config to %s", xray_path)

    if awg_peer is not None:
        awg_path = clients_dir / f"awg-{awg_peer.peer_name}.conf"
        awg_path.write_text(awg_peer.conf_content + "\n", encoding="utf-8")
        saved["awg"] = awg_path
        logger.info("Saved AmneziaWG peer config to %s", awg_path)

    return saved


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_vless_share_link(
    *,
    client_uuid: str,
    server_address: str,
    server_port: int,
    sni: str,
    public_key: str,
    short_id: str,
    client_name: str,
) -> str:
    """Build a VLESS+Reality share link URI.

    Format::

        vless://{uuid}@{server}:{port}?type=tcp&security=reality&sni={sni}
        &fp=chrome&pbk={pubkey}&sid={shortid}#{name}
    """
    fragment = quote(client_name, safe="")
    return (
        f"vless://{client_uuid}@{server_address}:{server_port}"
        f"?type=tcp&security=reality"
        f"&sni={quote(sni, safe='')}"
        f"&fp=chrome"
        f"&pbk={quote(public_key, safe='')}"
        f"&sid={quote(short_id, safe='')}"
        f"#{fragment}"
    )


def _build_awg_conf(
    *,
    private_key: str,
    server_public_key: str,
    endpoint: str,
    awg_obfuscation: "AwgObfuscation | None" = None,
) -> str:
    """Build an AmneziaWG client ``.conf`` file content.

    Produces a WireGuard-compatible configuration with ``[Interface]``
    and ``[Peer]`` sections.  When AWG obfuscation parameters are
    present, they are included in the ``[Interface]`` section for
    AmneziaWG client apps.
    """
    lines: list[str] = []

    # [Interface] section
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {private_key}")
    lines.append("Address = 10.8.0.2/24")
    lines.append("DNS = 1.1.1.1")

    # AWG obfuscation parameters (AmneziaWG 2.0 extension)
    if awg_obfuscation is not None:
        lines.append(f"S1 = {awg_obfuscation.s1}")
        lines.append(f"S2 = {awg_obfuscation.s2}")
        lines.append(f"S3 = {awg_obfuscation.s3}")
        lines.append(f"S4 = {awg_obfuscation.s4}")
        lines.append(f"H1 = {awg_obfuscation.h1}")
        lines.append(f"H2 = {awg_obfuscation.h2}")
        lines.append(f"H3 = {awg_obfuscation.h3}")
        lines.append(f"H4 = {awg_obfuscation.h4}")
        lines.append(f"Jc = {awg_obfuscation.jc}")
        lines.append(f"Jmin = {awg_obfuscation.jmin}")
        lines.append(f"Jmax = {awg_obfuscation.jmax}")
        lines.append(f"I1 = {awg_obfuscation.i1}")
        lines.append(f"I2 = {awg_obfuscation.i2}")
        lines.append(f"I3 = {awg_obfuscation.i3}")
        lines.append(f"I4 = {awg_obfuscation.i4}")
        lines.append(f"I5 = {awg_obfuscation.i5}")

    # [Peer] section
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
    lines.append(f"Endpoint = {endpoint}")

    return "\n".join(lines)
