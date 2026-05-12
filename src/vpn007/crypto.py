# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Cryptographic key generation for VPN007.

Generates x25519/Curve25519 key pairs for Xray Reality and WireGuard,
and random AmneziaWG 2.0 obfuscation parameters.
"""

from __future__ import annotations

import base64
import os
import random
import uuid as _uuid_mod

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from vpn007.models import AwgObfuscation, RealityKeys


def generate_reality_keypair() -> RealityKeys:
    """Generate an x25519 key pair and 8-char hex short_id for Xray Reality.

    Returns a ``RealityKeys`` instance with base64-encoded 32-byte private
    and public keys plus a random 8-character hexadecimal short identifier.
    """
    private_key = X25519PrivateKey.generate()

    raw_private = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    b64_private = base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
    b64_public = base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii")

    short_id = os.urandom(4).hex()

    return RealityKeys(
        private_key=b64_private,
        public_key=b64_public,
        short_id=short_id,
    )


def generate_wg_keypair() -> tuple[str, str]:
    """Generate a WireGuard (Curve25519) key pair.

    WireGuard keys are x25519/Curve25519 keys: 32 random bytes with
    clamping applied, then the public key is derived via scalar
    multiplication with the Curve25519 base point.

    Returns ``(private_key_b64, public_key_b64)`` where both are
    base64-encoded 32-byte values.
    """
    private_key = X25519PrivateKey.generate()

    raw_private = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    return (
        base64.b64encode(raw_private).decode("ascii"),
        base64.b64encode(raw_public).decode("ascii"),
    )


def generate_ssh_keypair() -> tuple[str, str]:
    """Generate an Ed25519 SSH key pair for tunnel authentication.

    Returns ``(private_key_openssh, public_key_openssh)`` where:
    - private_key_openssh is the PEM-encoded private key (OpenSSH format)
    - public_key_openssh is the single-line public key (OpenSSH format)
    """
    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.OpenSSH,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")

    public_openssh = private_key.public_key().public_bytes(
        encoding=Encoding.OpenSSH,
        format=PublicFormat.OpenSSH,
    ).decode("ascii")

    return private_pem, public_openssh


def generate_vless_uuid() -> str:
    """Generate a random UUID for VLESS client/tunnel identification.

    Returns a standard UUID v4 string (e.g., ``550e8400-e29b-41d4-a716-446655440000``).
    """
    return str(_uuid_mod.uuid4())


def generate_awg_obfuscation() -> AwgObfuscation:
    """Generate random AmneziaWG 2.0 obfuscation parameters.

    Values follow best practices from the official AmneziaWG documentation
    (https://docs.amnezia.org/documentation/amnezia-wg/):

    - S1: 15–150 (random prefix for Init packets, max 1132 but 15-150 recommended)
    - S2: 15–150 (random prefix for Response packets, constraint: S1+56≠S2)
    - S3: 15–150 (random prefix for Cookie packets, max 1216 but 15-150 recommended)
    - S4: 0–32 (random prefix for Data packets — limited room in data frames)
    - H1–H4: 5–2147483647, all distinct and non-overlapping ranges
    - Jc: 4–10 (recommended junk packet count; full range 1-128)
    - Jmin/Jmax: 50–1000 (practical junk packet sizes; full range 0-1280)

    I1-I3 default to WebRTC/STUN signatures — the most effective protocol
    for bypassing DPI because STUN is used by all video conferencing apps
    (Google Meet, Zoom, Teams) and is never blocked.

    CPS format reference: https://docs.amnezia.org/documentation/amnezia-wg/
    """
    s1, s2 = _generate_s_pair()
    s3 = random.randint(15, 150)
    s4 = random.randint(0, 32)

    h1, h2, h3, h4 = _generate_distinct_h_values()

    jmin = random.randint(50, 500)
    jmax = random.randint(jmin + 1, 1000)

    return AwgObfuscation(
        s1=s1,
        s2=s2,
        s3=s3,
        s4=s4,
        h1=h1,
        h2=h2,
        h3=h3,
        h4=h4,
        jc=random.randint(4, 10),
        jmin=jmin,
        jmax=jmax,
        # WebRTC/STUN Binding Request — mimics video call signaling
        i1="<b 0x000100002112a442><r 12>",
        # STUN-like follow-up with timestamp for multi-packet realism
        i2="<b 0x0101><r 4><t><r 8>",
        # Pure random entropy packet
        i3="<r 32>",
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_s_pair() -> tuple[int, int]:
    """Generate a pair (sa, sb) in [15, 150] satisfying sa+56≠sb and sb+56≠sa."""
    while True:
        sa = random.randint(15, 150)
        sb = random.randint(15, 150)
        if sa + 56 != sb and sb + 56 != sa:
            return sa, sb


def _generate_distinct_h_values() -> tuple[str, str, str, str]:
    """Generate four non-overlapping H ranges in [5, 2147483647].

    AmneziaWG 2.0 uses H1-H4 as ranges (min-max) instead of fixed values.
    Each range spans ~500M values and they must not overlap.
    """
    # Divide the space [5, 2147483647] into 4 non-overlapping bands
    # with random start points within each band
    band_size = 2147483647 // 5  # ~429M per band, leaving gaps
    ranges: list[str] = []
    for i in range(4):
        band_start = 5 + i * band_size + random.randint(0, band_size // 4)
        band_end = band_start + random.randint(band_size // 4, band_size // 2)
        band_end = min(band_end, 2147483647)
        ranges.append(f"{band_start}-{band_end}")
    return ranges[0], ranges[1], ranges[2], ranges[3]
