# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Cryptographic key generation for VPN007.

Generates x25519/Curve25519 key pairs for Xray Reality and WireGuard,
and random AmneziaWG 2.0 obfuscation parameters.
"""

from __future__ import annotations

import base64
import os
import random

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

    b64_private = base64.b64encode(raw_private).decode("ascii")
    b64_public = base64.b64encode(raw_public).decode("ascii")

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


def generate_awg_obfuscation() -> AwgObfuscation:
    """Generate random AmneziaWG 2.0 obfuscation parameters.

    All values are within the valid ranges defined by the AmneziaWG 2.0
    protocol specification:

    - S1–S4: 15–150, with bidirectional constraints S1+56≠S2, S3+56≠S4
      (and vice versa)
    - H1–H4: 5–2147483647, all distinct
    - I1–I5: 0–1280
    - Jc: 1–128
    - Jmin ≤ Jmax, both in range 1–1280
    """
    s1, s2 = _generate_s_pair()
    s3, s4 = _generate_s_pair()

    h1, h2, h3, h4 = _generate_distinct_h_values()

    jmin = random.randint(1, 1280)
    jmax = random.randint(jmin, 1280)

    return AwgObfuscation(
        s1=s1,
        s2=s2,
        s3=s3,
        s4=s4,
        h1=h1,
        h2=h2,
        h3=h3,
        h4=h4,
        jc=random.randint(1, 128),
        jmin=jmin,
        jmax=jmax,
        i1=random.randint(0, 1280),
        i2=random.randint(0, 1280),
        i3=random.randint(0, 1280),
        i4=random.randint(0, 1280),
        i5=random.randint(0, 1280),
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


def _generate_distinct_h_values() -> tuple[int, int, int, int]:
    """Generate four distinct H values in [5, 2147483647]."""
    values: set[int] = set()
    while len(values) < 4:
        values.add(random.randint(5, 2147483647))
    h1, h2, h3, h4 = values
    return h1, h2, h3, h4
