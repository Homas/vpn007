# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Property-based tests for vpn007.crypto — key generation and AWG obfuscation."""

from __future__ import annotations

import base64
import re

from hypothesis import given, settings as h_settings
from hypothesis import strategies as st

from vpn007.crypto import (
    generate_awg_obfuscation,
    generate_reality_keypair,
    generate_wg_keypair,
)


# ---------------------------------------------------------------------------
# Property 5: Reality key pair uniqueness
# ---------------------------------------------------------------------------


class TestRealityKeyPairUniqueness:
    """**Validates: Requirements 3.2**

    For any two invocations of the Reality key pair generator, the resulting
    key pairs should be distinct, and each key should be a valid x25519 key
    (32 bytes, base64-encoded).
    """

    @given(st.integers(min_value=1, max_value=100))
    def test_reality_keypairs_are_distinct(self, _n: int) -> None:
        """Two independently generated Reality key pairs must differ."""
        keys_a = generate_reality_keypair()
        keys_b = generate_reality_keypair()

        assert keys_a.private_key != keys_b.private_key, (
            "Two generated Reality private keys must not be identical"
        )
        assert keys_a.public_key != keys_b.public_key, (
            "Two generated Reality public keys must not be identical"
        )

    @given(st.integers(min_value=1, max_value=100))
    def test_reality_keys_are_valid_x25519(self, _n: int) -> None:
        """Each Reality key must be a valid base64-encoded 32-byte value."""
        keys = generate_reality_keypair()

        raw_private = base64.b64decode(keys.private_key)
        raw_public = base64.b64decode(keys.public_key)

        assert len(raw_private) == 32, (
            f"Reality private key must be 32 bytes, got {len(raw_private)}"
        )
        assert len(raw_public) == 32, (
            f"Reality public key must be 32 bytes, got {len(raw_public)}"
        )

    @given(st.integers(min_value=1, max_value=100))
    def test_reality_short_id_format(self, _n: int) -> None:
        """The short_id must be exactly 8 hexadecimal characters."""
        keys = generate_reality_keypair()

        assert len(keys.short_id) == 8, (
            f"short_id must be 8 chars, got {len(keys.short_id)}"
        )
        assert re.fullmatch(r"[0-9a-f]{8}", keys.short_id), (
            f"short_id must be lowercase hex, got {keys.short_id!r}"
        )


# ---------------------------------------------------------------------------
# WireGuard key pair validation
# ---------------------------------------------------------------------------


class TestWireGuardKeyPair:
    """Validates WireGuard key generation produces valid Curve25519 keys."""

    @given(st.integers(min_value=1, max_value=100))
    def test_wg_keys_are_valid_32_byte_base64(self, _n: int) -> None:
        """WireGuard keys must be base64-encoded 32-byte values."""
        priv, pub = generate_wg_keypair()

        raw_priv = base64.b64decode(priv)
        raw_pub = base64.b64decode(pub)

        assert len(raw_priv) == 32, (
            f"WG private key must be 32 bytes, got {len(raw_priv)}"
        )
        assert len(raw_pub) == 32, (
            f"WG public key must be 32 bytes, got {len(raw_pub)}"
        )

    @given(st.integers(min_value=1, max_value=100))
    def test_wg_keypairs_are_distinct(self, _n: int) -> None:
        """Two independently generated WireGuard key pairs must differ."""
        priv_a, pub_a = generate_wg_keypair()
        priv_b, pub_b = generate_wg_keypair()

        assert priv_a != priv_b, "Two WG private keys must not be identical"
        assert pub_a != pub_b, "Two WG public keys must not be identical"


# ---------------------------------------------------------------------------
# AmneziaWG obfuscation parameter validation
# ---------------------------------------------------------------------------


class TestAwgObfuscation:
    """Validates generated AWG obfuscation parameters are within valid ranges
    and satisfy all AmneziaWG 2.0 constraints.
    """

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_s_values_in_range(self, _n: int) -> None:
        """S1–S4 must be in [15, 150]."""
        awg = generate_awg_obfuscation()

        for name, val in [("s1", awg.s1), ("s2", awg.s2), ("s3", awg.s3), ("s4", awg.s4)]:
            assert 15 <= val <= 150, f"{name}={val} out of range [15, 150]"

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_s_bidirectional_constraints(self, _n: int) -> None:
        """S1+56≠S2, S2+56≠S1, S3+56≠S4, S4+56≠S3."""
        awg = generate_awg_obfuscation()

        assert awg.s1 + 56 != awg.s2, f"S1+56 == S2: {awg.s1}+56 == {awg.s2}"
        assert awg.s2 + 56 != awg.s1, f"S2+56 == S1: {awg.s2}+56 == {awg.s1}"
        assert awg.s3 + 56 != awg.s4, f"S3+56 == S4: {awg.s3}+56 == {awg.s4}"
        assert awg.s4 + 56 != awg.s3, f"S4+56 == S3: {awg.s4}+56 == {awg.s3}"

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_h_values_in_range_and_distinct(self, _n: int) -> None:
        """H1–H4 must be in [5, 2147483647] and all distinct."""
        awg = generate_awg_obfuscation()

        for name, val in [("h1", awg.h1), ("h2", awg.h2), ("h3", awg.h3), ("h4", awg.h4)]:
            assert 5 <= val <= 2147483647, f"{name}={val} out of range"

        h_set = {awg.h1, awg.h2, awg.h3, awg.h4}
        assert len(h_set) == 4, f"H values must be distinct, got {h_set}"

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_i_values_in_range(self, _n: int) -> None:
        """I1–I5 must be in [0, 1280]."""
        awg = generate_awg_obfuscation()

        for name, val in [
            ("i1", awg.i1), ("i2", awg.i2), ("i3", awg.i3),
            ("i4", awg.i4), ("i5", awg.i5),
        ]:
            assert 0 <= val <= 1280, f"{name}={val} out of range [0, 1280]"

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_jc_in_range(self, _n: int) -> None:
        """Jc must be in [1, 128]."""
        awg = generate_awg_obfuscation()
        assert 1 <= awg.jc <= 128, f"jc={awg.jc} out of range [1, 128]"

    @given(st.integers(min_value=1, max_value=100))
    def test_awg_jmin_jmax_ordering(self, _n: int) -> None:
        """Jmin ≤ Jmax, both in [1, 1280]."""
        awg = generate_awg_obfuscation()

        assert 1 <= awg.jmin <= 1280, f"jmin={awg.jmin} out of range [1, 1280]"
        assert 1 <= awg.jmax <= 1280, f"jmax={awg.jmax} out of range [1, 1280]"
        assert awg.jmin <= awg.jmax, f"jmin={awg.jmin} > jmax={awg.jmax}"
