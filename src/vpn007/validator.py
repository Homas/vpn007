# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Parameter validation for VPN007 deployment configuration."""

from __future__ import annotations

import ipaddress
import re

from vpn007.models import AwgObfuscation, DeployConfig


def validate_config(config: DeployConfig) -> list[str]:
    """Validate all config values and return a list of error messages.

    An empty list means the configuration is valid.  The validator collects
    *all* errors rather than stopping at the first one.
    """
    errors: list[str] = []

    # --- Required parameters ---
    if not config.domain:
        errors.append("Missing required parameter: domain")
    else:
        errors.extend(_validate_domain(config.domain))

    # --- IP addresses ---
    for field_name in ("incoming_ip", "outgoing_ip", "public_ipv4", "secondary_vm_ip"):
        value = getattr(config, field_name)
        if value is not None:
            if not _is_valid_ip(value):
                errors.append(f"Invalid IP address for {field_name}: {value!r}")

    if config.public_ipv6 is not None:
        if not _is_valid_ip(config.public_ipv6):
            errors.append(f"Invalid IP address for public_ipv6: {config.public_ipv6!r}")

    # --- CIDR subnets ---
    for subnet in config.blocked_subnets:
        if not _is_valid_cidr(subnet):
            errors.append(f"Invalid CIDR subnet: {subnet!r}")

    # --- Approved IPs (can be IPs or CIDRs) ---
    for ip_or_cidr in config.approved_ips:
        if not _is_valid_ip(ip_or_cidr) and not _is_valid_cidr(ip_or_cidr):
            errors.append(f"Invalid IP address or CIDR in approved_ips: {ip_or_cidr!r}")

    for ip_or_cidr in config.ssh_approved_ips:
        if not _is_valid_ip(ip_or_cidr) and not _is_valid_cidr(ip_or_cidr):
            errors.append(f"Invalid IP address or CIDR in ssh_approved_ips: {ip_or_cidr!r}")

    # --- Port numbers ---
    _validate_port(config.xray_internal_port, "xray_internal_port", errors)
    _validate_port(config.awg_panel_port, "awg_panel_port", errors)

    # awg_listen_port may be None (auto-randomize mode) — skip when None
    if config.awg_listen_port is not None:
        _validate_port(config.awg_listen_port, "awg_listen_port", errors)

    # Forwarding port entries
    for i, pf in enumerate(config.forwarding_ports):
        _validate_port(pf.listen_port, f"forwarding_ports[{i}].listen_port", errors)
        _validate_port(pf.forward_port, f"forwarding_ports[{i}].forward_port", errors)

    # --- AS numbers ---
    for asn in config.blocked_as_numbers:
        if not _is_valid_as_number(asn):
            errors.append(f"Invalid AS number format: {asn!r} (expected 'AS' followed by digits)")

    # --- Path prefixes ---
    if not config.xui_path_prefix.startswith("/"):
        errors.append(
            f"Path prefix xui_path_prefix must start with '/': {config.xui_path_prefix!r}"
        )
    if not config.awg_panel_path_prefix.startswith("/"):
        errors.append(
            f"Path prefix awg_panel_path_prefix must start with '/': "
            f"{config.awg_panel_path_prefix!r}"
        )

    # --- AWG obfuscation ---
    if config.awg_obfuscation is not None:
        errors.extend(_validate_awg_obfuscation(config.awg_obfuscation))

    # --- Forwarding config consistency ---
    if config.forwarding_enabled:
        if config.tunnel_type is None:
            errors.append(
                "tunnel_type is required when forwarding_enabled is True"
            )
        if config.secondary_vm_ip is None:
            errors.append(
                "secondary_vm_ip is required when forwarding_enabled is True"
            )

    return errors


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _validate_domain(domain: str) -> list[str]:
    """Validate that *domain* is a valid FQDN.

    Rules:
    - At least 2 labels separated by dots
    - Each label: alphanumeric + hyphens, not starting/ending with hyphen,
      max 63 chars
    """
    errors: list[str] = []
    labels = domain.split(".")
    if len(labels) < 2:
        errors.append(f"Invalid domain (need at least 2 labels): {domain!r}")
        return errors

    for label in labels:
        if not label:
            errors.append(f"Invalid domain (empty label): {domain!r}")
            return errors
        if len(label) > 63:
            errors.append(
                f"Invalid domain (label exceeds 63 chars): {domain!r}"
            )
            return errors
        if not _LABEL_RE.match(label):
            errors.append(f"Invalid domain (bad label {label!r}): {domain!r}")
            return errors

    return errors


# ---------------------------------------------------------------------------
# IP / CIDR validation
# ---------------------------------------------------------------------------


def _is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_cidr(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 CIDR network."""
    try:
        ipaddress.ip_network(value, strict=False)
        # Must contain a '/' to be considered a CIDR notation
        return "/" in value
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Port validation
# ---------------------------------------------------------------------------


def _validate_port(port: int, name: str, errors: list[str]) -> None:
    """Append an error if *port* is outside 1-65535."""
    if not (1 <= port <= 65535):
        errors.append(f"Invalid port number for {name}: {port} (must be 1-65535)")


# ---------------------------------------------------------------------------
# AS number validation
# ---------------------------------------------------------------------------

_AS_RE = re.compile(r"^AS\d+$")


def _is_valid_as_number(value: str) -> bool:
    """Return True if *value* matches the AS number format (AS followed by digits)."""
    return bool(_AS_RE.match(value))


# ---------------------------------------------------------------------------
# AWG obfuscation validation
# ---------------------------------------------------------------------------


def _validate_awg_obfuscation(obf: AwgObfuscation) -> list[str]:
    """Validate AmneziaWG 2.0 obfuscation parameter ranges and constraints.

    Ranges per official AmneziaWG documentation:
    - S1: 0-1132 (random prefix for Init packets)
    - S2: 0-1188 (random prefix for Response packets)
    - S3: 0-1216 (random prefix for Cookie packets)
    - S4: 0-32 (random prefix for Data packets)
    - H1-H4: 5-2147483647, all distinct (non-overlapping)
    - Jc: 1-128
    - Jmin/Jmax: 0-1280, Jmin < Jmax
    - I1-I5: optional CPS format strings (not validated here)
    """
    errors: list[str] = []

    # S1: 0-1132
    if not (0 <= obf.s1 <= 1132):
        errors.append(f"AWG S1 must be 0-1132, got {obf.s1}")

    # S2: 0-1188, with constraint S1+56 != S2
    if not (0 <= obf.s2 <= 1188):
        errors.append(f"AWG S2 must be 0-1188, got {obf.s2}")

    # S3: 0-1216
    if not (0 <= obf.s3 <= 1216):
        errors.append(f"AWG S3 must be 0-1216, got {obf.s3}")

    # S4: 0-32
    if not (0 <= obf.s4 <= 32):
        errors.append(f"AWG S4 must be 0-32, got {obf.s4}")

    # Bidirectional constraint: S1+56 != S2 and S2+56 != S1
    if obf.s1 + 56 == obf.s2:
        errors.append(f"AWG S1+56 must not equal S2 ({obf.s1}+56 == {obf.s2})")
    if obf.s2 + 56 == obf.s1:
        errors.append(f"AWG S2+56 must not equal S1 ({obf.s2}+56 == {obf.s1})")

    # H1-H4: 5-2147483647, all distinct
    for name, val in [("H1", obf.h1), ("H2", obf.h2), ("H3", obf.h3), ("H4", obf.h4)]:
        if not (5 <= val <= 2147483647):
            errors.append(f"AWG {name} must be 5-2147483647, got {val}")

    h_values = [("H1", obf.h1), ("H2", obf.h2), ("H3", obf.h3), ("H4", obf.h4)]
    for i in range(len(h_values)):
        for j in range(i + 1, len(h_values)):
            if h_values[i][1] == h_values[j][1]:
                errors.append(
                    f"AWG {h_values[i][0]} and {h_values[j][0]} must not overlap "
                    f"(both are {h_values[i][1]})"
                )

    # Jc: 1-128
    if not (1 <= obf.jc <= 128):
        errors.append(f"AWG Jc must be 1-128, got {obf.jc}")

    # Jmin < Jmax, both 0-1280
    if obf.jmin >= obf.jmax:
        errors.append(f"AWG Jmin must be < Jmax ({obf.jmin} >= {obf.jmax})")
    if obf.jmax > 1280:
        errors.append(f"AWG Jmax must be <= 1280, got {obf.jmax}")
    if obf.jmin < 0:
        errors.append(f"AWG Jmin must be >= 0, got {obf.jmin}")

    return errors
