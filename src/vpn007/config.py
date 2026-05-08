# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Configuration loading, merging, and public IP detection for VPN007."""

from __future__ import annotations

import argparse
import os
import random
import secrets
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

from vpn007.models import (
    AwgObfuscation,
    CoverSiteMode,
    DeployConfig,
    ForwardingMode,
    PortForward,
    TunnelType,
)

# ---------------------------------------------------------------------------
# Environment variable name → DeployConfig field mapping
# ---------------------------------------------------------------------------
# Maps UPPER_SNAKE_CASE env var names to (field_name, type_converter) pairs.
# Type converters accept a string and return the appropriate Python type.

_BOOL_TRUE = {"true", "yes", "1", "y", "on"}
_BOOL_FALSE = {"false", "no", "0", "n", "off"}


def _parse_bool(value: str) -> bool:
    """Parse a boolean from a string value."""
    lower = value.strip().lower()
    if lower in _BOOL_TRUE:
        return True
    if lower in _BOOL_FALSE:
        return False
    raise ValueError(f"Cannot parse boolean from {value!r}")


def _parse_int_or_none(value: str) -> int | None:
    """Parse an int, returning None for empty strings."""
    stripped = value.strip()
    if not stripped:
        return None
    return int(stripped)


def _parse_comma_list(value: str) -> list[str]:
    """Parse a comma-separated list, stripping whitespace and filtering empties."""
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_port_forwards(value: str) -> list[PortForward]:
    """Parse comma-separated PortForward entries.

    Format: "protocol:listen_port:forward_port:description"
    Example: "tcp:443:443:HTTPS,udp:51820:51820:WireGuard"
    """
    entries: list[PortForward] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) < 3:
            raise ValueError(
                f"Invalid port forward format {item!r}; "
                "expected 'protocol:listen_port:forward_port[:description]'"
            )
        protocol = parts[0].strip()
        listen_port = int(parts[1].strip())
        forward_port = int(parts[2].strip())
        description = parts[3].strip() if len(parts) > 3 else ""
        entries.append(
            PortForward(
                protocol=protocol,
                listen_port=listen_port,
                forward_port=forward_port,
                description=description,
            )
        )
    return entries


def _parse_cover_site_mode(value: str) -> CoverSiteMode:
    """Parse CoverSiteMode enum from string."""
    return CoverSiteMode(value.strip().lower())


def _parse_tunnel_type(value: str) -> TunnelType | None:
    """Parse TunnelType enum from string, returning None for empty."""
    stripped = value.strip().lower()
    if not stripped:
        return None
    return TunnelType(stripped)


def _parse_forwarding_mode(value: str) -> ForwardingMode:
    """Parse ForwardingMode enum from string."""
    return ForwardingMode(value.strip().lower())


def _parse_tls_versions(value: str) -> list[str]:
    """Parse TLS version list from comma-separated string."""
    return [v.strip() for v in value.split(",") if v.strip()]


def _parse_path_or_none(value: str) -> Path | None:
    """Parse a Path from string, returning None for empty."""
    stripped = value.strip()
    if not stripped:
        return None
    return Path(stripped)


def _parse_path(value: str) -> Path:
    """Parse a Path from string."""
    return Path(value.strip())


# ---------------------------------------------------------------------------
# Env var → field mapping table
# ---------------------------------------------------------------------------
# Each entry: (env_var_name, deploy_config_field_name, converter)
# Converter is a callable(str) -> appropriate type.

_ENV_FIELD_MAP: list[tuple[str, str, type | object]] = [
    # General
    ("DOMAIN", "domain", str),
    ("REALITY_SNI", "reality_sni", str),
    ("COVER_SITE_MODE", "cover_site_mode", _parse_cover_site_mode),
    ("COVER_SITE_URL", "cover_site_url", str),
    ("COVER_SITE_STATIC_PATH", "cover_site_static_path", _parse_path_or_none),
    # Routing paths
    ("XUI_PATH_PREFIX", "xui_path_prefix", str),
    ("AWG_PANEL_PATH_PREFIX", "awg_panel_path_prefix", str),
    ("ENABLE_PORT_8443", "enable_port_8443", _parse_bool),
    # Xray / Reality
    ("XRAY_INTERNAL_PORT", "xray_internal_port", int),
    # AmneziaWG
    ("AWG_LISTEN_PORT", "awg_listen_port", _parse_int_or_none),
    ("AWG_PANEL_PORT", "awg_panel_port", int),
    # Tailscale
    ("TAILSCALE_AUTH_KEY", "tailscale_auth_key", str),
    ("TAILSCALE_HOSTNAME", "tailscale_hostname", str),
    ("TAILSCALE_EXTRA_ARGS", "tailscale_extra_args", str),
    # Multi-IP
    ("INCOMING_IP", "incoming_ip", str),
    ("OUTGOING_IP", "outgoing_ip", str),
    ("PUBLIC_IPV4", "public_ipv4", str),
    ("PUBLIC_IPV6", "public_ipv6", str),
    # TLS
    ("TLS_VERSIONS", "tls_versions", _parse_tls_versions),
    ("SKIP_CERTBOT", "skip_certbot", _parse_bool),
    ("HTTPS_PORT", "https_port", int),
    # Access control
    ("APPROVED_IPS", "approved_ips", _parse_comma_list),
    ("APPROVED_HOSTNAMES", "approved_hostnames", _parse_comma_list),
    ("SSH_APPROVED_IPS", "ssh_approved_ips", _parse_comma_list),
    ("SSH_APPROVED_HOSTNAMES", "ssh_approved_hostnames", _parse_comma_list),
    ("HOSTNAME_RESOLVE_INTERVAL_MIN", "hostname_resolve_interval_min", int),
    # AS/Subnet blocking
    ("BLOCKED_AS_NUMBERS", "blocked_as_numbers", _parse_comma_list),
    ("BLOCKED_SUBNETS", "blocked_subnets", _parse_comma_list),
    ("BLOCKLIST_UPDATE_INTERVAL_HOURS", "blocklist_update_interval_hours", int),
    # Forwarding
    ("FORWARDING_ENABLED", "forwarding_enabled", _parse_bool),
    ("FORWARDING_MODE", "forwarding_mode", _parse_forwarding_mode),
    ("TUNNEL_TYPE", "tunnel_type", _parse_tunnel_type),
    ("SECONDARY_VM_IP", "secondary_vm_ip", str),
    ("REVERSE_INITIATED", "reverse_initiated", _parse_bool),
    ("FORWARDING_PORTS", "forwarding_ports", _parse_port_forwards),
    ("RECONNECT_INITIAL_DELAY_SEC", "reconnect_initial_delay_sec", int),
    ("RECONNECT_MAX_DELAY_SEC", "reconnect_max_delay_sec", int),
    ("TUNNEL_SUBNET", "tunnel_subnet", str),
    # Exit node role
    ("EXIT_NODE_ENABLED", "exit_node_enabled", _parse_bool),
    ("EXIT_NODE_TUNNEL_TYPE", "exit_node_tunnel_type", _parse_tunnel_type),
    ("EXIT_NODE_PEER_IP", "exit_node_peer_ip", str),
    ("EXIT_NODE_TUNNEL_SUBNET", "exit_node_tunnel_subnet", str),
    ("EXIT_NODE_LISTEN_PORT", "exit_node_listen_port", int),
    ("EXIT_NODE_REVERSE_INITIATED", "exit_node_reverse_initiated", _parse_bool),
    # Initial clients
    ("XRAY_INITIAL_CLIENT", "xray_initial_client", str),
    ("AWG_INITIAL_PEER", "awg_initial_peer", str),
    # Output
    ("OUTPUT_DIR", "output_dir", _parse_path),
    ("DEPLOYMENT_LOG_PATH", "deployment_log_path", _parse_path),
]

# Build a quick lookup: field_name → (env_var_name, converter)
_FIELD_TO_ENV: dict[str, tuple[str, type | object]] = {
    field: (env_var, conv) for env_var, field, conv in _ENV_FIELD_MAP
}

# Build reverse lookup: env_var_name → (field_name, converter)
_ENV_TO_FIELD: dict[str, tuple[str, type | object]] = {
    env_var: (field, conv) for env_var, field, conv in _ENV_FIELD_MAP
}


# ---------------------------------------------------------------------------
# AwgObfuscation env var parsing
# ---------------------------------------------------------------------------
_AWG_OBF_FIELDS = [
    "AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4",
    "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4",
    "AWG_JC", "AWG_JMIN", "AWG_JMAX",
    "AWG_I1", "AWG_I2", "AWG_I3", "AWG_I4", "AWG_I5",
]

# Fields that trigger "partial config" detection — I1-I5 are always optional
# and do NOT require S/H params to be present.
_AWG_CORE_FIELDS = [
    "AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4",
    "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4",
    "AWG_JC", "AWG_JMIN", "AWG_JMAX",
]


def _parse_awg_obfuscation(env: dict[str, str | None]) -> AwgObfuscation | None:
    """Parse AwgObfuscation from individual AWG_* env vars.

    Returns None if none of the core AWG obfuscation env vars (S/H/J) are set.
    I1-I5 alone do NOT trigger obfuscation config — they are stored separately
    and applied to the auto-generated config if S/H params are not provided.
    Raises ValueError if only some S/H params are set (partial config).
    """
    # Only core fields (S/H/J) trigger the obfuscation config path
    core_present = {k for k in _AWG_CORE_FIELDS if env.get(k)}
    if not core_present:
        # No core params set — check if only I1-I5 are provided
        # If so, return None (auto-generate S/H/J, I values applied later)
        return None

    # All required fields for a complete obfuscation config
    required = {"AWG_S1", "AWG_S2", "AWG_S3", "AWG_S4",
                "AWG_H1", "AWG_H2", "AWG_H3", "AWG_H4"}
    missing = required - core_present
    if missing:
        raise ValueError(
            f"Partial AmneziaWG obfuscation config: missing {', '.join(sorted(missing))}. "
            "Provide all S1-S4 and H1-H4 parameters, or omit all for auto-generation."
        )

    def _get_int(key: str, default: int | None = None) -> int:
        val = env.get(key)
        if val is None or val.strip() == "":
            if default is not None:
                return default
            raise ValueError(f"Missing required AWG obfuscation parameter: {key}")
        return int(val.strip())

    # Default to WebRTC/STUN signatures when I params are absent from env.
    # If the key is present (even as empty string AWG_I1=), respect that choice.
    _AWG_I_DEFAULTS = {
        "AWG_I1": "<b 0x000100002112a442><r 12>",
        "AWG_I2": "<b 0x0101><r 4><t><r 8>",
        "AWG_I3": "<r 32>",
    }

    def _get_i(key: str) -> str:
        if key not in env:
            return _AWG_I_DEFAULTS.get(key, "")
        val = env[key]
        return val.strip() if val else ""

    return AwgObfuscation(
        s1=_get_int("AWG_S1"),
        s2=_get_int("AWG_S2"),
        s3=_get_int("AWG_S3"),
        s4=_get_int("AWG_S4"),
        h1=env.get("AWG_H1", "").strip(),
        h2=env.get("AWG_H2", "").strip(),
        h3=env.get("AWG_H3", "").strip(),
        h4=env.get("AWG_H4", "").strip(),
        jc=_get_int("AWG_JC", default=4),
        jmin=_get_int("AWG_JMIN", default=50),
        jmax=_get_int("AWG_JMAX", default=1000),
        i1=_get_i("AWG_I1"),
        i2=_get_i("AWG_I2"),
        i3=_get_i("AWG_I3"),
        i4=_get_i("AWG_I4"),
        i5=_get_i("AWG_I5"),
    )


# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def detect_public_ips() -> tuple[str | None, str | None]:
    """Auto-detect public IPv4 and IPv6 addresses.

    Uses ``curl -4 ifconfig.me`` for IPv4 and ``curl -6 ifconfig.me`` for IPv6.
    Returns (ipv4, ipv6) where either may be None if detection fails.
    """
    ipv4 = _curl_ip("-4")
    ipv6 = _curl_ip("-6")
    return ipv4, ipv6


def _curl_ip(flag: str) -> str | None:
    """Run ``curl <flag> ifconfig.me`` and return the trimmed output, or None."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "10", flag, "ifconfig.me"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------

def _is_interactive() -> bool:
    """Return True if running in interactive mode (not AUTO_INSTALL=y)."""
    auto = os.environ.get("AUTO_INSTALL", "").strip().lower()
    return auto not in _BOOL_TRUE


def _prompt_ip(label: str, detected: str | None) -> str | None:
    """Prompt the operator to confirm or override a detected IP address.

    Returns the confirmed/overridden IP, or None if the operator declines.
    """
    if detected:
        answer = input(
            f"Detected {label}: {detected}. Press Enter to accept, "
            "or type a new value: "
        ).strip()
        return answer if answer else detected
    else:
        answer = input(
            f"Could not detect {label}. Enter it manually (or press Enter to skip): "
        ).strip()
        return answer if answer else None


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _read_env_file(env_file_path: str | Path = ".env") -> dict[str, str | None]:
    """Read a .env file if it exists, returning a dict of key→value.

    Returns an empty dict if the file does not exist.
    """
    path = Path(env_file_path)
    if not path.is_file():
        return {}
    return dotenv_values(path)


def _persist_generated_value(env_file: str | Path, key: str, value: str) -> None:
    """Append a generated value to the .env file so it persists across re-deploys.

    Only appends if the key is not already present in the file.
    """
    import logging

    _logger = logging.getLogger("vpn007")
    path = Path(env_file)

    # Check if key already exists
    if path.is_file():
        content = path.read_text()
        if f"{key}=" in content:
            return

    try:
        with path.open("a") as f:
            f.write(f"\n# Auto-generated by VPN007 (do not remove)\n{key}={value}\n")
        _logger.info("Persisted %s=%s to %s", key, value, path)
    except OSError as exc:
        _logger.warning("Could not persist %s to %s: %s", key, path, exc)


def _cli_args_to_dict(cli_args: argparse.Namespace) -> dict[str, object]:
    """Convert argparse Namespace to a dict, excluding None values.

    Only includes keys that were explicitly provided by the user (not defaults).
    """
    result: dict[str, object] = {}
    for key, value in vars(cli_args).items():
        if value is not None:
            result[key] = value
    return result


def load_config(cli_args: argparse.Namespace) -> DeployConfig:
    """Load deployment configuration from .env file and CLI args.

    Precedence (highest to lowest):
    1. CLI arguments
    2. .env file values
    3. DeployConfig defaults

    When public IPs are not provided, auto-detects them. In interactive mode,
    prompts the operator to confirm/override. In non-interactive mode, uses
    detected values or exits with error if detection fails.
    """
    # 1. Read .env file
    env_file = getattr(cli_args, "env_file", ".env")
    env_values = _read_env_file(env_file)

    # 2. Get CLI args as dict (only explicitly provided values)
    cli_dict = _cli_args_to_dict(cli_args)

    # 3. Build merged config dict: start with env, override with CLI
    config_kwargs: dict[str, object] = {}

    for env_var, field_name, converter in _ENV_FIELD_MAP:
        # CLI takes precedence
        if field_name in cli_dict:
            raw_cli = cli_dict[field_name]
            # Apply the converter to CLI values too (e.g. str → Path, str → int)
            if isinstance(raw_cli, str):
                try:
                    config_kwargs[field_name] = converter(raw_cli)
                except (ValueError, KeyError):
                    config_kwargs[field_name] = raw_cli
            else:
                config_kwargs[field_name] = raw_cli
        elif env_var in env_values and env_values[env_var] is not None:
            raw = env_values[env_var]
            assert raw is not None  # for type checker
            try:
                config_kwargs[field_name] = converter(raw)
            except (ValueError, KeyError) as exc:
                raise SystemExit(
                    f"Error parsing {env_var}={raw!r}: {exc}"
                ) from exc

    # 4. Parse AWG obfuscation from individual env vars (if not set via CLI)
    if "awg_obfuscation" in cli_dict:
        config_kwargs["awg_obfuscation"] = cli_dict["awg_obfuscation"]
    else:
        # Merge env file values with os.environ for AWG fields
        awg_env: dict[str, str | None] = {}
        for key in _AWG_OBF_FIELDS:
            if key in env_values and env_values[key] is not None:
                awg_env[key] = env_values[key]
        awg_obf = _parse_awg_obfuscation(awg_env)
        if awg_obf is not None:
            config_kwargs["awg_obfuscation"] = awg_obf

    # 5. Auto-randomize awg_listen_port if not set
    if "awg_listen_port" not in config_kwargs or config_kwargs["awg_listen_port"] is None:
        config_kwargs["awg_listen_port"] = random.randint(10000, 65535)
        _persist_generated_value(env_file, "AWG_LISTEN_PORT", str(config_kwargs["awg_listen_port"]))

    # 5b. Append random suffix to panel path prefixes if not explicitly set
    if "xui_path_prefix" not in config_kwargs:
        suffix = secrets.token_hex(3)  # 6 hex chars
        config_kwargs["xui_path_prefix"] = f"/secretpanel-{suffix}"
        _persist_generated_value(env_file, "XUI_PATH_PREFIX", config_kwargs["xui_path_prefix"])
    if "awg_panel_path_prefix" not in config_kwargs:
        suffix = secrets.token_hex(3)
        config_kwargs["awg_panel_path_prefix"] = f"/awgadmin-{suffix}"
        _persist_generated_value(env_file, "AWG_PANEL_PATH_PREFIX", config_kwargs["awg_panel_path_prefix"])

    # 6. Handle public IP detection
    _resolve_public_ips(config_kwargs)

    # 7. Build DeployConfig
    return DeployConfig(**config_kwargs)  # type: ignore[arg-type]


def _resolve_public_ips(config_kwargs: dict[str, object]) -> None:
    """Detect and resolve public IPs, prompting in interactive mode.

    Modifies *config_kwargs* in place to set ``public_ipv4`` and ``public_ipv6``
    when they are not already provided.

    In non-interactive mode (AUTO_INSTALL=y), uses detected values or exits
    with an error if detection fails and no IPs are provided.
    """
    interactive = _is_interactive()

    ipv4_provided = bool(config_kwargs.get("public_ipv4"))
    ipv6_provided = bool(config_kwargs.get("public_ipv6"))

    if ipv4_provided and ipv6_provided:
        return  # Both already provided, nothing to do

    # Auto-detect missing IPs
    detected_v4: str | None = None
    detected_v6: str | None = None

    if not ipv4_provided or not ipv6_provided:
        detected_v4, detected_v6 = detect_public_ips()

    # Resolve IPv4
    if not ipv4_provided:
        if interactive:
            resolved = _prompt_ip("public IPv4", detected_v4)
            if resolved:
                config_kwargs["public_ipv4"] = resolved
            # In interactive mode, it's okay to skip IPv4 if operator declines
        else:
            if detected_v4:
                config_kwargs["public_ipv4"] = detected_v4
            else:
                # Non-interactive mode: IPv4 detection failed, exit with error
                print(
                    "ERROR: Could not auto-detect public IPv4 address. "
                    "Set PUBLIC_IPV4 in .env or pass --public-ipv4.",
                    file=sys.stderr,
                )
                raise SystemExit(1)

    # Resolve IPv6
    if not ipv6_provided:
        if interactive:
            resolved = _prompt_ip("public IPv6", detected_v6)
            if resolved:
                config_kwargs["public_ipv6"] = resolved
        else:
            # IPv6 is optional — use detected value if available, skip otherwise
            if detected_v6:
                config_kwargs["public_ipv6"] = detected_v6
