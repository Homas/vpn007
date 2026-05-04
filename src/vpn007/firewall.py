# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""nftables firewall configuration generator for VPN007.

Generates an nftables ruleset from a Jinja2 template with:

- Default-deny input policy
- Named sets for blocked IPv4/IPv6 prefixes (AS and subnet blocking)
- Named set for approved SSH source IPs
- Accept rules for 443/tcp, optionally 8443/tcp, AmneziaWG UDP port
- SSH access restricted to approved IPs
- Blocked sets referenced in both input and output chains
- Optional SNAT rule for multi-IP outgoing traffic

Also provides AS-to-prefix resolution via Team Cymru whois with RIPE RIS
API fallback.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vpn007.models import DeployConfig

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


def _classify_prefixes(
    subnets: list[str],
) -> tuple[list[str], list[str]]:
    """Classify a list of CIDR prefixes into IPv4 and IPv6 lists.

    Invalid prefixes are logged and skipped.
    """
    v4: list[str] = []
    v6: list[str] = []
    for prefix in subnets:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if net.version == 4:
                v4.append(str(net))
            else:
                v6.append(str(net))
        except ValueError:
            logger.warning("Skipping invalid prefix: %s", prefix)
    return v4, v6


def generate_nftables_config(config: DeployConfig) -> str:
    """Generate ``nftables.conf`` content from a deployment config.

    The generated ruleset implements a default-deny input policy with
    explicit accept rules for required service ports, SSH from approved
    IPs, and AS/subnet blocking in both input and output chains.

    Port 80 is intentionally NOT included in the base ruleset — it is
    opened dynamically by the certbot renewal script's pre/post-hook
    only during the brief renewal window.

    Panel access restriction is handled at the Nginx level via
    ``allow``/``deny`` directives, not in nftables.

    Parameters
    ----------
    config:
        The validated deployment configuration.

    Returns
    -------
    str
        The rendered ``nftables.conf`` content.
    """
    env = _create_jinja_env()
    template = env.get_template("nftables.conf.j2")

    # Collect all blocked prefixes: explicit subnets + resolved AS prefixes
    all_blocked = list(config.blocked_subnets)

    # Classify into v4 and v6
    blocked_v4, blocked_v6 = _classify_prefixes(all_blocked)

    context = {
        "blocked_v4_prefixes": blocked_v4,
        "blocked_v6_prefixes": blocked_v6,
        "ssh_approved_ips": config.ssh_approved_ips,
        "enable_port_8443": config.enable_port_8443,
        "https_port": config.https_port,
        "awg_listen_port": config.awg_listen_port,
        "outgoing_ip": config.outgoing_ip,
    }

    return template.render(context)


def resolve_as_prefixes(as_numbers: list[str]) -> dict[str, list[str]]:
    """Resolve AS numbers to their announced IP prefixes.

    Uses a two-tier resolution strategy:

    1. **Primary**: Team Cymru whois (``whois -h whois.radb.net``)
    2. **Fallback**: RIPE RIS API
       (``https://stat.ripe.net/data/announced-prefixes/data.json``)

    Parameters
    ----------
    as_numbers:
        List of AS number strings (e.g. ``["AS196747", "AS12345"]``).

    Returns
    -------
    dict[str, list[str]]
        Mapping of AS number → list of announced CIDR prefixes.
        AS numbers that could not be resolved map to empty lists.
    """
    results: dict[str, list[str]] = {}
    for asn in as_numbers:
        # Strip "AS" prefix for queries
        asn_num = asn.upper().removeprefix("AS")
        prefixes = _resolve_via_whois(asn_num)
        if prefixes is None:
            logger.info(
                "Whois resolution failed for %s, trying RIPE RIS API", asn
            )
            prefixes = _resolve_via_ripe(asn_num)
        if prefixes is None:
            logger.warning("Could not resolve prefixes for %s", asn)
            prefixes = []
        results[asn] = prefixes
    return results


def _resolve_via_whois(asn_num: str) -> list[str] | None:
    """Resolve AS prefixes via Team Cymru / RADB whois.

    Queries ``whois -h whois.radb.net -- -i origin AS<number>`` and
    parses ``route:`` and ``route6:`` lines from the output.

    Returns a list of CIDR prefixes, or ``None`` if the query fails.
    """
    try:
        result = subprocess.run(
            ["whois", "-h", "whois.radb.net", "--", "-i", "origin", f"AS{asn_num}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None

        prefixes: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("route:") or line.startswith("route6:"):
                prefix = line.split(":", 1)[1].strip()
                try:
                    ipaddress.ip_network(prefix, strict=False)
                    prefixes.append(prefix)
                except ValueError:
                    continue
        return prefixes if prefixes else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _resolve_via_ripe(asn_num: str) -> list[str] | None:
    """Resolve AS prefixes via RIPE RIS API.

    Queries the RIPE Stat announced-prefixes endpoint and parses the
    JSON response for prefix entries.

    Returns a list of CIDR prefixes, or ``None`` if the query fails.
    """
    url = (
        f"https://stat.ripe.net/data/announced-prefixes/data.json"
        f"?resource=AS{asn_num}"
    )
    try:
        result = subprocess.run(
            ["curl", "-s", "-m", "30", url],
            capture_output=True,
            text=True,
            timeout=35,
        )
        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        prefixes_data = data.get("data", {}).get("prefixes", [])
        prefixes: list[str] = []
        for entry in prefixes_data:
            prefix = entry.get("prefix", "")
            try:
                ipaddress.ip_network(prefix, strict=False)
                prefixes.append(prefix)
            except ValueError:
                continue
        return prefixes if prefixes else None
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
        KeyError,
    ):
        return None
