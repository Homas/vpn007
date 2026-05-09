#!/usr/bin/env python3
"""Scan a subnet for open HTTP/HTTPS ports, resolve hostnames, and extract TLS certificate CNs.

Usage:
    python scripts/scan_subnet.py <subnet> [--format text|csv|json]

Examples:
    python scripts/scan_subnet.py 192.168.1.0/24
    python scripts/scan_subnet.py 10.0.0.0/24 --format json
    python scripts/scan_subnet.py 203.0.113.0/28 --format csv

Requirements (system):
    - nmap
    - dig (bind-utils / dnsutils)
    - openssl
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class HostInfo:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    cert_cn: str = ""
    cert_sans: list[str] = field(default_factory=list)
    cn_matches_ip: bool = False

    @property
    def cert_names(self) -> list[str]:
        """Unique certificate names: CN followed by SANs (deduplicated)."""
        seen: set[str] = set()
        result: list[str] = []
        for name in [self.cert_cn, *self.cert_sans]:
            if name and name not in seen:
                seen.add(name)
                result.append(name)
        return result


def check_dependencies() -> None:
    """Verify required system tools are available."""
    missing = []
    for tool in ("nmap", "dig", "openssl"):
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        sys.exit(f"Error: missing required tools: {', '.join(missing)}")


def scan_subnet(subnet: str) -> list[HostInfo]:
    """Run nmap to find hosts with open ports 80 and/or 443."""
    cmd = ["nmap", "-p", "80,443", "--open", "-oG", "-", subnet]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        sys.exit(f"nmap failed:\n{result.stderr}")

    hosts: list[HostInfo] = []
    for line in result.stdout.splitlines():
        if not line.startswith("Host:"):
            continue
        # Format: Host: 1.2.3.4 ()  Ports: 80/open/tcp//http///, 443/open/tcp//https///
        ip_match = re.search(r"Host:\s+([\d.]+)", line)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        ports_section = line.split("Ports:")[1] if "Ports:" in line else ""
        open_ports: list[int] = []
        for port_entry in ports_section.split(","):
            port_entry = port_entry.strip()
            parts = port_entry.split("/")
            if len(parts) >= 2 and parts[1] == "open":
                try:
                    open_ports.append(int(parts[0]))
                except ValueError:
                    continue
        if open_ports:
            hosts.append(HostInfo(ip=ip, open_ports=open_ports))
    return hosts


def reverse_lookup(ip: str) -> list[str]:
    """Perform reverse DNS lookup using dig -x. Returns list of PTR hostnames."""
    try:
        result = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True,
            text=True,
            timeout=10,
        )
        names: list[str] = []
        for line in result.stdout.strip().splitlines():
            name = line.strip().rstrip(".")
            if name:
                names.append(name)
        return names
    except (subprocess.TimeoutExpired, OSError):
        return []


def resolve_name(name: str) -> list[str]:
    """Resolve a hostname to its A-record IPs using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "A", name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ips: list[str] = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            # Only keep lines that look like IPs (skip CNAMEs)
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                ips.append(line)
        return ips
    except (subprocess.TimeoutExpired, OSError):
        return []


def get_certificate_names(ip: str, port: int = 443) -> tuple[str, list[str]]:
    """Connect via openssl and extract CN and SANs from the certificate.

    Returns (common_name, list_of_sans).
    """
    try:
        result = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{ip}:{port}",
                "-servername",
                ip,
            ],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
        )
        cert_text = result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ("", [])

    # Extract the certificate block
    cert_match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        cert_text,
        re.DOTALL,
    )
    if not cert_match:
        return ("", [])

    cert_pem = cert_match.group(1)

    # Parse with openssl x509
    try:
        x509_result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-ext", "subjectAltName"],
            input=cert_pem,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = x509_result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ("", [])

    # Extract CN
    cn = ""
    cn_match = re.search(r"CN\s*=\s*([^\n/,]+)", output)
    if cn_match:
        cn = cn_match.group(1).strip()

    # Extract SANs
    sans: list[str] = []
    san_matches = re.findall(r"DNS:([^\s,]+)", output)
    if san_matches:
        sans = [s.strip() for s in san_matches]

    return (cn, sans)


def enrich_hosts(hosts: list[HostInfo]) -> None:
    """Add reverse DNS and certificate info to each host."""
    for host in hosts:
        host.hostnames = reverse_lookup(host.ip)
        if 443 in host.open_ports:
            cn, sans = get_certificate_names(host.ip)
            host.cert_cn = cn
            host.cert_sans = sans
            # Check if CN resolves back to this IP
            if cn and not cn.startswith("*"):
                resolved_ips = resolve_name(cn)
                host.cn_matches_ip = host.ip in resolved_ips


def format_text(hosts: list[HostInfo]) -> str:
    """Produce a tabulated text table with DNS and CN/SANs in separate columns.

    Output format:
        IP              Ports     DNS (rDNS)                  CN/SANs
        --------------- --------- --------------------------- ----------------------------
        45.143.94.9     80, 443   -                           tengizchevroil.indigotech.ru
        45.143.94.11    80, 443   -                           k-labgame.com
                                                              api.k-labgame.com
                                                              cdn.k-labgame.com
        45.143.94.36    80, 443   domimaster.ru               domimaster.ru
                                  toksila.ru                  www.domimaster.ru
                                  remtok.ru
    """
    # Determine column widths
    ip_w = max(len("IP"), *(len(h.ip) for h in hosts))
    ports_w = max(len("Ports"), *(len(", ".join(str(p) for p in h.open_ports)) for h in hosts))
    dns_w = max(
        len("DNS (rDNS)"),
        *(len(name) for h in hosts for name in h.hostnames),
        1,
    )
    cn_w = max(
        len("CN/SANs"),
        *(len(name) + 2 for h in hosts for name in h.cert_names),  # +1 for potential * (space *)
        1,
    )

    hdr = f"{'IP':<{ip_w}}  {'Ports':<{ports_w}}  {'DNS (rDNS)':<{dns_w}}  {'CN/SANs'}"
    sep = f"{'-' * ip_w}  {'-' * ports_w}  {'-' * dns_w}  {'-' * cn_w}"
    lines = [hdr, sep]

    for h in hosts:
        ports_str = ", ".join(str(p) for p in h.open_ports)
        dns_list = h.hostnames if h.hostnames else ["-"]
        cn_list = h.cert_names if h.cert_names else ["-"]
        # Mark first entry (CN) with * if it resolves to this IP
        if h.cn_matches_ip and cn_list[0] != "-":
            cn_list = [f"{cn_list[0]} *"] + cn_list[1:]
        row_count = max(len(dns_list), len(cn_list))

        for i in range(row_count):
            ip_cell = h.ip if i == 0 else ""
            ports_cell = ports_str if i == 0 else ""
            dns_cell = dns_list[i] if i < len(dns_list) else ""
            cn_cell = cn_list[i] if i < len(cn_list) else ""
            lines.append(
                f"{ip_cell:<{ip_w}}  {ports_cell:<{ports_w}}  {dns_cell:<{dns_w}}  {cn_cell}"
            )

    return "\n".join(lines)


def format_csv(hosts: list[HostInfo]) -> str:
    """Produce CSV output with one row per IP."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["IP", "Open Ports", "DNS (rDNS)", "CN/SANs", "CN Matches IP"])
    for h in hosts:
        writer.writerow([
            h.ip,
            ", ".join(str(p) for p in h.open_ports),
            "; ".join(h.hostnames) if h.hostnames else "",
            "; ".join(h.cert_names) if h.cert_names else "",
            h.cn_matches_ip,
        ])
    return buf.getvalue()


def format_json(hosts: list[HostInfo]) -> str:
    """Produce JSON output."""
    data = [
        {
            "ip": h.ip,
            "open_ports": h.open_ports,
            "dns": h.hostnames,
            "cert_names": h.cert_names,
            "cn_matches_ip": h.cn_matches_ip,
        }
        for h in hosts
    ]
    return json.dumps(data, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan subnet for open HTTP/HTTPS ports, resolve hostnames, extract TLS certs."
    )
    parser.add_argument("subnet", help="Target subnet in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "csv", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    check_dependencies()

    print(f"Scanning {args.subnet} ...", file=sys.stderr)
    hosts = scan_subnet(args.subnet)

    if not hosts:
        print("No hosts with open ports 80/443 found.", file=sys.stderr)
        sys.exit(0)

    print(f"Found {len(hosts)} host(s). Enriching with DNS and TLS info ...", file=sys.stderr)
    enrich_hosts(hosts)

    formatters = {
        "text": format_text,
        "csv": format_csv,
        "json": format_json,
    }
    print(formatters[args.format](hosts))


if __name__ == "__main__":
    main()
