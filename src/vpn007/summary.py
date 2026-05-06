# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

"""Post-install summary and next-steps generator for VPN007.

Produces a formatted Markdown summary of the deployment result including
service statuses, public endpoints, VPN client connection instructions,
web panel access URLs, common management commands, and security reminders.
The summary is saved to ``{output_dir}/POST_INSTALL.md`` and printed to
the console.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vpn007.models import (
    AwgPeerConfig,
    DeployConfig,
    DeployResult,
    XrayClientConfig,
)

logger = logging.getLogger(__name__)

# The six containers that make up a full deployment.
_SERVICE_NAMES: list[str] = [
    "reverse_proxy",
    "three_x_ui",
    "amneziawg",
    "tailscale",
    "cover_site",
    "certbot",
]


def generate_summary(
    config: DeployConfig,
    deploy_result: DeployResult,
    client_configs: dict[str, XrayClientConfig | AwgPeerConfig],
) -> str:
    """Generate a formatted Markdown post-install summary.

    Parameters
    ----------
    config:
        The validated deployment configuration.
    deploy_result:
        Result of the deployment with per-service success/failure info.
    client_configs:
        Dict with optional ``'xray'`` (:class:`XrayClientConfig`) and
        ``'awg'`` (:class:`AwgPeerConfig`) keys containing the generated
        client configurations.

    Returns
    -------
    str
        A Markdown-formatted summary string.
    """
    sections: list[str] = []

    sections.append(_header())
    sections.append(_service_status_section(deploy_result))
    sections.append(_public_endpoints_section(config))
    sections.append(_vpn_client_section(config, client_configs))
    sections.append(_web_panel_section(config))
    sections.append(_management_commands_section(config))
    sections.append(_security_reminder_section(config))

    # Failed-service diagnostics (Req 19.7)
    failed_section = _failed_services_section(deploy_result)
    if failed_section:
        sections.append(failed_section)

    sections.append(_footer())

    return "\n".join(sections)


def save_summary(output_dir: Path, summary_text: str) -> Path:
    """Save the summary to ``{output_dir}/POST_INSTALL.md``.

    Parameters
    ----------
    output_dir:
        The deployment output directory.
    summary_text:
        The rendered Markdown summary.

    Returns
    -------
    Path
        The path to the saved file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "POST_INSTALL.md"
    path.write_text(summary_text, encoding="utf-8")
    logger.info("Saved post-install summary to %s", path)
    return path


# ---------------------------------------------------------------------------
# Internal section builders
# ---------------------------------------------------------------------------


def _header() -> str:
    return (
        "# VPN007 — Post-Install Summary\n"
        "\n"
        "Deployment completed. Review the sections below for service\n"
        "status, connection details, and management instructions.\n"
    )


def _service_status_section(deploy_result: DeployResult) -> str:
    """Req 19.1 — status of each deployed service (running/failed)."""
    lines: list[str] = [
        "## Service Status\n",
        "| Service | Status |",
        "|---------|--------|",
    ]
    for name in _SERVICE_NAMES:
        svc = deploy_result.services.get(name)
        if svc is None:
            status = "⚠️  not deployed"
        elif svc.success:
            status = "✅ running"
        else:
            status = "❌ failed"
        lines.append(f"| {name} | {status} |")
    lines.append("")
    return "\n".join(lines)


def _public_endpoints_section(config: DeployConfig) -> str:
    """Req 19.1 — public-facing endpoints."""
    server = config.domain
    lines: list[str] = [
        "## Public Endpoints\n",
        f"- **Domain**: `{config.domain}`",
        f"- **Server address**: `{server}`",
    ]
    if config.public_ipv4:
        lines.append(f"- **Public IPv4**: `{config.public_ipv4}`")
    if config.public_ipv6:
        lines.append(f"- **Public IPv6**: `{config.public_ipv6}`")
    lines.append(f"- **HTTPS**: port `443`")
    if config.enable_port_8443:
        lines.append(f"- **HTTPS (alt)**: port `8443`")
    if config.awg_listen_port is not None:
        lines.append(
            f"- **AmneziaWG (UDP)**: port `{config.awg_listen_port}`"
        )
    lines.append("")
    return "\n".join(lines)


def _vpn_client_section(
    config: DeployConfig,
    client_configs: dict[str, XrayClientConfig | AwgPeerConfig],
) -> str:
    """Req 19.2 — VPN client connection instructions."""
    lines: list[str] = [
        "## VPN Client Connection Instructions\n",
    ]

    # VLESS share link
    xray: XrayClientConfig | None = client_configs.get("xray")  # type: ignore[assignment]
    if xray is not None:
        lines.append("### Xray VLESS+Reality\n")
        lines.append(
            "1. Install a compatible client (v2rayNG, Nekoray, Shadowrocket)."
        )
        lines.append("2. Import the following VLESS share link:\n")
        lines.append(f"```\n{xray.vless_share_link}\n```\n")
        lines.append(
            "3. The share link can also be scanned as a QR code from the "
            f"client config file at `{config.output_dir}/clients/xray-{xray.client_name}.txt`."
        )
        lines.append("")

    # AmneziaWG config file path
    awg: AwgPeerConfig | None = client_configs.get("awg")  # type: ignore[assignment]
    if awg is not None:
        lines.append("### AmneziaWG\n")
        lines.append(
            "1. Install the AmneziaVPN or AmneziaWG client app."
        )
        lines.append(
            f"2. Import the config file: `{config.output_dir}/clients/awg-{awg.peer_name}.conf`"
        )
        lines.append("3. Connect using the imported tunnel.\n")

    # Tailscale join URL
    lines.append("### Tailscale\n")
    if config.tailscale_auth_key:
        lines.append(
            "Tailscale was configured with an auth key. The node should "
            "already be joined to your tailnet."
        )
    else:
        lines.append(
            "No Tailscale auth key was provided. Check the Tailscale "
            "container logs for the authentication URL:"
        )
        lines.append("")
        lines.append(
            "```bash\n"
            "docker compose logs tailscale\n"
            "```\n"
        )
        lines.append(
            "Open the URL in a browser to authorize the node on your tailnet."
        )
    lines.append("")
    return "\n".join(lines)


def _web_panel_section(config: DeployConfig) -> str:
    """Req 19.3 — web panel access URLs with approved-IP reminder."""
    server = config.domain
    lines: list[str] = [
        "## Web Panel Access\n",
        f"### 3x-ui Panel\n",
        f"- **URL**: `https://{server}{config.xui_path_prefix}/`",
        "",
        f"### AmneziaWG Panel\n",
        f"- **URL**: `https://{server}{config.awg_panel_path_prefix}/`",
        "",
        "> **Note**: Panel access is restricted to approved IPs only.",
    ]
    if config.approved_ips:
        ips = ", ".join(f"`{ip}`" for ip in config.approved_ips)
        lines.append(f"> Approved IPs: {ips}")
    if config.approved_hostnames:
        hosts = ", ".join(f"`{h}`" for h in config.approved_hostnames)
        lines.append(f"> Approved hostnames: {hosts}")
    lines.append("")
    return "\n".join(lines)


def _management_commands_section(config: DeployConfig) -> str:
    """Req 19.4 — common management commands."""
    compose_dir = config.output_dir
    lines: list[str] = [
        "## Common Management Commands\n",
        "### Add / Remove VPN Clients\n",
        "- **Xray**: Use the 3x-ui web panel to add or remove VLESS clients.",
        "- **AmneziaWG**: Use the AmneziaWG web panel to add or remove peers.\n",
        "### Restart Services\n",
        "```bash",
        f"cd {compose_dir}",
        "docker compose restart              # restart all services",
        "docker compose restart reverse_proxy # restart a single service",
        "```\n",
        "### View Logs\n",
        "```bash",
        f"cd {compose_dir}",
        "docker compose logs -f              # follow all logs",
        "docker compose logs three_x_ui      # logs for a single service",
        "```\n",
        "### Update Service Images\n",
        "```bash",
        f"cd {compose_dir}",
        "docker compose pull",
        "docker compose up -d",
        "```\n",
    ]
    return "\n".join(lines)


def _security_reminder_section(config: DeployConfig) -> str:
    """Req 19.5 — security reminder."""
    lines: list[str] = [
        "## Security Reminder\n",
    ]
    if config.approved_ips:
        ips = ", ".join(f"`{ip}`" for ip in config.approved_ips)
        lines.append(f"- **Approved IPs for panel access**: {ips}")
    if config.approved_hostnames:
        hosts = ", ".join(f"`{h}`" for h in config.approved_hostnames)
        lines.append(f"- **Approved hostnames**: {hosts}")
    if config.blocked_as_numbers:
        asns = ", ".join(f"`{a}`" for a in config.blocked_as_numbers)
        lines.append(f"- **Blocked AS numbers**: {asns}")
    if config.blocked_subnets:
        subnets = ", ".join(f"`{s}`" for s in config.blocked_subnets)
        lines.append(f"- **Blocked subnets**: {subnets}")
    lines.append(
        "- Review the nftables firewall rules in "
        f"`{config.output_dir}/nftables.conf` to verify they match your "
        "security requirements."
    )
    lines.append("")
    return "\n".join(lines)


def _failed_services_section(deploy_result: DeployResult) -> str | None:
    """Req 19.7 — error output and troubleshooting for failed services."""
    failed: list[tuple[str, str]] = []
    for name in _SERVICE_NAMES:
        svc = deploy_result.services.get(name)
        if svc is not None and not svc.success and svc.error is not None:
            failed.append((name, str(svc.error)))

    if not failed:
        return None

    lines: list[str] = [
        "## ⚠️  Failed Services\n",
    ]
    for name, error_msg in failed:
        svc = deploy_result.services[name]
        lines.append(f"### {name}\n")
        lines.append(f"**Error**: {error_msg}\n")
        if svc.error and svc.error.remediation:
            lines.append(f"**Suggested fix**: {svc.error.remediation}\n")
        lines.append("**Troubleshooting steps**:\n")
        lines.append(f"1. Check container logs: `docker compose logs {name}`")
        lines.append(
            f"2. Try restarting the service: `docker compose restart {name}`"
        )
        lines.append(
            "3. Review the troubleshooting guide in "
            f"`{deploy_result.services[name].error.service if svc.error else name}` section "
            "of `docs/troubleshooting.md`."
        )
        lines.append("")
    return "\n".join(lines)


def _footer() -> str:
    return (
        "---\n"
        "\n"
        "© Vadim Pavlov 2026. Licensed under GPL-3.0.\n"
    )
