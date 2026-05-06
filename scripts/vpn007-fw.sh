#!/usr/bin/env bash
# vpn007-fw.sh — Simplified firewall management for VPN007
#
# Manage blocked/allowed IPs, subnets, and AS numbers in the running
# nftables firewall without regenerating the full config.
#
# Usage:
#   vpn007-fw.sh block ip <IP_OR_CIDR>       Block an IP or subnet
#   vpn007-fw.sh unblock ip <IP_OR_CIDR>     Unblock an IP or subnet
#   vpn007-fw.sh block as <AS_NUMBER>         Block all prefixes for an AS
#   vpn007-fw.sh unblock as <AS_NUMBER>       Unblock all prefixes for an AS
#   vpn007-fw.sh allow ssh <IP_OR_CIDR>       Allow SSH from an IP/subnet
#   vpn007-fw.sh deny ssh <IP_OR_CIDR>        Remove SSH allow for an IP/subnet
#   vpn007-fw.sh allow panel <IP_OR_CIDR>     Allow panel access from an IP/subnet
#   vpn007-fw.sh deny panel <IP_OR_CIDR>      Remove panel access for an IP/subnet
#   vpn007-fw.sh list                          Show current sets and rules
#   vpn007-fw.sh list blocked                  Show blocked IPs/subnets
#   vpn007-fw.sh list ssh                      Show SSH-approved IPs
#   vpn007-fw.sh resolve as <AS_NUMBER>        Resolve AS to prefixes (dry-run)
#
# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NGINX_APPROVED_CONF="/etc/nginx/conf.d/approved_panel_ips.conf"
COMPOSE_DIR="${VPN007_DIR:-/opt/vpn007}"
NFTABLES_CONF="${VPN007_NFTABLES_CONF:-/etc/nftables.conf}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[+] $*"; }
log_error() { echo "[!] $*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This command requires root. Run with sudo."
        exit 1
    fi
}

is_ipv6() {
    [[ "$1" == *:* ]]
}

# Save the current nftables ruleset to disk so changes survive reboot.
persist_nftables() {
    nft list ruleset > "$NFTABLES_CONF"
    log_info "Ruleset saved to $NFTABLES_CONF (persistent across reboots)"
}

# Resolve an AS number to its announced IPv4 prefixes via Team Cymru whois
resolve_as_prefixes() {
    local as_number="$1"
    # Strip "AS" prefix if present
    local asn="${as_number#AS}"
    asn="${asn#as}"

    # Primary: Team Cymru bulk whois
    local prefixes
    prefixes=$(whois -h whois.radb.net -- "-i origin AS${asn}" 2>/dev/null \
        | grep -oP '^\s*route:\s+\K[\d./]+' || true)

    if [[ -z "$prefixes" ]]; then
        # Fallback: bgp.tools
        prefixes=$(curl -s "https://bgp.tools/table.txt" 2>/dev/null \
            | grep -P "\s${asn}$" | awk '{print $1}' || true)
    fi

    if [[ -z "$prefixes" ]]; then
        log_error "Could not resolve AS${asn} to any prefixes."
        return 1
    fi

    echo "$prefixes"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_block_ip() {
    require_root
    local target="$1"

    if is_ipv6 "$target"; then
        nft add element inet filter blocked_v6 "{ $target }"
        log_info "Blocked IPv6: $target"
    else
        nft add element inet filter blocked_v4 "{ $target }"
        log_info "Blocked IPv4: $target"
    fi
    persist_nftables
}

cmd_unblock_ip() {
    require_root
    local target="$1"

    if is_ipv6 "$target"; then
        nft delete element inet filter blocked_v6 "{ $target }"
        log_info "Unblocked IPv6: $target"
    else
        nft delete element inet filter blocked_v4 "{ $target }"
        log_info "Unblocked IPv4: $target"
    fi
    persist_nftables
}

cmd_block_as() {
    require_root
    local as_number="$1"

    log_info "Resolving $as_number to IP prefixes..."
    local prefixes
    prefixes=$(resolve_as_prefixes "$as_number") || exit 1

    local count=0
    while IFS= read -r prefix; do
        [[ -z "$prefix" ]] && continue
        if is_ipv6 "$prefix"; then
            nft add element inet filter blocked_v6 "{ $prefix }" 2>/dev/null || true
        else
            nft add element inet filter blocked_v4 "{ $prefix }" 2>/dev/null || true
        fi
        count=$((count + 1))
    done <<< "$prefixes"

    log_info "Blocked $count prefixes for $as_number"
    persist_nftables
}

cmd_unblock_as() {
    require_root
    local as_number="$1"

    log_info "Resolving $as_number to IP prefixes..."
    local prefixes
    prefixes=$(resolve_as_prefixes "$as_number") || exit 1

    local count=0
    while IFS= read -r prefix; do
        [[ -z "$prefix" ]] && continue
        if is_ipv6 "$prefix"; then
            nft delete element inet filter blocked_v6 "{ $prefix }" 2>/dev/null || true
        else
            nft delete element inet filter blocked_v4 "{ $prefix }" 2>/dev/null || true
        fi
        count=$((count + 1))
    done <<< "$prefixes"

    log_info "Unblocked $count prefixes for $as_number"
    persist_nftables
}

cmd_allow_ssh() {
    require_root
    local target="$1"
    nft add element inet filter approved_ssh_v4 "{ $target }"
    log_info "SSH allowed from: $target"
    persist_nftables
}

cmd_deny_ssh() {
    require_root
    local target="$1"
    nft delete element inet filter approved_ssh_v4 "{ $target }"
    log_info "SSH denied from: $target"
    persist_nftables
}

cmd_allow_panel() {
    require_root
    local target="$1"

    # Add to Nginx approved_panel_ips.conf
    if [[ -f "$NGINX_APPROVED_CONF" ]]; then
        if ! grep -q "allow ${target};" "$NGINX_APPROVED_CONF"; then
            # Insert before the last line (or append)
            echo "allow ${target};" >> "$NGINX_APPROVED_CONF"
            log_info "Panel access allowed from: $target"
            # Reload Nginx
            if docker compose -f "${COMPOSE_DIR}/docker-compose.yml" exec reverse_proxy nginx -s reload 2>/dev/null; then
                log_info "Nginx reloaded."
            else
                log_info "Note: Reload Nginx manually if not using docker compose."
            fi
        else
            log_info "Already allowed: $target"
        fi
    else
        log_error "Nginx config not found at $NGINX_APPROVED_CONF"
        log_info "Add 'allow ${target};' to your approved_panel_ips.conf manually."
    fi
}

cmd_deny_panel() {
    require_root
    local target="$1"

    if [[ -f "$NGINX_APPROVED_CONF" ]]; then
        sed -i "/^allow ${target//\//\\/};$/d" "$NGINX_APPROVED_CONF"
        log_info "Panel access denied from: $target"
        if docker compose -f "${COMPOSE_DIR}/docker-compose.yml" exec reverse_proxy nginx -s reload 2>/dev/null; then
            log_info "Nginx reloaded."
        else
            log_info "Note: Reload Nginx manually if not using docker compose."
        fi
    else
        log_error "Nginx config not found at $NGINX_APPROVED_CONF"
    fi
}

cmd_list() {
    local what="${1:-all}"

    case "$what" in
        blocked)
            echo "=== Blocked IPv4 ==="
            nft list set inet filter blocked_v4 2>/dev/null || echo "(set not found)"
            echo ""
            echo "=== Blocked IPv6 ==="
            nft list set inet filter blocked_v6 2>/dev/null || echo "(set not found)"
            ;;
        ssh)
            echo "=== SSH Approved IPv4 ==="
            nft list set inet filter approved_ssh_v4 2>/dev/null || echo "(set not found)"
            ;;
        all)
            echo "=== Blocked IPv4 ==="
            nft list set inet filter blocked_v4 2>/dev/null || echo "(set not found)"
            echo ""
            echo "=== Blocked IPv6 ==="
            nft list set inet filter blocked_v6 2>/dev/null || echo "(set not found)"
            echo ""
            echo "=== SSH Approved IPv4 ==="
            nft list set inet filter approved_ssh_v4 2>/dev/null || echo "(set not found)"
            echo ""
            echo "=== Panel Approved IPs (Nginx) ==="
            if [[ -f "$NGINX_APPROVED_CONF" ]]; then
                grep "^allow" "$NGINX_APPROVED_CONF" || echo "(none)"
            else
                echo "(config not found)"
            fi
            ;;
        *)
            log_error "Unknown list target: $what (use: blocked, ssh, all)"
            exit 1
            ;;
    esac
}

cmd_resolve_as() {
    local as_number="$1"
    log_info "Resolving $as_number (dry-run — not applying)..."
    local prefixes
    prefixes=$(resolve_as_prefixes "$as_number") || exit 1
    local count
    count=$(echo "$prefixes" | wc -l)
    echo "$prefixes"
    log_info "Total: $count prefixes"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
usage() {
    cat << 'EOF'
Usage: vpn007-fw.sh <command> [args]

Commands:
  block ip <IP/CIDR>        Block an IP or subnet in nftables
  unblock ip <IP/CIDR>      Remove an IP or subnet from block list
  block as <ASxxxxx>        Resolve and block all prefixes for an AS
  unblock as <ASxxxxx>      Resolve and unblock all prefixes for an AS
  allow ssh <IP/CIDR>       Allow SSH access from an IP/subnet
  deny ssh <IP/CIDR>        Remove SSH access for an IP/subnet
  allow panel <IP/CIDR>     Allow web panel access from an IP/subnet
  deny panel <IP/CIDR>      Remove web panel access for an IP/subnet
  list [blocked|ssh|all]    Show current firewall sets (default: all)
  resolve as <ASxxxxx>      Resolve AS to prefixes without applying

Environment:
  VPN007_DIR                Path to VPN007 deploy dir (default: /opt/vpn007)
  VPN007_NFTABLES_CONF      Path to save nftables ruleset (default: /etc/nftables.conf)

Examples:
  sudo vpn007-fw.sh block ip 192.168.1.0/24
  sudo vpn007-fw.sh block as AS196747
  sudo vpn007-fw.sh allow ssh 203.0.113.50
  sudo vpn007-fw.sh allow panel 10.0.0.5
  sudo vpn007-fw.sh list blocked
  vpn007-fw.sh resolve as AS61280
EOF
}

if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

action="$1"
shift

case "$action" in
    block)
        [[ $# -lt 2 ]] && { log_error "Usage: vpn007-fw.sh block <ip|as> <target>"; exit 1; }
        type="$1"; target="$2"
        case "$type" in
            ip) cmd_block_ip "$target" ;;
            as) cmd_block_as "$target" ;;
            *) log_error "Unknown block type: $type (use: ip, as)"; exit 1 ;;
        esac
        ;;
    unblock)
        [[ $# -lt 2 ]] && { log_error "Usage: vpn007-fw.sh unblock <ip|as> <target>"; exit 1; }
        type="$1"; target="$2"
        case "$type" in
            ip) cmd_unblock_ip "$target" ;;
            as) cmd_unblock_as "$target" ;;
            *) log_error "Unknown unblock type: $type (use: ip, as)"; exit 1 ;;
        esac
        ;;
    allow)
        [[ $# -lt 2 ]] && { log_error "Usage: vpn007-fw.sh allow <ssh|panel> <IP/CIDR>"; exit 1; }
        type="$1"; target="$2"
        case "$type" in
            ssh) cmd_allow_ssh "$target" ;;
            panel) cmd_allow_panel "$target" ;;
            *) log_error "Unknown allow type: $type (use: ssh, panel)"; exit 1 ;;
        esac
        ;;
    deny)
        [[ $# -lt 2 ]] && { log_error "Usage: vpn007-fw.sh deny <ssh|panel> <IP/CIDR>"; exit 1; }
        type="$1"; target="$2"
        case "$type" in
            ssh) cmd_deny_ssh "$target" ;;
            panel) cmd_deny_panel "$target" ;;
            *) log_error "Unknown deny type: $type (use: ssh, panel)"; exit 1 ;;
        esac
        ;;
    list)
        cmd_list "${1:-all}"
        ;;
    resolve)
        [[ $# -lt 2 ]] && { log_error "Usage: vpn007-fw.sh resolve as <AS_NUMBER>"; exit 1; }
        type="$1"; target="$2"
        case "$type" in
            as) cmd_resolve_as "$target" ;;
            *) log_error "Unknown resolve type: $type (use: as)"; exit 1 ;;
        esac
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: $action"
        usage
        exit 1
        ;;
esac
