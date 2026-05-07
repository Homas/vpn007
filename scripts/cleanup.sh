#!/usr/bin/env bash
# cleanup.sh — Complete removal of VPN007 deployment
# © Vadim Pavlov 2026
#
# Removes all VPN007 components:
#   - Docker containers, images, volumes, and networks
#   - nftables firewall rules (restores default accept policy)
#   - Systemd timers and services
#   - AmneziaWG kernel module and persistence config
#   - Kernel parameter overrides
#   - Deployment data directory
#
# Usage:
#   sudo ./cleanup.sh [--keep-data] [--deploy-dir /path/to/deploy]
#
# Options:
#   --keep-data     Preserve the deploy directory (configs, client keys, certs)
#   --deploy-dir    Path to the deploy directory (default: ./deploy or /opt/vpn007)
#   --yes           Skip confirmation prompt

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEPLOY_DIR=""
KEEP_DATA=false
SKIP_CONFIRM=false
PROJECT_NAME="vpn007"

# Container names (from docker-compose.yml.j2)
CONTAINERS=(
    vpn007_reverse_proxy
    vpn007_three_x_ui
    vpn007_amneziawg
    vpn007_tailscale
    vpn007_cover_site
    vpn007_certbot
)

# Systemd units installed by VPN007
SYSTEMD_TIMERS=(
    blocklist-updater.timer
    hostname-resolver.timer
    certbot-renew.timer
)
SYSTEMD_SERVICES=(
    blocklist-updater.service
    hostname-resolver.service
    certbot-renew.service
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo)."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-data)
            KEEP_DATA=true
            shift
            ;;
        --deploy-dir)
            DEPLOY_DIR="$2"
            shift 2
            ;;
        --yes|-y)
            SKIP_CONFIRM=true
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $0 [--keep-data] [--deploy-dir /path] [--yes]"
            echo ""
            echo "Completely removes VPN007 deployment from this server."
            echo ""
            echo "Options:"
            echo "  --keep-data     Preserve deploy directory (configs, client keys, certs)"
            echo "  --deploy-dir    Path to deploy directory (default: auto-detect)"
            echo "  --yes, -y       Skip confirmation prompt"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Auto-detect deploy directory
if [[ -z "$DEPLOY_DIR" ]]; then
    if [[ -f "./deploy/docker-compose.yml" ]]; then
        DEPLOY_DIR="./deploy"
    elif [[ -f "/opt/vpn007/docker-compose.yml" ]]; then
        DEPLOY_DIR="/opt/vpn007"
    elif [[ -f "./docker-compose.yml" ]]; then
        DEPLOY_DIR="."
    else
        warn "Could not auto-detect deploy directory."
        warn "Use --deploy-dir to specify it, or run from the project root."
        DEPLOY_DIR=""
    fi
fi

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  VPN007 — Complete Cleanup"
echo "============================================================"
echo ""
echo "This will remove:"
echo "  • All VPN007 Docker containers and networks"
echo "  • Docker images used by VPN007"
echo "  • nftables firewall rules (table inet filter, table ip nat)"
echo "  • Persisted firewall config (/etc/nftables.conf)"
echo "  • Systemd timers (blocklist-updater, hostname-resolver, certbot-renew)"
echo "  • AmneziaWG kernel module and /etc/modules-load.d/amneziawg.conf"
echo "  • Kernel parameter overrides"
if [[ "$KEEP_DATA" == "true" ]]; then
    echo "  • Deploy directory: PRESERVED (--keep-data)"
else
    echo "  • Deploy directory: ${DEPLOY_DIR:-'(not found)'}"
    echo "    Including: client configs, certificates, database, logs"
fi
echo ""

if [[ "$SKIP_CONFIRM" != "true" ]]; then
    read -rp "Are you sure you want to proceed? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

check_root

echo ""
info "Starting VPN007 cleanup..."
echo ""

# ---------------------------------------------------------------------------
# 1. Stop and remove Docker containers
# ---------------------------------------------------------------------------

info "=== Step 1/7: Stopping Docker containers ==="

if [[ -n "$DEPLOY_DIR" && -f "$DEPLOY_DIR/docker-compose.yml" ]]; then
    info "Stopping containers via docker compose..."
    docker compose -f "$DEPLOY_DIR/docker-compose.yml" \
        --project-name "$PROJECT_NAME" \
        down --remove-orphans --timeout 30 2>/dev/null || true
else
    info "No compose file found. Stopping containers individually..."
    for container in "${CONTAINERS[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
            info "  Stopping and removing: $container"
            docker stop "$container" 2>/dev/null || true
            docker rm -f "$container" 2>/dev/null || true
        fi
    done
fi

# Remove the vpn_net network if it still exists
if docker network ls --format '{{.Name}}' | grep -q "^${PROJECT_NAME}_vpn_net$"; then
    info "Removing Docker network: ${PROJECT_NAME}_vpn_net"
    docker network rm "${PROJECT_NAME}_vpn_net" 2>/dev/null || true
fi

# Prune any orphaned networks
docker network prune -f 2>/dev/null || true

# Restart Docker daemon to clear stale state
info "Restarting Docker daemon..."
systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || \
    warn "Could not restart Docker daemon."

info "Docker containers and networks removed."
echo ""

# ---------------------------------------------------------------------------
# 2. Remove Docker images (optional cleanup)
# ---------------------------------------------------------------------------

info "=== Step 2/7: Removing Docker images ==="

IMAGES=(
    "ghcr.io/mhsanaei/3x-ui"
    "ghcr.io/wg-easy/wg-easy"
    "tailscale/tailscale"
    "certbot/certbot"
    "nginx:mainline"
    "nginx:alpine"
)

for image in "${IMAGES[@]}"; do
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${image}"; then
        info "  Removing image: $image"
        docker rmi "$image" 2>/dev/null || true
    fi
done

# Remove any locally-built vpn007 images
docker images --format '{{.Repository}}:{{.Tag}}' | grep -i "vpn007" | while read -r img; do
    info "  Removing image: $img"
    docker rmi "$img" 2>/dev/null || true
done

info "Docker images cleaned up."
echo ""

# ---------------------------------------------------------------------------
# 3. Remove nftables firewall rules
# ---------------------------------------------------------------------------

info "=== Step 3/7: Removing firewall rules ==="

if command -v nft &>/dev/null; then
    # Delete VPN007-managed tables
    nft delete table inet filter 2>/dev/null && info "  Deleted table inet filter" || true
    nft delete table ip nat 2>/dev/null && info "  Deleted table ip nat" || true

    # Restore a minimal permissive ruleset so the server isn't locked out
    info "  Applying minimal permissive firewall (accept all)..."
    nft -f - <<'EOF' 2>/dev/null || true
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    info "  Firewall reset to accept-all policy."

    # Remove persisted nftables config
    if [[ -f /etc/nftables.conf ]]; then
        info "  Removing /etc/nftables.conf..."
        rm -f /etc/nftables.conf
        # Restore a minimal default
        cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Minimal default nftables config (VPN007 removed)
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
        info "  Restored default /etc/nftables.conf (accept-all)."
    fi
else
    warn "nft command not found — skipping firewall cleanup."
fi

echo ""

# ---------------------------------------------------------------------------
# 4. Disable and remove systemd timers/services
# ---------------------------------------------------------------------------

info "=== Step 4/7: Removing systemd timers and services ==="

if command -v systemctl &>/dev/null; then
    # Stop and disable timers
    for timer in "${SYSTEMD_TIMERS[@]}"; do
        if systemctl list-unit-files "$timer" &>/dev/null; then
            info "  Disabling: $timer"
            systemctl disable --now "$timer" 2>/dev/null || true
        fi
    done

    # Stop services (they're oneshot, but just in case)
    for service in "${SYSTEMD_SERVICES[@]}"; do
        systemctl stop "$service" 2>/dev/null || true
    done

    # Remove unit files
    for unit in "${SYSTEMD_TIMERS[@]}" "${SYSTEMD_SERVICES[@]}"; do
        if [[ -f "/etc/systemd/system/$unit" ]]; then
            info "  Removing: /etc/systemd/system/$unit"
            rm -f "/etc/systemd/system/$unit"
        fi
    done

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
    info "Systemd units removed and daemon reloaded."
else
    warn "systemctl not found — skipping systemd cleanup."
fi

echo ""

# ---------------------------------------------------------------------------
# 5. Remove AmneziaWG kernel module
# ---------------------------------------------------------------------------

info "=== Step 5/7: Removing AmneziaWG kernel module ==="

# Unload the module if loaded
if lsmod 2>/dev/null | grep -q "^amneziawg"; then
    info "  Unloading amneziawg kernel module..."
    modprobe -r amneziawg 2>/dev/null || rmmod amneziawg 2>/dev/null || \
        warn "  Could not unload amneziawg module (may be in use)."
fi

# Remove boot persistence
if [[ -f /etc/modules-load.d/amneziawg.conf ]]; then
    info "  Removing /etc/modules-load.d/amneziawg.conf"
    rm -f /etc/modules-load.d/amneziawg.conf
fi

info "AmneziaWG module cleanup done."
echo ""

# ---------------------------------------------------------------------------
# 6. Reset kernel parameters
# ---------------------------------------------------------------------------

info "=== Step 6/7: Resetting kernel parameters ==="

# These were set by the deployer; reset to defaults
# Note: ip_forward=0 may break other services — only reset if no other
# Docker containers or VPNs need it.
if ! docker ps -q 2>/dev/null | grep -q .; then
    # No other Docker containers running — safe to disable forwarding
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null && \
        info "  Reset net.ipv4.ip_forward=0" || true
else
    warn "  Other Docker containers are running — keeping net.ipv4.ip_forward=1"
fi

sysctl -w net.ipv4.conf.all.src_valid_mark=0 2>/dev/null && \
    info "  Reset net.ipv4.conf.all.src_valid_mark=0" || true

echo ""

# ---------------------------------------------------------------------------
# 7. Remove deployment data
# ---------------------------------------------------------------------------

info "=== Step 7/7: Cleaning deployment data ==="

if [[ "$KEEP_DATA" == "true" ]]; then
    info "Preserving deploy directory (--keep-data specified)."
    if [[ -n "$DEPLOY_DIR" ]]; then
        info "  Data preserved at: $DEPLOY_DIR"
        info "  Client configs at: $DEPLOY_DIR/clients/"
    fi
else
    if [[ -n "$DEPLOY_DIR" && -d "$DEPLOY_DIR" ]]; then
        info "Removing deploy directory: $DEPLOY_DIR"
        rm -rf "$DEPLOY_DIR"
        info "Deploy directory removed."
    else
        info "No deploy directory to remove."
    fi
fi

echo ""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo "============================================================"
info "VPN007 cleanup complete."
echo "============================================================"
echo ""
if [[ "$KEEP_DATA" == "true" && -n "$DEPLOY_DIR" ]]; then
    echo "  Data preserved at: $DEPLOY_DIR"
    echo "  To fully remove: rm -rf $DEPLOY_DIR"
    echo ""
fi
echo "  The server firewall is now set to accept-all."
echo "  If you need a restrictive firewall, configure it manually"
echo "  or install a firewall manager (ufw, firewalld)."
echo ""
echo "  To re-deploy VPN007: sudo vpn007 --domain your.domain.com"
echo ""
