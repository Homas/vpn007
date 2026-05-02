#!/usr/bin/env bash
# docker-entrypoint-awg.sh — Entrypoint for custom AmneziaWG 2.0 container
#
# Configures the awg0 interface with all 2.0 obfuscation parameters,
# starts the amneziawg-go userspace daemon, and launches the web panel.
# Handles graceful shutdown via SIGTERM/SIGINT.
#
# Copyright (c) Vadim Pavlov 2026. Licensed under GPL-3.0.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration from environment variables (with defaults)
# ---------------------------------------------------------------------------
AWG_INTERFACE="${AWG_INTERFACE:-awg0}"
AWG_ADDRESS="${AWG_ADDRESS:-10.8.0.1/24}"
AWG_PORT="${WG_PORT:-51820}"
AWG_WEB_PORT="${PORT:-51821}"
AWG_WEB_HOST="${WEBUI_HOST:-127.0.0.1}"
AWG_CONFIG_DIR="${AWG_CONFIG_DIR:-/etc/amneziawg}"
AWG_CONFIG_FILE="${AWG_CONFIG_DIR}/${AWG_INTERFACE}.conf"

# AmneziaWG 2.0 obfuscation parameters
AWG_S1="${AWG_S1:-}"
AWG_S2="${AWG_S2:-}"
AWG_S3="${AWG_S3:-}"
AWG_S4="${AWG_S4:-}"
AWG_H1="${AWG_H1:-}"
AWG_H2="${AWG_H2:-}"
AWG_H3="${AWG_H3:-}"
AWG_H4="${AWG_H4:-}"
AWG_JC="${AWG_JC:-4}"
AWG_JMIN="${AWG_JMIN:-50}"
AWG_JMAX="${AWG_JMAX:-1000}"
AWG_I1="${AWG_I1:-0}"
AWG_I2="${AWG_I2:-0}"
AWG_I3="${AWG_I3:-0}"
AWG_I4="${AWG_I4:-0}"
AWG_I5="${AWG_I5:-0}"

# PIDs for graceful shutdown
AMNEZIAWG_GO_PID=""
WEB_PANEL_PID=""

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }

# ---------------------------------------------------------------------------
# Graceful shutdown handler
# ---------------------------------------------------------------------------
cleanup() {
    log_info "Received shutdown signal, cleaning up..."

    # Stop web panel
    if [[ -n "${WEB_PANEL_PID}" ]] && kill -0 "${WEB_PANEL_PID}" 2>/dev/null; then
        log_info "Stopping web panel (PID ${WEB_PANEL_PID})..."
        kill -TERM "${WEB_PANEL_PID}" 2>/dev/null || true
        wait "${WEB_PANEL_PID}" 2>/dev/null || true
    fi

    # Bring down the AmneziaWG interface
    if ip link show "${AWG_INTERFACE}" &>/dev/null; then
        log_info "Bringing down ${AWG_INTERFACE}..."
        awg-quick down "${AWG_CONFIG_FILE}" 2>/dev/null || true
    fi

    # Stop amneziawg-go
    if [[ -n "${AMNEZIAWG_GO_PID}" ]] && kill -0 "${AMNEZIAWG_GO_PID}" 2>/dev/null; then
        log_info "Stopping amneziawg-go (PID ${AMNEZIAWG_GO_PID})..."
        kill -TERM "${AMNEZIAWG_GO_PID}" 2>/dev/null || true
        wait "${AMNEZIAWG_GO_PID}" 2>/dev/null || true
    fi

    log_info "Shutdown complete."
    exit 0
}

trap cleanup SIGTERM SIGINT

# ---------------------------------------------------------------------------
# Generate server private key if not present
# ---------------------------------------------------------------------------
generate_server_key() {
    local key_file="${AWG_CONFIG_DIR}/server_private.key"
    if [[ ! -f "${key_file}" ]]; then
        log_info "Generating server private key..."
        awg genkey > "${key_file}"
        chmod 600 "${key_file}"
    fi
    cat "${key_file}"
}

# ---------------------------------------------------------------------------
# Generate AmneziaWG configuration file with 2.0 parameters
# ---------------------------------------------------------------------------
generate_config() {
    local private_key
    private_key="$(generate_server_key)"

    log_info "Generating ${AWG_INTERFACE} configuration with 2.0 parameters..."

    cat > "${AWG_CONFIG_FILE}" <<EOF
[Interface]
Address = ${AWG_ADDRESS}
ListenPort = ${AWG_PORT}
PrivateKey = ${private_key}
EOF

    # Append 2.0 obfuscation parameters if provided
    if [[ -n "${AWG_S1}" ]]; then
        cat >> "${AWG_CONFIG_FILE}" <<EOF
S1 = ${AWG_S1}
S2 = ${AWG_S2}
S3 = ${AWG_S3}
S4 = ${AWG_S4}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
I1 = ${AWG_I1}
I2 = ${AWG_I2}
I3 = ${AWG_I3}
I4 = ${AWG_I4}
I5 = ${AWG_I5}
EOF
    fi

    # Add PostUp/PostDown for NAT (iptables masquerade)
    cat >> "${AWG_CONFIG_FILE}" <<EOF
PostUp = iptables -A FORWARD -i ${AWG_INTERFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i ${AWG_INTERFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

    chmod 600 "${AWG_CONFIG_FILE}"
    log_info "Configuration written to ${AWG_CONFIG_FILE}"
}

# ---------------------------------------------------------------------------
# Enable IP forwarding
# ---------------------------------------------------------------------------
enable_forwarding() {
    log_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Start amneziawg-go userspace daemon
# ---------------------------------------------------------------------------
start_amneziawg_go() {
    log_info "Starting amneziawg-go userspace daemon for ${AWG_INTERFACE}..."
    amneziawg-go "${AWG_INTERFACE}" &
    AMNEZIAWG_GO_PID=$!

    # Wait briefly for the interface to appear
    local retries=10
    while [[ ${retries} -gt 0 ]]; do
        if ip link show "${AWG_INTERFACE}" &>/dev/null; then
            log_info "Interface ${AWG_INTERFACE} is up."
            return 0
        fi
        sleep 0.5
        retries=$((retries - 1))
    done

    log_error "Interface ${AWG_INTERFACE} did not appear after 5 seconds."
    return 1
}

# ---------------------------------------------------------------------------
# Apply configuration to the running interface
# ---------------------------------------------------------------------------
apply_config() {
    log_info "Applying configuration to ${AWG_INTERFACE}..."
    awg-quick up "${AWG_CONFIG_FILE}"
    log_info "AmneziaWG interface ${AWG_INTERFACE} configured successfully."
    awg show "${AWG_INTERFACE}"
}

# ---------------------------------------------------------------------------
# Start the web panel
# ---------------------------------------------------------------------------
start_web_panel() {
    log_info "Starting web panel on ${AWG_WEB_HOST}:${AWG_WEB_PORT}..."

    if [[ -x /usr/bin/awg-web ]]; then
        AWG_WEB_LISTEN="${AWG_WEB_HOST}:${AWG_WEB_PORT}" \
        AWG_CONFIG_DIR="${AWG_CONFIG_DIR}" \
        AWG_INTERFACE="${AWG_INTERFACE}" \
            /usr/bin/awg-web &
        WEB_PANEL_PID=$!
        log_info "Web panel started (PID ${WEB_PANEL_PID})."
    else
        log_warn "Web panel binary not found at /usr/bin/awg-web, skipping."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log_info "=== AmneziaWG 2.0 Custom Container Starting ==="
    log_info "Interface: ${AWG_INTERFACE}"
    log_info "Listen port: ${AWG_PORT}"
    log_info "Web panel: ${AWG_WEB_HOST}:${AWG_WEB_PORT}"

    enable_forwarding

    # Generate config if it doesn't exist or if obfuscation params changed
    if [[ ! -f "${AWG_CONFIG_FILE}" ]] || [[ -n "${AWG_S1}" ]]; then
        generate_config
    fi

    # Start the userspace daemon
    start_amneziawg_go

    # Apply the configuration
    apply_config

    # Start the web panel
    start_web_panel

    log_info "=== AmneziaWG 2.0 is running ==="

    # Wait for any child process to exit
    wait -n 2>/dev/null || true

    # If we get here, a child process exited unexpectedly
    log_warn "A child process exited, shutting down..."
    cleanup
}

main "$@"
