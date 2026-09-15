#!/bin/bash
set -e

echo "[+] Starting initialization script..."

# 1. File Descriptor Limits
# Increases file descriptors for high concurrency (fallback safely if restricted)
ulimit -n 65535 2>/dev/null || true

# 2. Kernel & TCP Parameters
# Note: Requires runtime capabilities (--cap-add=SYS_ADMIN or --privileged) to apply.
# Suppressed errors gracefully for environments where /proc/sys is read-only.
echo "[+] Attempting Kernel & TCP Socket Tuning..."

# Enable BBR Congestion Control
sysctl -w net.core.default_qdisc=fq 2>/dev/null || true
sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true

# Maximize socket memory buffers (16MB max)
sysctl -w net.core.rmem_max=16777216 2>/dev/null || true
sysctl -w net.core.wmem_max=16777216 2>/dev/null || true
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216" 2>/dev/null || true
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216" 2>/dev/null || true

# Fast socket recycling, low FIN timeouts, and TCP Fast Open
sysctl -w net.ipv4.tcp_fin_timeout=15 2>/dev/null || true
sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null || true
sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null || true

# 3. Hand over control to supervisord/CMD
exec "$@"
