import os
import time
import ipaddress
import subprocess
from collections import defaultdict

# ---------------- CONFIGURATION ----------------
MAX_CONNECTIONS = 100        # Max active connections per IP
CHECK_INTERVAL = 2           # Check frequency (seconds)
BLOCK_TIME_SECONDS = 3600    # Auto-unblock after 1 hour (0 for permanent)
SET_NAME = "antiddos_blacklist"

WHITELIST = {
    "127.0.0.1",
    "::1",
    # Add your static server IPs or management IPs here
}
# -----------------------------------------------

def setup_kernel_rules():
    """Initializes high-performance ipset and iptables rules."""
    try:
        # Create ipset hash map for fast O(1) IP blocking
        timeout_arg = f"timeout {BLOCK_TIME_SECONDS}" if BLOCK_TIME_SECONDS > 0 else ""
        subprocess.run(
            f"ipset create {SET_NAME} hash:ip {timeout_arg} -exist",
            shell=True, check=True
        )

        # Ensure iptables routes blocked ipset directly to DROP at top of chain
        check_rule = subprocess.run(
            f"iptables -C INPUT -m set --match-set {SET_NAME} src -j DROP",
            shell=True, stderr=subprocess.DEVNULL
        )
        if check_rule.returncode != 0:
            subprocess.run(
                f"iptables -I INPUT 1 -m set --match-set {SET_NAME} src -j DROP",
                shell=True, check=True
            )
        print("[Anti-DDoS] ipset and kernel rules successfully initialized.")
    except Exception as e:
        print(f"[Anti-DDoS Error] Failed setting up kernel firewall rules: {e}")

def hex_to_ip(hex_str, is_ipv6=False):
    """Converts raw kernel hex strings to standard IPv4/IPv6 address string."""
    try:
        if not is_ipv6:
            # IPv4 is little-endian stored hex
            struct_bytes = bytes.fromhex(hex_str)
            return str(ipaddress.IPv4Address(struct_bytes[::-1]))
        else:
            # IPv6 hex format parsing
            struct_bytes = bytes.fromhex(hex_str)
            return str(ipaddress.IPv6Address(struct_bytes))
    except Exception:
        return None

def parse_proc_net(filepath, is_ipv6=False):
    """Parses /proc/net socket entries natively in Python without subprocess call overhead."""
    counts = defaultdict(int)
    if not os.path.exists(filepath):
        return counts

    try:
        with open(filepath, 'r') as f:
            next(f)  # Skip header line
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                
                # Check socket state (01 = ESTABLISHED, 06 = TIME_WAIT, 02 = SYN_SENT)
                state = parts[3]
                if state in ("01", "02"):  # Track Active & SYN connections
                    rem_address = parts[2]
                    ip_hex = rem_address.split(':')[0]
                    ip = hex_to_ip(ip_hex, is_ipv6)
                    if ip:
                        counts[ip] += 1
    except Exception as e:
        print(f"[Anti-DDoS Error] Reading {filepath} failed: {e}")
    return counts

def get_active_connections():
    """Combines IPv4 and IPv6 connection metrics natively."""
    counts = parse_proc_net("/proc/net/tcp", is_ipv6=False)
    v6_counts = parse_proc_net("/proc/net/tcp6", is_ipv6=True)
    
    for ip, count in v6_counts.items():
        counts[ip] += count
    return counts

def block_ip(ip):
    """Inserts IP into high-performance kernel ipset structure."""
    if ip in WHITELIST:
        return
    try:
        # Adding to ipset is an O(1) operation
        subprocess.run(
            f"ipset add {SET_NAME} {ip} -exist",
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[Anti-DDoS ALERT] Blocked malicious IP: {ip}")
    except Exception as e:
        print(f"[Anti-DDoS Error] Could not block IP {ip}: {e}")

def main():
    if os.geteuid() != 0:
        print("[Anti-DDoS Fatal] This script must be run as root to manage network rules.")
        return

    setup_kernel_rules()
    print(f"[Anti-DDoS] High-Throughput Monitor active (Interval: {CHECK_INTERVAL}s, Max Limit: {MAX_CONNECTIONS} conn)...")

    while True:
        connections = get_active_connections()
        for ip, count in connections.items():
            if count > MAX_CONNECTIONS:
                print(f"[Anti-DDoS Warning] High connection density detected from {ip}: {count} sockets")
                block_ip(ip)
        time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    main()
