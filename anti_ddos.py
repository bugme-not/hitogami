import os
import time
import asyncio
import ipaddress
from collections import defaultdict

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

MAX_CONNECTIONS = 100        
CHECK_INTERVAL = 2           
BLOCK_TIME_SECONDS = 3600    
SET_NAME = "antiddos_blacklist"

WHITELIST = {
    "127.0.0.1",
    "::1",
}

async def exec_cmd(*args) -> bool:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
    )
    await proc.wait()
    return proc.returncode == 0

async def setup_kernel_rules():
    try:
        timeout_arg = ["timeout", str(BLOCK_TIME_SECONDS)] if BLOCK_TIME_SECONDS > 0 else []
        cmd = ["ipset", "create", SET_NAME, "hash:ip"] + timeout_arg + ["-exist"]
        await exec_cmd(*cmd)

        rule_exists = await exec_cmd("iptables", "-C", "INPUT", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP")
        if not rule_exists:
            await exec_cmd("iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP")
            
        print("[Anti-DDoS] ipset and kernel rules successfully initialized.", flush=True)
    except Exception as e:
        print(f"[Anti-DDoS Error] Failed setting up kernel firewall rules: {e}", flush=True)

def hex_to_ip(hex_str, is_ipv6=False):
    try:
        if not is_ipv6:
            struct_bytes = bytes.fromhex(hex_str)
            return str(ipaddress.IPv4Address(struct_bytes[::-1]))
        else:
            struct_bytes = bytes.fromhex(hex_str)
            return str(ipaddress.IPv6Address(struct_bytes))
    except Exception:
        return None

def parse_proc_net(filepath, is_ipv6=False):
    counts = defaultdict(int)
    if not os.path.exists(filepath):
        return counts

    try:
        with open(filepath, 'r') as f:
            next(f)  
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                
                state = parts[3]
                if state in ("01", "02"):  
                    rem_address = parts[2]
                    ip_hex = rem_address.split(':')[0]
                    ip = hex_to_ip(ip_hex, is_ipv6)
                    if ip:
                        counts[ip] += 1
    except Exception as e:
        print(f"[Anti-DDoS Error] Reading {filepath} failed: {e}", flush=True)
    return counts

def read_active_connections_sync():
    counts = parse_proc_net("/proc/net/tcp", is_ipv6=False)
    v6_counts = parse_proc_net("/proc/net/tcp6", is_ipv6=True)
    for ip, count in v6_counts.items():
        counts[ip] += count
    return counts

async def block_ip(ip):
    if ip in WHITELIST:
        return
    try:
        success = await exec_cmd("ipset", "add", SET_NAME, ip, "-exist")
        if success:
            print(f"[Anti-DDoS ALERT] Blocked malicious IP: {ip}", flush=True)
    except Exception as e:
        print(f"[Anti-DDoS Error] Could not block IP {ip}: {e}", flush=True)

async def monitor_loop():
    await setup_kernel_rules()
    print(f"[Anti-DDoS] High-Throughput Monitor active (Interval: {CHECK_INTERVAL}s, Max Limit: {MAX_CONNECTIONS} conn)...", flush=True)

    while True:
        connections = await asyncio.to_thread(read_active_connections_sync)
        block_tasks = []
        for ip, count in connections.items():
            if count > MAX_CONNECTIONS:
                print(f"[Anti-DDoS Warning] High connection density detected from {ip}: {count} sockets", flush=True)
                block_tasks.append(block_ip(ip))
                
        if block_tasks:
            await asyncio.gather(*block_tasks)
            
        await asyncio.sleep(CHECK_INTERVAL)

def main():
    if os.geteuid() != 0:
        print("[Anti-DDoS Fatal] This script must be run as root to manage network rules.", flush=True)
        return

    try:
        asyncio.run(monitor_loop())
    except KeyboardInterrupt:
        print("\n[Anti-DDoS] Monitor stopped cleanly.", flush=True)

if __name__ == '__main__':
    main()
