#!/usr/bin/env python3
"""
simple_port_scanner.py
Lightweight multi-threaded TCP port scanner.

Usage examples:
  # scan top common ports on a target
  python3 simple_port_scanner.py --host 192.168.1.10

  # scan specific port range (1-1024)
  python3 simple_port_scanner.py --host 127.0.0.1 --start 1 --end 1024 --threads 200

  # scan a comma list of ports
  python3 simple_port_scanner.py --host 127.0.0.1 --ports 22,80,443,3306

  # output JSON
  python3 simple_port_scanner.py --host 127.0.0.1 --json

Notes:
 - Use responsibly. Only scan hosts you own or have permission to scan.
"""
from __future__ import annotations
import socket
import argparse
import concurrent.futures
import time
import json
from typing import List

# top common ports (small list to speed default scans)
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,179,443,445,465,587,993,995,
    1723,3306,3389,5900,8080,8443
]

def scan_port(host: str, port: int, timeout: float) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        result = s.connect_ex((host, port))
        duration = time.time() - start
        if result == 0:
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(1024).strip().decode('utf-8', errors='ignore')
            except Exception:
                banner = ''
            s.close()
            return {'port': port, 'status': 'open', 'banner': banner, 'rtt_s': round(duration,4)}
        else:
            s.close()
            return {'port': port, 'status': 'closed', 'rtt_s': round(duration,4)}
    except Exception as e:
        return {'port': port, 'status': 'error', 'error': str(e)}
    
def parse_ports_arg(ports_arg: str) -> List[int]:
    ports = set()
    for part in ports_arg.split(','):
        part = part.strip()
        if '-' in part:
            a,b = part.split('-',1)
            ports.update(range(int(a), int(b)+1))
        else:
            if part:
                ports.add(int(part))
    return sorted(ports)

def main():
    ap = argparse.ArgumentParser(description="Simple multi-threaded TCP port scanner")
    ap.add_argument('--host', required=True, help='Target hostname or IP')
    ap.add_argument('--start', type=int, default=1, help='Start port (inclusive)')
    ap.add_argument('--end', type=int, default=1024, help='End port (inclusive)')
    ap.add_argument('--ports', help='Comma-separated ports or ranges, e.g. 22,80,1000-1010')
    ap.add_argument('--threads', type=int, default=100, help='Number of worker threads')
    ap.add_argument('--timeout', type=float, default=0.8, help='Socket timeout in seconds')
    ap.add_argument('--json', action='store_true', help='Output results in JSON')
    ap.add_argument('--top', action='store_true', help='Scan a small common-ports list and exit')
    args = ap.parse_args()

    target = args.host
    if args.top:
        ports = COMMON_PORTS
    elif args.ports:
        ports = parse_ports_arg(args.ports)
    else:
        ports = list(range(args.start, args.end + 1))

    print(f"Scanning {target} ({len(ports)} ports) with {args.threads} threads (timeout={args.timeout}s)...")
    start_time = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_port, target, p, args.timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {'port': futures[fut], 'status': 'error', 'error': str(e)}
            results.append(res)

    end_time = time.time()
    open_ports = sorted([r for r in results if r['status'] == 'open'], key=lambda x: x['port'])
    if args.json:
        out = {
            'target': target,
            'scanned_ports': len(ports),
            'duration_s': round(end_time - start_time, 4),
            'open_ports': open_ports,
            'all_results': results
        }
        print(json.dumps(out, indent=2))
        return

    print(f"Scan completed in {round(end_time - start_time,3)}s. Open ports: {len(open_ports)}")
    for op in open_ports:
        banner = op.get('banner') or ''
        print(f"  {op['port']:5d}  open   rtt={op.get('rtt_s',0)}s  {banner.splitlines()[0] if banner else ''}")

if __name__ == '__main__':
    main()
