#!/usr/bin/env python3
"""
parse_auth_log.py
Simple parser for /var/log/auth.log style files that extracts failed SSH login attempts
and summarizes by IP and username.

Usage:
  python3 parse_auth_log.py                # parse /var/log/auth.log (may need sudo to read)
  python3 parse_auth_log.py --file sample.log --json
  python3 parse_auth_log.py --file sample.log --top 10

Outputs a human summary to stdout; use --json to get JSON.
"""
from __future__ import annotations
import re, sys, argparse, json
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict

# regexes to capture common failed SSH auth lines
PATTERNS = [
    # OpenSSH: "Failed password for <user> from <ip> port <port> ..."
    re.compile(r'Failed password for (?P<user>.+?) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    # "Invalid user <user> from <ip>"
    re.compile(r'Invalid user (?P<user>.+?) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    # "Failed publickey for <user> from <ip>"
    re.compile(r'Failed publickey for (?P<user>.+?) from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
    # Some distributions use "authentication failure;.*rhost=<ip>"
    re.compile(r'rhost=(?P<ip>\d+\.\d+\.\d+\.\d+).*user=(?P<user>\S+)'),
    # Generic: "connection from <ip>"
    re.compile(r'connection from (?P<ip>\d+\.\d+\.\d+\.\d+)'),
]

MONTHS = {m: i for i, m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def parse_line(line: str):
    for p in PATTERNS:
        m = p.search(line)
        if m:
            user = m.groupdict().get('user') or '(unknown)'
            ip = m.groupdict().get('ip') or '(unknown)'
            return user.strip(), ip.strip()
    return None

def read_file(path: str) -> List[str]:
    with open(path, 'r', errors='ignore') as f:
        return f.readlines()

def summarize(lines: List[str], ignore_private: bool=False) -> Dict:
    total_matches = 0
    by_ip = Counter()
    by_user = Counter()
    samples_by_ip = defaultdict(list)

    for l in lines:
        r = parse_line(l)
        if not r:
            continue
        user, ip = r
        # optionally ignore RFC1918 private IPs
        if ignore_private:
            if ip.startswith(('10.', '192.168.', '172.')):
                continue
        total_matches += 1
        by_ip[ip] += 1
        by_user[user] += 1
        if len(samples_by_ip[ip]) < 5:
            samples_by_ip[ip].append(l.strip())

    return {
        'total': total_matches,
        'by_ip': by_ip,
        'by_user': by_user,
        'samples_by_ip': samples_by_ip
    }

def pretty_print(summary: Dict, top: int=10, json_out: bool=False):
    if json_out:
        # convert Counters to lists of tuples for JSON compatibility
        out = {
            'total': summary['total'],
            'by_ip': summary['by_ip'].most_common(top),
            'by_user': summary['by_user'].most_common(top),
            'samples_by_ip': {k: v for k, v in summary['samples_by_ip'].items()}
        }
        print(json.dumps(out, indent=2))
        return

    print(f"Total matched failed auth lines: {summary['total']}")
    print("\nTop IPs:")
    for ip, cnt in summary['by_ip'].most_common(top):
        print(f"  {ip:15}  {cnt:5d}")
    print("\nTop usernames:")
    for user, cnt in summary['by_user'].most_common(top):
        print(f"  {user:20}  {cnt:5d}")

    print("\nExample lines for top IPs:")
    for ip, _ in summary['by_ip'].most_common(min(top, len(summary['by_ip']))):
        print(f"\n{ip}:")
        for ex in summary['samples_by_ip'].get(ip, []):
            print(f"  {ex}")

def main():
    ap = argparse.ArgumentParser(description="Parse auth.log for failed SSH attempts")
    ap.add_argument('--file', '-f', default='/var/log/auth.log', help='path to auth.log-style file')
    ap.add_argument('--json', action='store_true', help='output JSON')
    ap.add_argument('--top', type=int, default=10, help='how many top items to show')
    ap.add_argument('--ignore-private', action='store_true', help='ignore private RFC1918 addresses')
    args = ap.parse_args()

    try:
        lines = read_file(args.file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"Permission denied reading {args.file}. Try with sudo or copy the file locally.", file=sys.stderr)
        sys.exit(2)

    summary = summarize(lines, ignore_private=args.ignore_private)
    pretty_print(summary, top=args.top, json_out=args.json)

if __name__ == '__main__':
    main()
