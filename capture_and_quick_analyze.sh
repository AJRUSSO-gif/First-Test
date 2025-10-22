#!/usr/bin/env bash
# capture_and_quick_analyze.sh
# Usage: sudo ./capture_and_quick_analyze.sh [seconds]
# Example: sudo ./capture_and_quick_analyze.sh 45

DUR="${1:-45}"
OUT="capture_$(date +%Y%m%d_%H%M%S).pcap"
FILTER="${2:-''}"

echo "Capturing for ${DUR}s -> ${OUT}"
if [ -z "$FILTER" ]; then
  sudo timeout "${DUR}" tcpdump -i any -c 5000 -w "./${OUT}"
else
  sudo timeout "${DUR}" tcpdump -i any -c 5000 -w "./${OUT}" "${FILTER}"
fi

echo "Saved to ${OUT}"
echo "Top IP endpoints:"
tshark -r "${OUT}" -q -z endpoints,ip | sed -n '1,30p'

echo
echo "Top conversations (IP):"
tshark -r "${OUT}" -q -z conv,ip | sed -n '1,30p'

echo
echo "Top DNS queries:"
tshark -r "${OUT}" -Y 'dns && dns.qry.name' -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n 40

echo
echo "Top HTTP hosts:"
tshark -r "${OUT}" -Y 'http.host' -T fields -e http.host | sort | uniq -c | sort -rn | head -n 40

echo
echo "TLS SNI (HTTPS hosts):"
tshark -r "${OUT}" -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn | head -n 40

echo
echo "Done. File: ${OUT}"
echo "To open in Wireshark: explorer.exe \"$(wslpath -w $(pwd)/${OUT})\""
