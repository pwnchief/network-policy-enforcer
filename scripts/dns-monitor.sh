#!/bin/sh
# Captures DNS responses via tcpdump to build a real-time IP-to-domain mapping.
# Used by monitor.sh instead of unreliable reverse DNS lookups.

PREFIX="net-enforcer"
DNS_MAP_FILE="/tmp/${PREFIX}-dns-map.txt"
DNS_PID_FILE="/tmp/${PREFIX}-dns-monitor.pid"

: > "$DNS_MAP_FILE"
echo $$ > "$DNS_PID_FILE"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "::warning::tcpdump not found. DNS mapping will fall back to reverse DNS."
  exec sleep infinity
fi

# Capture DNS responses (UDP source port 53) with -v to see query names.
# -l: line-buffered, -n: no name resolution, -v: verbose (shows question section)
exec sudo tcpdump -l -n -v -i any 'udp src port 53' 2>/dev/null | while IFS= read -r line; do
  # tcpdump -v DNS response format:
  #   resolver.53 > client.port: txid q: A? github.com. 1/0/0 github.com. A 140.82.121.3 (52)
  #   resolver.53 > client.port: txid q: A? cdn.ex.com. 2/0/0 cdn.ex.com. CNAME real.cdn.net., real.cdn.net. A 1.2.3.4 (80)

  # Extract queried domain from question section: "q: A? domain." or "q: AAAA? domain."
  query_domain=$(printf '%s' "$line" | sed -n 's/.*q: [A-Z]*? \([^ ]*\)\..*/\1/p')
  [ -z "$query_domain" ] && continue

  # Extract all A record IPs (IPv4)
  printf '%s' "$line" | grep -oE ' A [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r _ ip; do
    printf '%s %s\n' "$ip" "$query_domain" >> "$DNS_MAP_FILE"
  done

  # Extract all AAAA record IPs (IPv6)
  printf '%s' "$line" | grep -oE ' AAAA [0-9a-fA-F:]+' | while read -r _ ip; do
    printf '%s %s\n' "$ip" "$query_domain" >> "$DNS_MAP_FILE"
  done
done
