#!/bin/sh
PREFIX="net-enforcer"
MONITOR_PID_FILE="/tmp/${PREFIX}-monitor.pid"
DNS_PID_FILE="/tmp/${PREFIX}-dns-monitor.pid"
TETRAGON_PID_FILE="/tmp/${PREFIX}-tetragon.pid"

# Stop the monitor process (runs as root via sudo)
if [ -f "$MONITOR_PID_FILE" ]; then
  sudo kill "$(cat "$MONITOR_PID_FILE")" 2>/dev/null || true
fi

# Stop the DNS monitor
if [ -f "$DNS_PID_FILE" ]; then
  kill "$(cat "$DNS_PID_FILE")" 2>/dev/null || true
fi

# Stop Tetragon
if [ -f "$TETRAGON_PID_FILE" ]; then
  kill -TERM "$(cat "$TETRAGON_PID_FILE")" 2>/dev/null || true
fi

# Remove iptables rules (block mode cleanup)
if sudo iptables -L NET_ENFORCER -n >/dev/null 2>&1; then
  sudo iptables -D OUTPUT -m conntrack --ctstate NEW -j NET_ENFORCER 2>/dev/null || true
  sudo iptables -F NET_ENFORCER 2>/dev/null || true
  sudo iptables -X NET_ENFORCER 2>/dev/null || true
  sudo ipset destroy gh_infra 2>/dev/null || true
  echo "iptables rules cleaned up."
fi

echo "Tetragon stopped."
