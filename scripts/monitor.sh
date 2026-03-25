#!/bin/sh

# Ensure files created by this script are world-readable (it may run as root)
umask 022

PREFIX="net-enforcer"
EVENTS_FILE="/tmp/${PREFIX}-events.json"
AUDIT_FILE="/tmp/${PREFIX}-audit.json"
VIOLATIONS_FILE="/tmp/${PREFIX}-violations.json"
ALLOWED_DOMAINS_FILE="/tmp/${PREFIX}-allowed-domains.txt"
POLICY_VIOLATION_FLAG="/tmp/${PREFIX}-policy-violation-detected"
DNS_MAP_FILE="/tmp/${PREFIX}-dns-map.txt"

# Check if a string is an IPv4 address
is_ipv4() {
  case "$1" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) return 0 ;;
    *) return 1 ;;
  esac
}

# Check if an IP falls within a CIDR range (IPv4 only).
# Uses bit arithmetic to compare network prefix.
ip_in_cidr() {
  _ip="$1"
  _cidr="$2"
  _net="${_cidr%/*}"
  _bits="${_cidr#*/}"

  # Convert IPs to 32-bit integers via awk
  _ip_int=$(printf '%s' "$_ip" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')
  _net_int=$(printf '%s' "$_net" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')

  # Compute mask and compare
  if [ "$_bits" -eq 0 ]; then
    return 0
  fi
  _mask=$(awk "BEGIN {printf \"%d\", (2^32 - 2^(32-$_bits))}")
  _ip_masked=$(awk "BEGIN {printf \"%d\", and($_ip_int, $_mask)}")
  _net_masked=$(awk "BEGIN {printf \"%d\", and($_net_int, $_mask)}")

  [ "$_ip_masked" = "$_net_masked" ]
}

# Match a destination (hostname or IP) against the allowed list.
# Supports: exact domains, *.wildcard domains, bare IPs, and CIDR ranges.
matches_allowed() {
  _host="$1"
  _ip="$2"
  while IFS= read -r _pattern || [ -n "$_pattern" ]; do
    # Skip empty lines and comments
    case "$_pattern" in
      ""|\#*) continue ;;
    esac

    # Exact match (domain or IP)
    if [ "$_host" = "$_pattern" ] || [ "$_ip" = "$_pattern" ]; then
      return 0
    fi

    # Wildcard domain match: *.example.com
    case "$_pattern" in
      \*.*)
        _suffix="${_pattern#\*}"
        case "$_host" in
          *"$_suffix") return 0 ;;
        esac
        ;;
    esac

    # CIDR match: 10.0.0.0/8, 172.16.0.0/12, etc.
    case "$_pattern" in
      */*) is_ipv4 "${_pattern%/*}" && ip_in_cidr "$_ip" "$_pattern" && return 0 ;;
    esac
  done < "$ALLOWED_DOMAINS_FILE"
  return 1
}

# Resolve IP to hostname using DNS map (captured from real DNS queries),
# falling back to reverse DNS only if the map has no entry.
resolve_host() {
  _ip="$1"
  _resolved=""
  # Check DNS map first (built by dns-monitor.sh from actual DNS responses)
  if [ -f "$DNS_MAP_FILE" ]; then
    _resolved=$(grep "^${_ip} " "$DNS_MAP_FILE" | tail -1 | awk '{print $2}')
  fi
  # Fall back to reverse DNS
  if [ -z "$_resolved" ]; then
    _resolved=$(getent hosts "$_ip" 2>/dev/null | awk '{print $2}')
  fi
  if [ -z "$_resolved" ]; then
    _resolved=$(dig +short +timeout=1 +tries=1 -x "$_ip" 2>/dev/null | grep -v '^;;' | sed 's/\.$//' | head -1)
  fi
  if [ -z "$_resolved" ]; then
    _resolved="$_ip"
  fi
  printf '%s' "$_resolved"
}

# Identify which GitHub Actions step a process belongs to by reading
# GITHUB_ACTION from /proc/<pid>/environ. Walks up the process tree
# (up to 5 levels) since child processes inherit the step's env vars.
get_step_name() {
  _pid="$1"
  _depth=0
  while [ "$_depth" -lt 5 ] && [ "$_pid" -gt 1 ]; do
    if [ -r "/proc/${_pid}/environ" ]; then
      _step=$(tr '\0' '\n' < "/proc/${_pid}/environ" 2>/dev/null | sed -n 's/^GITHUB_ACTION=//p' | head -1)
      if [ -n "$_step" ]; then
        printf '%s' "$_step"
        return 0
      fi
    fi
    # Walk up to parent process
    _ppid=$(awk '/^PPid:/ {print $2}' "/proc/${_pid}/status" 2>/dev/null)
    [ -z "$_ppid" ] && break
    _pid="$_ppid"
    _depth=$((_depth + 1))
  done
  printf '%s' "unknown"
}

# Wait for the events file to exist (Tetragon creates it on first event)
WAITED=0
while [ ! -f "$EVENTS_FILE" ] && [ "$WAITED" -lt 60 ]; do
  sleep 1
  WAITED=$((WAITED + 1))
done
if [ ! -f "$EVENTS_FILE" ]; then
  # Create empty file so tail -f can watch it
  touch "$EVENTS_FILE"
fi

tail -f "$EVENTS_FILE" 2>/dev/null | while IFS= read -r line; do
  # Fast-skip non-kprobe events to avoid slow jq parsing on every line.
  # Without this, thousands of process_exec/exit events cause the monitor
  # to fall behind and never reach the kprobe events in time.
  case "$line" in
    *'"process_kprobe"'*) ;;
    *) continue ;;
  esac

  # Parse fields from Tetragon kprobe event JSON
  pid=$(printf '%s' "$line" | jq -r '.process_kprobe.process.pid // empty' 2>/dev/null)
  binary=$(printf '%s' "$line" | jq -r '.process_kprobe.process.binary // empty' 2>/dev/null)
  destination_ip=$(printf '%s' "$line" | jq -r '.process_kprobe.args[]? | .sock_arg?.daddr? // empty' 2>/dev/null | head -1)
  destination_port=$(printf '%s' "$line" | jq -r '.process_kprobe.args[]? | .sock_arg?.dport? // empty' 2>/dev/null | head -1)
  timestamp=$(printf '%s' "$line" | jq -r '.time // empty' 2>/dev/null)

  # Skip lines that didn't parse into a valid event
  if [ -z "$pid" ] || [ -z "$destination_ip" ]; then
    continue
  fi

  # Skip localhost and cloud provider metadata/infrastructure IPs
  case "$destination_ip" in
    127.*|169.254.*|168.63.129.16) continue ;;
  esac

  # Resolve hostname and identify originating workflow step
  destination=$(resolve_host "$destination_ip")
  step=$(get_step_name "$pid" | tr -d '\000-\037')

  verdict="allowed"

  # Block mode check (matches against hostname, raw IP, and CIDR ranges)
  if [ "$INPUT_MODE" = "block" ]; then
    if [ -f "$ALLOWED_DOMAINS_FILE" ] && matches_allowed "$destination" "$destination_ip"; then
      verdict="allowed"
    else
      verdict="blocked"
    fi
  fi

  # Build audit record
  audit_record=$(jq -cn \
    --arg ts "$timestamp" \
    --argjson pid "$pid" \
    --arg binary "$binary" \
    --arg destination "$destination" \
    --arg ip "$destination_ip" \
    --argjson port "${destination_port:-0}" \
    --arg verdict "$verdict" \
    --arg step "$step" \
    '{ "timestamp": $ts, "pid": $pid, "binary": $binary, "destination": $destination, "ip": $ip, "port": $port, "verdict": $verdict, "step": $step }')

  # Append to audit log
  printf '%s\n' "$audit_record" >> "$AUDIT_FILE"

  # Handle blocked connections (iptables REJECT prevents data from leaving;
  # we only need to log the violation here)
  if [ "$verdict" = "blocked" ]; then
    printf '%s\n' "$audit_record" >> "$VIOLATIONS_FILE"
    printf '%s\n' "$audit_record" > "$POLICY_VIOLATION_FLAG"
  fi
done
