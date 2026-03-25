#!/bin/sh
set -e

PREFIX="net-enforcer"

# Resolve ACTION_PATH (directory of this script's parent)
ACTION_PATH="${ACTION_PATH:-$(cd "$(dirname "$0")/.." && pwd)}"

# --- 1. Detect kernel version ---
echo ":: Detecting kernel version..."
KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]; }; then
  echo "::warning::Kernel version $KERNEL_VERSION is below 5.8. Tetragon requires kernel >= 5.8. Skipping setup."
  exit 0
fi
echo ":: Kernel version $KERNEL_VERSION is supported."

# --- 2. Download Tetragon binary ---
VERSION="${INPUT_TETRAGON_VERSION:-v1.3.0}"
TARBALL="tetragon-${VERSION}-amd64.tar.gz"
DOWNLOAD_URL="https://github.com/cilium/tetragon/releases/download/${VERSION}/${TARBALL}"
TMP_TARBALL="/tmp/${PREFIX}-${TARBALL}"

echo ":: Downloading Tetragon ${VERSION} from ${DOWNLOAD_URL}..."
if ! curl -fSL -o "$TMP_TARBALL" "$DOWNLOAD_URL"; then
  echo "::warning::Failed to download Tetragon binary from ${DOWNLOAD_URL}. Skipping setup."
  exit 0
fi

# Try to verify SHA256 checksum
echo ":: Attempting to verify SHA256 checksum..."
CHECKSUM_VERIFIED=false
TMP_CHECKSUM="/tmp/${PREFIX}-checksums.txt"
# Tetragon uses per-file .sha256sum files (e.g. tetragon-v1.6.0-amd64.tar.gz.sha256sum)
for CHECKSUM_FILE in "${TARBALL}.sha256sum" "SHA256SUMS" "checksums.txt"; do
  CHECKSUM_URL="https://github.com/cilium/tetragon/releases/download/${VERSION}/${CHECKSUM_FILE}"
  if curl -fSL -o "$TMP_CHECKSUM" "$CHECKSUM_URL" 2>/dev/null; then
    EXPECTED_SUM=$(grep "$TARBALL" "$TMP_CHECKSUM" | awk '{print $1}')
    # Per-file sha256sum may not contain the filename
    if [ -z "$EXPECTED_SUM" ]; then
      EXPECTED_SUM=$(awk '{print $1}' "$TMP_CHECKSUM" | head -1)
    fi
    if [ -n "$EXPECTED_SUM" ]; then
      ACTUAL_SUM=$(sha256sum "$TMP_TARBALL" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$TMP_TARBALL" 2>/dev/null | awk '{print $1}')
      if [ "$EXPECTED_SUM" = "$ACTUAL_SUM" ]; then
        echo ":: SHA256 checksum verified successfully."
        CHECKSUM_VERIFIED=true
      else
        echo "::warning::SHA256 checksum mismatch! Expected: ${EXPECTED_SUM}, Got: ${ACTUAL_SUM}"
      fi
    fi
    rm -f "$TMP_CHECKSUM"
    break
  fi
done
if [ "$CHECKSUM_VERIFIED" = "false" ]; then
  echo "::warning::Could not verify SHA256 checksum. Proceeding without verification."
fi

# --- 3. Extract tarball ---
EXTRACT_DIR="/tmp/${PREFIX}-tetragon"
echo ":: Extracting tarball to ${EXTRACT_DIR}..."
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$TMP_TARBALL" -C "$EXTRACT_DIR"
rm -f "$TMP_TARBALL"

# Search for tetragon binary
TETRAGON_BIN=$(find "$EXTRACT_DIR" -type f -name "tetragon" | head -n 1)
if [ -z "$TETRAGON_BIN" ]; then
  echo "::warning::Could not find tetragon binary in extracted contents. Skipping setup."
  exit 0
fi
chmod +x "$TETRAGON_BIN"
echo ":: Found tetragon binary at ${TETRAGON_BIN}"

# Search for bpf lib directory
BPF_DIR=$(find "$EXTRACT_DIR" -type d -name "bpf" | head -n 1)
BPF_FLAG=""
if [ -n "$BPF_DIR" ]; then
  BPF_FLAG="--bpf-lib ${BPF_DIR}"
  echo ":: Found BPF lib directory at ${BPF_DIR}"
else
  echo ":: No BPF lib directory found, proceeding without --bpf-lib flag."
fi

# --- 4. Write TracingPolicy YAML ---
MODE="${INPUT_MODE:-audit}"
POLICY_FILE="/tmp/${PREFIX}-policy.yaml"
echo ":: Writing tracing policy for mode: ${MODE}..."

if [ "$MODE" = "block" ]; then
  POLICY_SOURCE="${ACTION_PATH}/policies/block.yaml"
else
  POLICY_SOURCE="${ACTION_PATH}/policies/audit.yaml"
fi

if [ -f "$POLICY_SOURCE" ]; then
  cp "$POLICY_SOURCE" "$POLICY_FILE"
  echo ":: Policy written to ${POLICY_FILE}"
else
  echo "::warning::Policy file ${POLICY_SOURCE} not found. Skipping setup."
  exit 0
fi

# --- 5. Start Tetragon as a background daemon ---
EVENTS_FILE="/tmp/${PREFIX}-events.json"
LOG_FILE="/tmp/${PREFIX}-tetragon.log"
PID_FILE="/tmp/${PREFIX}-tetragon.pid"

# Pre-create the events file so Tetragon appends to it rather than creating
# a new root-only file. This lets monitor.sh (non-root) read events.
touch "$EVENTS_FILE"
chmod 644 "$EVENTS_FILE"

echo ":: Starting Tetragon daemon..."
# shellcheck disable=SC2086
sudo "$TETRAGON_BIN" $BPF_FLAG \
  --tracing-policy "$POLICY_FILE" \
  --export-filename "$EVENTS_FILE" \
  > "$LOG_FILE" 2>&1 &

TETRAGON_PID=$!
echo "$TETRAGON_PID" > "$PID_FILE"
echo ":: Tetragon started with PID ${TETRAGON_PID}"

# --- 6. Wait up to 10 seconds for Tetragon to become ready ---
# Tetragon v1.6.0+ uses ring buffers and only creates the export file on first event,
# so we check for the "Listening for events" log message instead.
echo ":: Waiting for Tetragon to become ready..."
READY=false
WAITED=0
while [ "$WAITED" -lt 10 ]; do
  if ! kill -0 "$TETRAGON_PID" 2>/dev/null; then
    echo "::warning::Tetragon process (PID ${TETRAGON_PID}) died during startup. Check ${LOG_FILE} for details."
    exit 0
  fi
  if grep -q "Listening for events" "$LOG_FILE" 2>/dev/null; then
    READY=true
    break
  fi
  sleep 1
  WAITED=$((WAITED + 1))
done

if [ "$READY" = "true" ]; then
  echo ":: Tetragon is ready (listening after ${WAITED}s)."
else
  echo "::warning::Tetragon did not become ready within 10 seconds. Check ${LOG_FILE} for details."
  exit 0
fi

# Make events file readable by non-root processes (report.sh, debug steps).
# Tetragon runs as root and creates the file with 600 permissions.
# Also chmod the log file for the same reason.
if [ -f "$EVENTS_FILE" ]; then
  sudo chmod 644 "$EVENTS_FILE"
fi
sudo chmod 644 "$LOG_FILE" 2>/dev/null || true

# --- 7. Write allowed-domains list ---
ALLOWED_FILE="/tmp/${PREFIX}-allowed-domains.txt"
echo ":: Writing allowed domains list to ${ALLOWED_FILE}..."

cat > "$ALLOWED_FILE" <<'EOF'
github.com
*.github.com
api.github.com
objects.githubusercontent.com
raw.githubusercontent.com
*.githubusercontent.com
ghcr.io
*.ghcr.io
pkg.github.com
*.actions.githubusercontent.com
pipelines.actions.githubusercontent.com
EOF

# Append user-specified domains (file takes precedence over inline input)
if [ -n "$INPUT_ALLOWED_DOMAINS_FILE" ] && [ -f "$INPUT_ALLOWED_DOMAINS_FILE" ]; then
  echo ":: Loading allowed domains from file: ${INPUT_ALLOWED_DOMAINS_FILE}"
  while IFS= read -r line || [ -n "$line" ]; do
    trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$trimmed" in ""|\#*) continue ;; esac
    echo "$trimmed" >> "$ALLOWED_FILE"
  done < "$INPUT_ALLOWED_DOMAINS_FILE"
elif [ -n "$INPUT_ALLOWED_DOMAINS" ]; then
  echo "$INPUT_ALLOWED_DOMAINS" | while IFS= read -r line; do
    trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -n "$trimmed" ]; then
      echo "$trimmed" >> "$ALLOWED_FILE"
    fi
  done
fi

echo ":: Allowed domains written."

# --- 8. Set up iptables firewall (block mode only) ---
if [ "$MODE" = "block" ]; then
  echo ":: Setting up iptables network-level enforcement..."

  # Create a dedicated chain
  sudo iptables -N NET_ENFORCER 2>/dev/null || true

  # Allow established/related connections (so in-flight setup traffic isn't broken)
  sudo iptables -A NET_ENFORCER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Allow localhost
  sudo iptables -A NET_ENFORCER -d 127.0.0.0/8 -j ACCEPT

  # Allow Azure IMDS and wireserver (used by GitHub-hosted runners for metadata)
  sudo iptables -A NET_ENFORCER -d 169.254.169.254 -j ACCEPT
  sudo iptables -A NET_ENFORCER -d 168.63.129.16 -j ACCEPT

  # Allow DNS to all system resolvers so name resolution keeps working.
  # On systemd-resolved systems, /etc/resolv.conf points to 127.0.0.53 (stub),
  # but the stub forwards to upstream resolvers listed in /run/systemd/resolve/resolv.conf.
  # We must allow traffic to BOTH the stub AND the upstream resolvers.
  DNS_ALLOW_IPS=""
  # Collect nameservers from /etc/resolv.conf
  for ns in $(grep '^nameserver' /etc/resolv.conf | awk '{print $2}'); do
    DNS_ALLOW_IPS="$DNS_ALLOW_IPS $ns"
  done
  # Collect upstream resolvers from systemd-resolved (if present)
  if [ -f /run/systemd/resolve/resolv.conf ]; then
    for ns in $(grep '^nameserver' /run/systemd/resolve/resolv.conf | awk '{print $2}'); do
      DNS_ALLOW_IPS="$DNS_ALLOW_IPS $ns"
    done
  fi
  # Also try resolvectl for any active DNS servers
  if command -v resolvectl >/dev/null 2>&1; then
    for ns in $(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{for(i=3;i<=NF;i++) print $i}'); do
      DNS_ALLOW_IPS="$DNS_ALLOW_IPS $ns"
    done
  fi
  # Deduplicate and add rules
  for dns_ip in $(printf '%s\n' $DNS_ALLOW_IPS | sort -u); do
    sudo iptables -A NET_ENFORCER -d "$dns_ip" -p udp --dport 53 -j ACCEPT
    sudo iptables -A NET_ENFORCER -d "$dns_ip" -p tcp --dport 53 -j ACCEPT
    echo ":: Allowed DNS to $dns_ip"
  done

  # Block DNS-over-HTTPS to known public resolvers to prevent DoH bypass.
  # Processes must use the system DNS resolver, which our tcpdump monitor can see.
  DOH_RESOLVERS="8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220"
  for doh_ip in $DOH_RESOLVERS; do
    sudo iptables -A NET_ENFORCER -d "$doh_ip" -p tcp --dport 443 -j REJECT --reject-with tcp-reset
  done
  echo ":: DoH bypass prevention rules applied."

  # Whitelist GitHub infrastructure CIDRs via ipset (O(1) matching).
  # The runner needs these for log streaming, action downloads, status updates.
  echo ":: Fetching and loading GitHub infrastructure CIDRs..."
  if ! command -v ipset >/dev/null 2>&1; then
    sudo apt-get install -y -qq ipset >/dev/null 2>&1 || true
  fi
  GH_META=$(curl -fsSL --max-time 10 https://api.github.com/meta 2>/dev/null || true)
  if [ -n "$GH_META" ]; then
    sudo ipset create gh_infra hash:net maxelem 65536 -exist
    # Use ipset restore for bulk loading (much faster than individual add calls)
    IPSET_RESTORE_FILE="/tmp/${PREFIX}-ipset-restore.txt"
    printf '%s' "$GH_META" | jq -r '(.actions // []) + (.web // []) + (.api // []) + (.git // []) | .[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"))' 2>/dev/null | sort -u | sed 's/^/add gh_infra /;s/$/ -exist/' > "$IPSET_RESTORE_FILE"
    GH_COUNT=$(wc -l < "$IPSET_RESTORE_FILE" | tr -d ' ')
    sudo ipset restore < "$IPSET_RESTORE_FILE"
    rm -f "$IPSET_RESTORE_FILE"
    sudo iptables -A NET_ENFORCER -m set --match-set gh_infra dst -j ACCEPT
    echo ":: Loaded ${GH_COUNT} GitHub infrastructure CIDRs into ipset."
  else
    echo "::warning::Could not fetch GitHub IP ranges from api.github.com/meta."
  fi

  # Pre-resolve allowed entries and add ACCEPT rules
  # Handles: bare IPs, CIDR ranges, domains (resolved to IPs), and skips wildcards
  echo ":: Pre-resolving allowed entries..."
  _add_accept() {
    sudo iptables -C NET_ENFORCER -d "$1" -j ACCEPT 2>/dev/null || \
      sudo iptables -A NET_ENFORCER -d "$1" -j ACCEPT || true
  }
  _resolve_and_accept() {
    resolved_ips=$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true)
    for rip in $resolved_ips; do
      _add_accept "$rip"
    done
  }

  while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in ""|\#*) continue ;; esac
    # Skip wildcard entries (can't pre-resolve *.example.com)
    case "$entry" in \*.*) continue ;; esac

    case "$entry" in
      # CIDR range or bare IPv4 — add directly
      */* | [0-9]*.[0-9]*.[0-9]*.[0-9]*)
        _add_accept "$entry"
        ;;
      # Domain name — resolve to IPs and add each
      *)
        _resolve_and_accept "$entry"
        ;;
    esac
  done < "$ALLOWED_FILE"
  echo ":: Allowed entries pre-resolved and added to firewall."

  # Log blocked connections before rejecting (so report.sh can show them)
  sudo iptables -A NET_ENFORCER -j LOG --log-prefix "NET_ENFORCER_BLOCK: " --log-level 4

  # Default REJECT for everything else (fail fast instead of timeout)
  sudo iptables -A NET_ENFORCER -p tcp -j REJECT --reject-with tcp-reset
  sudo iptables -A NET_ENFORCER -j REJECT --reject-with icmp-port-unreachable

  # Insert our chain into OUTPUT for new outbound connections
  sudo iptables -I OUTPUT -m conntrack --ctstate NEW -j NET_ENFORCER

  echo ":: iptables enforcement active."
fi

# --- 9. Start DNS monitor ---
DNS_MONITOR_SCRIPT="${ACTION_PATH}/scripts/dns-monitor.sh"
if [ -f "$DNS_MONITOR_SCRIPT" ]; then
  echo ":: Starting DNS monitor..."
  sh "$DNS_MONITOR_SCRIPT" &
  sleep 1
  echo ":: DNS monitor started."
else
  echo "::warning::DNS monitor script not found at ${DNS_MONITOR_SCRIPT}."
fi

# --- 10. Start monitor.sh as a background process ---
MONITOR_SCRIPT="${ACTION_PATH}/scripts/monitor.sh"
MONITOR_PID_FILE="/tmp/${PREFIX}-monitor.pid"

if [ -f "$MONITOR_SCRIPT" ]; then
  echo ":: Starting monitor process..."
  sudo INPUT_MODE="$MODE" sh "$MONITOR_SCRIPT" &
  MONITOR_PID=$!
  echo "$MONITOR_PID" > "$MONITOR_PID_FILE"
  echo ":: Monitor started with PID ${MONITOR_PID}"
else
  echo "::warning::Monitor script not found at ${MONITOR_SCRIPT}."
fi

echo ":: Setup complete."
