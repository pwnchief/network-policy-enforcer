# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A GitHub Action (composite) that uses Cilium Tetragon (eBPF) to monitor and optionally block outbound network connections from GitHub Actions runners. Two modes: **audit** (observe and report) and **block** (reject connections to disallowed domains at the network level, fail the workflow).

## Architecture

Shell-based GitHub Action with no build step. Entry point is `action.yml`, which orchestrates five shell scripts:

1. **`scripts/setup.sh`** - Downloads Tetragon binary, verifies checksum, applies TracingPolicy, starts Tetragon daemon, writes allowed-domains list, sets up iptables firewall (block mode), starts DNS and event monitors.
2. **`scripts/dns-monitor.sh`** - Captures DNS responses via `tcpdump` to build a real-time IP-to-domain map (`/tmp/net-enforcer-dns-map.txt`). Replaces unreliable reverse DNS lookups.
3. **`scripts/monitor.sh`** - Tails Tetragon's JSON event stream, resolves destination IPs using the DNS map (falling back to reverse DNS), checks against allowed-domains list, and logs violations.
4. **`scripts/report.sh`** - Summarizes audit log, emits `::notice::` (audit) or `::error::` (block) GitHub Actions annotations, exits non-zero on violations.
5. **`scripts/teardown.sh`** - Stops monitor/DNS/Tetragon processes, removes iptables rules.

### Enforcement layers (block mode)

- **iptables** (`NET_ENFORCER` chain): Default-deny with REJECT. Allowed domain IPs are pre-resolved at setup and added as ACCEPT rules. Connections to disallowed IPs are rejected at the network layer before data leaves the machine.
- **DoH prevention**: Outbound HTTPS (port 443) to known public DNS resolver IPs (Google, Cloudflare, Quad9, OpenDNS) is blocked, forcing all DNS through the system resolver where `tcpdump` can observe it.
- **Tetragon + monitor.sh**: Observes `tcp_connect` kprobe events for logging and violation reporting. Does not kill processes — iptables handles blocking.

**TracingPolicies** (`policies/audit.yaml`, `policies/block.yaml`) hook `tcp_connect` kprobes excluding localhost, both with `action: Post` (observe-only).

## Key Design Decisions

- All temp files use the `/tmp/net-enforcer-` prefix.
- GitHub infrastructure domains are always allowed (hardcoded in `setup.sh`).
- Wildcard matching uses `*.example.com` syntax via POSIX shell `case` patterns in `monitor.sh:matches_allowed_domain()`.
- DNS resolution uses captured DNS responses (dns-monitor.sh) instead of reverse DNS. Falls back to `getent hosts` / `dig -x` when the DNS map has no entry.
- Scripts use POSIX `sh`, not bash, for portability.
- Graceful degradation: if kernel < 5.8, Tetragon fails, or tcpdump is missing, the action warns and continues rather than failing.

## Testing

No automated test suite. Push the action to a GitHub repo and use example workflows in `example/.github/workflows/` (`test-audit.yml`, `test-block.yml`). Requires a Linux runner with kernel >= 5.8 and sudo access.

## File Layout

- `action.yml` - GitHub Action definition (composite action entry point)
- `scripts/` - Shell scripts (setup, dns-monitor, monitor, report, teardown)
- `policies/` - Cilium Tetragon TracingPolicy YAML files
- `example/` - Example GitHub Actions workflows for testing
