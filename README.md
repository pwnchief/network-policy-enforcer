# Network Policy Enforcer

[![Test - Audit Mode](https://github.com/pwnchief/network-policy-enforcer/actions/workflows/test-audit.yml/badge.svg)](https://github.com/pwnchief/network-policy-enforcer/actions/workflows/test-audit.yml)
[![Test - Block Mode](https://github.com/pwnchief/network-policy-enforcer/actions/workflows/test-block.yml/badge.svg)](https://github.com/pwnchief/network-policy-enforcer/actions/workflows/test-block.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A GitHub Action that monitors and enforces outbound network policies on CI/CD runners using [Cilium Tetragon](https://tetragon.io/) (eBPF) and iptables.

**No SaaS. No telemetry. No vendor lock-in.** ~300 lines of POSIX shell running entirely on your runner.

- **Audit mode** -- logs every outbound connection and generates a summary table in the GitHub Job Summary.
- **Block mode** -- rejects connections to disallowed domains at the network layer, fails the workflow, and reports exactly which step triggered the violation.

---

## Why

CI/CD pipelines run arbitrary code -- build scripts, package managers, post-install hooks, third-party actions. Any of these can exfiltrate secrets, download malware, or phone home to unexpected endpoints. Most teams have zero visibility into what their pipelines actually connect to.

This action gives you that visibility (audit mode) and the ability to enforce a strict allowlist (block mode), catching supply chain attacks, compromised dependencies, and misconfigured builds before data leaves the runner.

---

## Quick Start

### 1. Audit first

Add the action to your workflow in two phases: **setup** (start monitoring) and **report** (generate report and tear down). Place your build steps between them.

```yaml
jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4

      - name: Setup Network Policy Enforcer
        uses: pwnchief/network-policy-enforcer@v1
        with:
          mode: audit
          phase: setup

      - name: Build and Test
        run: |
          npm ci
          npm test

      - name: Report
        if: always()
        uses: pwnchief/network-policy-enforcer@v1
        with:
          mode: audit
          phase: report
```

After the job completes, check the **Job Summary** for a table of every domain, port, binary, and workflow step observed.

Audit mode also generates a policy file at `network-policy.txt` (configurable via `policy-file`) containing all observed domains. The Job Summary includes the file contents and a ready-to-use workflow snippet for switching to block mode.

### 2. Commit the policy file

Review the generated `network-policy.txt`, remove any domains that shouldn't be allowed, and commit it to your repo.

### 3. Switch to block mode

Point the action at your policy file:

```yaml
      - name: Setup Network Policy Enforcer
        uses: pwnchief/network-policy-enforcer@v1
        with:
          mode: block
          phase: setup
          allowed-domains-file: network-policy.txt

      # ... your build steps ...

      - name: Report
        if: always()
        uses: pwnchief/network-policy-enforcer@v1
        with:
          mode: block
          phase: report
          allowed-domains-file: network-policy.txt
```

Connections to domains not in the file are **rejected at the network layer** (the process gets an immediate connection error) and the workflow fails with an error annotation showing the blocked domain and the originating step.

You can also inline the domains directly:

```yaml
          allowed-domains: |
            github.com
            registry.npmjs.org
            pypi.org
```

> **Tip:** Add `id:` to your workflow steps for clearer step attribution in the report. Without an `id`, steps may appear as `__run`, `__run_2`, etc.

---

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `mode` | Yes | -- | `audit` (observe and report) or `block` (enforce allowed domains). |
| `phase` | Yes | -- | `setup` (start monitoring) or `report` (generate report and tear down). |
| `allowed-domains` | No | -- | Inline list of permitted domains (one per line). Ignored if `allowed-domains-file` is set. |
| `allowed-domains-file` | No | -- | Path to a file containing allowed domains (one per line, `#` comments supported). Takes precedence over `allowed-domains`. |
| `policy-file` | No | `network-policy.txt` | Path where audit mode writes the generated policy file. |
| `tetragon-version` | No | `v1.3.0` | Version of Cilium Tetragon to install. |

---

## Allowed Entries Format

The allowed list (inline or file) supports domains, wildcards, bare IPs, and CIDR ranges:

```
# Exact domain
github.com

# Wildcard -- matches any subdomain
*.googleapis.com

# Bare IP address
172.16.5.10

# CIDR range
10.0.0.0/8

# Comments are supported
# registry.npmjs.org
```

- `*.example.com` matches any subdomain (`sub.example.com`, `deep.sub.example.com`).
- `example.com` matches only `example.com` exactly.
- `10.0.0.0/8` matches any IP in the CIDR range.
- `1.2.3.4` matches that exact IP.
- Lines starting with `#` are comments. Blank lines are ignored.

---

## How It Works

### Audit mode

1. **Tetragon** traces `tcp_connect` kernel calls via eBPF kprobes.
2. A **DNS monitor** captures DNS responses via `tcpdump` to map IPs to the actual queried domain name (instead of unreliable reverse DNS).
3. Every connection is logged with: domain, IP, port, binary path, and originating workflow step.
4. A summary table is written to the GitHub Job Summary. A policy file is generated for transitioning to block mode.

### Block mode

Everything from audit mode, plus three enforcement layers:

1. **iptables firewall** -- A dedicated `NET_ENFORCER` chain with default REJECT. Allowed domain IPs are pre-resolved and added as ACCEPT rules. GitHub infrastructure CIDRs from [api.github.com/meta](https://api.github.com/meta) are bulk-loaded via `ipset` for O(1) matching. Disallowed connections get an immediate TCP RST or ICMP unreachable -- no timeout, no data exfiltrated.

2. **DNS-over-HTTPS prevention** -- Outbound HTTPS (port 443) to known public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS) is blocked, forcing all DNS through the system resolver where `tcpdump` can observe it.

3. **Blocked connection reporting** -- Connections rejected by iptables are logged via kernel `LOG` target and surfaced in the Job Summary alongside Tetragon-observed events. Both firewall-level and monitor-level blocks appear in the report.

### Step-level attribution

Each connection (allowed or blocked) is attributed to the workflow step that triggered it. The monitor reads `GITHUB_ACTION` from `/proc/<pid>/environ`, walking up the process tree to find the step context.

---

## Always-Allowed Domains

These GitHub infrastructure domains are always permitted regardless of your `allowed-domains` list:

| Domain | Purpose |
|---|---|
| `github.com` / `*.github.com` | Git operations, API, runner infrastructure |
| `*.githubusercontent.com` | Actions, raw files, release downloads |
| `ghcr.io` / `*.ghcr.io` | GitHub Container Registry |
| `pkg.github.com` | GitHub Package Registry |
| `pipelines.actions.githubusercontent.com` | Actions pipelines |

In block mode, the following are also automatically allowed at the firewall level:

| Target | Purpose |
|---|---|
| GitHub infrastructure CIDRs (via `api.github.com/meta`) | Runner log streaming, action downloads, status updates |
| `127.0.0.0/8` (localhost) | Local services |
| `169.254.169.254` / `168.63.129.16` | Cloud provider metadata and wireserver |
| System DNS resolvers | Name resolution (detected from resolv.conf and systemd-resolved) |

---

## Job Summary Output

After each run, a markdown table is written to the GitHub Job Summary:

**Audit mode** -- Lists all observed domains with port, binary, and step. Includes the generated policy file contents.

**Block mode** -- Shows:
- Blocked connections from the firewall (iptables LOG) with domain, IP, port, and protocol
- Blocked connections from the monitor (Tetragon) with domain, port, binary, step, PID, and timestamp
- Allowed connections table

---

## Requirements

- **GitHub-hosted runner** with `ubuntu-22.04` or later (or any Linux runner with kernel >= 5.8 and sudo access)
- **Kernel >= 5.8** -- Required for Tetragon's eBPF features. On older kernels, the action emits a warning and exits gracefully without blocking.
- **sudo access** -- Needed for Tetragon, iptables, tcpdump, and ipset.

---

## Known Limitations

- **DNS-over-HTTPS from custom resolvers.** DoH to well-known public resolvers (Google, Cloudflare, Quad9, OpenDNS) is blocked. A process using a non-standard DoH endpoint could bypass DNS monitoring (but iptables still blocks the connection if the destination IP isn't allowed).

- **No TLS inspection.** The action operates at the connection level. It sees destination IPs and ports but cannot inspect HTTP paths or request bodies within HTTPS traffic.

- **Step attribution is best-effort.** If the connecting process exits before `/proc/<pid>/environ` can be read, the step shows as `unknown`. Short-lived processes may occasionally miss step correlation.

- **Wildcard domains cannot be pre-resolved.** Entries like `*.googleapis.com` rely on runtime DNS monitoring for the monitor's allowlist check. At the iptables level, only explicitly resolved domains have firewall rules -- wildcard subdomains that resolve to IPs not seen during setup will be blocked by iptables but flagged as "allowed" by the monitor.

- **IPv4 only.** The iptables rules and ipset target IPv4 traffic. IPv6 connections are not currently filtered.

---

## Architecture

```
action.yml (composite action entry point)
 |
 ├── scripts/setup.sh      -- Downloads Tetragon, starts daemon, configures iptables, starts monitors
 ├── scripts/dns-monitor.sh -- Captures DNS responses via tcpdump → IP-to-domain map
 ├── scripts/monitor.sh     -- Tails Tetragon events, resolves IPs, checks allowlist, logs violations
 ├── scripts/report.sh      -- Generates Job Summary, annotations, policy file
 └── scripts/teardown.sh    -- Stops processes, removes iptables rules

policies/
 ├── audit.yaml             -- Tetragon TracingPolicy (observe tcp_connect)
 └── block.yaml             -- Tetragon TracingPolicy (observe tcp_connect)
```

All scripts are POSIX `sh` -- no bash required. Temp files use the `/tmp/net-enforcer-` prefix. Graceful degradation: if the kernel is too old, Tetragon fails to start, or tcpdump is missing, the action warns and continues without blocking.

---

## Recommended Workflow

1. **Start with audit mode** in your existing pipeline. Review the Job Summary to see every domain your build contacts.
2. **Commit the generated policy file.** Remove any domains you don't expect or need.
3. **Add `id:` to your workflow steps** for clear attribution in the network report.
4. **Switch to block mode.** Any unexpected connection is rejected at the network layer and the workflow fails with the exact step and domain identified.
5. **Iterate.** If a legitimate dependency is blocked, add it to your policy file and re-run.

---

## Examples

See the [`example/`](example/) directory for ready-to-use workflow files:

- [`test-audit.yml`](example/.github/workflows/test-audit.yml) -- Audit mode example
- [`test-block.yml`](example/.github/workflows/test-block.yml) -- Block mode example with allowed domains

---

## License

[Apache License 2.0](LICENSE)
