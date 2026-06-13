# Runtime Monitoring Agent — Design Roadmap

**Status:** Design only — no code implemented yet. This document describes the Phase 5 architecture for a future optional runtime monitoring component. All current Chaintrap detection remains shift-left static analysis.

---

## Motivation

Static analysis (CTW-* rules) can detect attack patterns before merge and before execution, on any repository and any runner, with zero opt-in. However, some threat categories are only observable at runtime:

| Threat | Static coverage | Runtime gap |
|--------|-----------------|-------------|
| Egress to unknown dynamic host | CTW-008/016 (known sinks + raw IP) | Ephemeral C2 on fresh domains |
| Exfiltration through DNS subdomains | CTC-EXFIL004 (code pattern) | Actual DNS query to attacker resolver |
| Process tree anomalies | — | Unexpected child processes of runner |
| File reads of masked secrets | CTW-012 (code pattern) | Actual `/proc/<pid>/mem` read against runner process |
| Lateral movement to other jobs | — | Network connections to internal runner metadata |

The runtime agent provides defence-in-depth for these gaps without replacing the static layer.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  GitHub-hosted runner (ubuntu-latest)               │
│                                                     │
│  Step 0 (first-in-job):  Chaintrap Runtime Agent   │◄── agent binary or
│    - DNS proxy (127.0.0.1:53 → resolver)            │    Docker sidecar
│    - inotify watcher on $GITHUB_WORKSPACE           │
│    - /proc poller for process tree                  │
│    - iptables egress logger (audit) or dropper      │
│                                                     │
│  Step 1..N: Normal job steps                        │
│                                                     │
│  Step N+1 (always): Agent emit                      │
│    - Correlate events → step/job context            │
│    - Write SARIF supplemental results               │
│    - Optionally POST to Supabase baseline store     │
└─────────────────────────────────────────────────────┘
```

The agent is injected as the **first step** of each job via an optional composite action (not required for the core static scan). It runs in the background and terminates after the final step, emitting findings into the same SARIF file as the static scan.

---

## Track 1: Egress Allowlist Enforcement

### Audit mode (default)
- Intercept outbound DNS queries via a loopback DNS proxy (`unbound` or a lightweight Go binary).
- Log every unique FQDN → resolving IP pair with the step context (injected via `$GITHUB_STEP`).
- At job end, compare against a configured allowlist (`egress.allow` in `.chaintrap.yml`).
- Flag any FQDN that is a known exfil sink (`data/exfil_sinks.txt`) or matches no allowlist entry.

### Block mode (optional, `egress.block_unlisted: true`)
- Use `iptables` / `nftables` DROP rules to block any outbound connection to hosts not in the allowlist.
- DNS proxy returns `NXDOMAIN` for disallowed FQDNs.
- Log blocked attempts as `CTW-016` (CRITICAL) in the SARIF output.

### False-positive mitigation
- Pre-seed the allowlist with GitHub Actions infrastructure FQDNs at startup (from GitHub's published IP ranges).
- Allow packages to declare expected egress in `.chaintrap.yml` under `egress.allow`.
- Never block connections to `*.actions.githubusercontent.com` or `*.github.com`.

---

## Track 2: Workspace File-Integrity Monitoring

- Start an `inotify` watcher on `$GITHUB_WORKSPACE` immediately after checkout.
- Watch events: `IN_CREATE`, `IN_MODIFY`, `IN_MOVED_TO`.
- **Critical paths** that always alert regardless of step context:
  - `.github/workflows/**` → CTW-015 (CRITICAL, persistent backdoor)
  - `.git/hooks/**` → CTW-015 (CRITICAL)
  - `package.json`, `requirements.txt`, lock files → CTW-019 (HIGH, supply-chain tamper)
  - Any file with executable bit set that was not present at checkout → CTW-014 (HIGH)
- **Noise filters:**
  - Ignore writes inside `node_modules/`, `.venv/`, `__pycache__/`, `dist/`, `build/`.
  - Ignore writes by known-safe step names (e.g., `actions/checkout`, `actions/setup-node`).

---

## Track 3: Process-Tree Monitoring

- Poll `/proc/<pid>/cmdline` and `/proc/<pid>/status` every 500 ms during job execution.
- Maintain a process tree rooted at the runner's init PID.
- **Alert patterns:**
  - `grep`/`rg` targeting `/proc/*/environ` or `/proc/*/mem` → CTW-012 (CRITICAL, secret scraping)
  - `git push` spawned from a job step while `contents: write` is set → CTW-014
  - `nc`, `socat`, `bash -i` spawned with a `/dev/tcp/` redirect → CTW-017 (CRITICAL)
  - Unexpected interpreter spawns (`perl -e`, `ruby -e`, `python -c`) → CTW-018 (HIGH)
  - `npm config set registry` or `pip config set global.index-url` → CTW-019

- **Step attribution:** Each process inherits the step number from its parent via environment variable injection (`CHAINTRAP_STEP_IDX`). The agent reads this to attribute findings accurately.

---

## Track 4: Event Correlation Layer (Longer-Term)

Static and runtime scanning are per-run. The correlation layer aggregates signals across runs and across GitHub API events for multi-stage attack detection.

### Ingestion sources

| Source | Signals |
|--------|---------|
| GitHub Audit Log | `workflows.prepared_workflow_job.secrets` (which secrets were injected), `org.set_default_workflow_permissions`, `workflow_run.event == pull_request_target` |
| GitHub Webhook | `workflow_run` events, `push` to `.github/workflows/**`, `pull_request.head.repo.fork` |
| Chaintrap SARIF output | Per-run CTW-* and CTC-* findings |
| Runtime agent events | Egress, file-write, process events (Track 1-3 above) |

### Detection patterns

| Multi-stage pattern | Individual signals | Correlated conclusion |
|----|----|----|
| **Slow exfil** | DNS queries to fresh domain (run 1), `git push` with new file (run 2) | Staged exfil across runs |
| **Permissions escalation** | `org.set_default_workflow_permissions` + `workflow_run` trigger added | Attacker gained write access and added privileged trigger |
| **Worm propagation** | `npm publish` in run + `CTC-TTP012` (worm-propagation code) | Active supply-chain worm |
| **Fork poisoning** | `CTW-001` (fork checkout) + `CTW-013` (secret to file) + secrets injected per audit log | Confirmed Pwn Request with secret exfil |

### Storage

- Findings and runtime events stored in Supabase (existing `chaintrap_scan_results` table).
- New `chaintrap_runtime_events` table: `(org_id, repo, run_id, step, event_type, host, file, pid, timestamp)`.
- Correlation queries run on a scheduled Edge Function (Supabase cron) or on each push webhook.

---

## Coverage Gap Map

| Threat | Static (now) | Runtime (Phase 5) | Correlation (Phase 6) |
|--------|-------------|-------------------|----------------------|
| Pwn Request checkout | CTW-001 | — | Confirm with audit log secrets |
| Secret interpolation | CTW-005 | — | — |
| Env dump | CTW-012 | `/proc` poll | — |
| Secret staged to file | CTW-013 | inotify | — |
| Repo self-mutation | CTW-014 | process tree (`git push`) | Cross-run push pattern |
| CI config tamper | CTW-015 | inotify on `.github/` | — |
| Egress to unknown | CTW-016 (known sinks) | DNS proxy all hosts | — |
| Reverse shell | CTW-017 | process tree (`/dev/tcp`) | — |
| Dynamic exec | CTW-018 | process tree | — |
| Registry hijack | CTW-019 | `npm config` proc | — |
| Expression injection | CTW-022 | — | — |
| Artifact poisoning | CTW-023 | inotify (downloaded artifact exec) | — |
| Fresh domain C2 | — | DNS proxy | First-seen domain alert |
| Cross-run worm | — | — | Correlation |

---

## Implementation Phases

### Phase 5a — Egress DNS proxy (Linux runners only)
- Lightweight Go binary: intercepts DNS on `127.0.0.1:5353`, logs FQDNs, forwards to `8.8.8.8`.
- Injected via `chaintrap-sec/runtime-agent@v1` composite action.
- Emits `CTW-016` findings into SARIF at job completion.

### Phase 5b — File-integrity watcher
- Python `watchdog` or `inotify-simple` watcher started in a background thread.
- Shares the Supabase client already used for IOC lookups.

### Phase 5c — Process-tree monitor
- Polls `/proc` in a 500 ms loop (Python, negligible CPU).
- Correlates PIDs to step index via environment variable.

### Phase 6 — Correlation layer
- Supabase Edge Function subscribes to GitHub webhooks.
- Runs correlation queries on each new scan result.
- Posts alerts to configured notification channel (Slack, email, or GitHub Issue).

---

## Security Considerations for the Agent Itself

- The agent binary is pinned to a full commit SHA and verified via SLSA provenance before execution.
- The agent runs with no additional permissions beyond the job's GITHUB_TOKEN.
- DNS proxy: only forwards to a hardcoded upstream (no user-configurable upstream).
- File-integrity watcher: read-only access to the workspace; cannot modify files.
- All agent telemetry is written to the same SARIF file, not to external endpoints (by default).
- The agent respects `egress.allow` itself — its own outbound connections (Supabase) are exempted.
