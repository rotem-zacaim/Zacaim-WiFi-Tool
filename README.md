# ZACAIM

`ZACAIM` is a terminal-first operator workstation for authorized host discovery, web mapping, evidence collection, and engagement reporting.

This repository currently contains two tracks:

- `zacaim_v2.py`: the active CLI workbench
- `zacaim_wifi_tool.py`: a legacy WiFi-oriented script preserved as a separate path

The main direction of the project is workflow orchestration and structured analysis, not blind exploit automation.

## Scope

Use this repository only on systems, applications, networks, and wireless environments you own or are explicitly authorized to assess.

Good fits:

- local labs
- CTF / training environments
- internal security testing
- approved customer engagements

## Repository Layout

- [`zacaim_v2.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_v2.py): primary CLI workbench
- [`zacaim_wifi_tool.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_wifi_tool.py): legacy WiFi lab script
- [`SESSION_HANDOFF.md`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/SESSION_HANDOFF.md): project direction and handoff notes
- [`.gitignore`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/.gitignore): ignores local app data and Python cache

## ZACAIM V2

`zacaim_v2.py` is the main interface and should be treated as the current implementation.

### UX

The CLI now includes:

- animated boot sequence with matrix-style startup visuals
- modernized logo and landing screen
- workstation-style dashboard
- richer scan summaries
- live progress/status feedback during longer operations
- optional `rich`-powered rendering when the library is installed

### Core Capabilities

- environment and tool health checks
- standalone host scanning with multi-tool enrichment
- web automation profiles for authorized HTTP/S targets
- engagement and target registry management
- notes and evidence capture
- structured findings and markdown/JSON reporting
- local WiFi workspace readiness checks

## Host Scan Pipeline

Host/IP scans are no longer just a minimal `nmap` wrapper. The host workflow can combine:

- `nmap` service and version detection
- reverse DNS checks with `dig` and `host`
- `ssh-keyscan` collection for exposed SSH services
- automatic web endpoint enrichment for HTTP/S-like services
- optional web-side enrichment on discovered endpoints with:
  - `httpx`
  - `whatweb`
  - `wafw00f`
  - `katana`
  - `testssl.sh`

Host reports now track:

- service groups such as `web`, `admin`, `files`, and `database`
- reverse DNS observations
- SSH host key material
- TLS highlights
- recommended next steps

### Host Scan Profiles

- `quick`
- `standard`
- `deep`

## Web Automation Pipeline

`web scan` supports deeper discovery profiles instead of a single shallow fingerprint pass.

### Web Profiles

- `safe`
- `standard`
- `deep`

### Web Automation Stages

Depending on the profile and installed tooling, the web workflow can include:

- HTTP header and body probing with `curl`
- TLS inspection with `openssl`
- technology hints with `whatweb`
- richer probing with `httpx`
- WAF/WAAP identification with `wafw00f`
- crawl and endpoint discovery with `katana`
- TLS review with `testssl.sh`
- known-path checks for:
  - `robots.txt`
  - `sitemap.xml`
  - `.well-known/security.txt`
  - `security.txt`

Web reports now include:

- reachable endpoints
- titles, headers, and technology hints
- crawl URL counts and crawl samples
- WAF/CDN hints
- reachable known paths
- TLS highlights
- recommended next steps

## Engagement Workflow

The built-in engagement workflow supports:

- creating engagement workspaces
- registering targets
- scanning one target or all targets in scope
- attaching notes
- storing text or file evidence
- retaining latest report artifacts per target

Available commands:

- `engagement init`
- `engagement list`
- `engagement add-target`
- `engagement list-targets`
- `engagement scan`
- `note add`
- `evidence add`

## Reports And Artifacts

Each scan session writes structured output under `.zacaim_v2/`.

Typical layout:

- `artifacts/`: stdout/stderr from individual tools
- `raw/`: base scan artifacts such as Nmap XML/text
- `reports/summary.json`
- `reports/findings.json`
- `reports/report.md`

The generated report now includes:

- scope metadata
- service summary
- host automation summary
- web automation summary
- findings and leads
- recommended next steps
- command execution results

## Storage Layout

The application stores data under `.zacaim_v2/` in the current environment.

Important paths:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/notes/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/evidence/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/reports/`
- `.zacaim_v2/engagements/<engagement>/sessions/`

## Tooling

### Core

- `python3`
- `curl`
- `nmap`

### Optional Host And Web Enrichment

- `openssl`
- `whatweb`
- `httpx`
- `katana`
- `wafw00f`
- `testssl.sh`
- `dig`
- `host`
- `ssh-keyscan`

### Optional CLI UX

- `rich`

### Optional Local Wireless Status

- `iw`
- `nmcli`

Missing optional tools do not stop the CLI. Their related stages are skipped and recorded in the session artifacts/report.

## Legacy WiFi Script

`zacaim_wifi_tool.py` is still present as a separate legacy script and is not the primary code path.

It currently provides a menu-driven wireless lab workflow around Aircrack-ng style tooling, including:

- local environment preparation
- monitor mode setup
- live wireless views
- capture/crack-oriented lab steps

This script expects a Linux environment with the relevant wireless tooling installed and usually requires elevated privileges.

## Quick Start

### Interactive CLI

```bash
python3 zacaim_v2.py
```

### Health Check

```bash
python3 zacaim_v2.py health
```

### Standalone Host Scan

```bash
python3 zacaim_v2.py scan 10.10.10.10 --profile standard
```

### Deep Host Scan

```bash
python3 zacaim_v2.py scan 10.10.10.10 --profile deep
```

### Web Automation

```bash
python3 zacaim_v2.py web scan https://example.com --profile standard
```

### Deep Web Automation

```bash
python3 zacaim_v2.py web scan https://example.com --profile deep
```

### Create Engagement

```bash
python3 zacaim_v2.py engagement init thm-demo --description "TryHackMe lab" --scope "Lab only"
```

### Register Target

```bash
python3 zacaim_v2.py engagement add-target thm-demo 10.10.10.11 --name dc --tags windows ad
```

### Scan Registered Target

```bash
python3 zacaim_v2.py engagement scan thm-demo --target dc --profile deep
```

### Add Note

```bash
python3 zacaim_v2.py note add thm-demo dc "Initial SMB observations" --category enum --tags smb windows
```

### Add Evidence

```bash
python3 zacaim_v2.py evidence add thm-demo dc --text "Captured banner" --description "Quick evidence"
```

### WiFi Workspace Status

```bash
python3 zacaim_v2.py wifi status
```

## Environment Notes

The current workspace has been used from WSL-compatible paths. For heavier day-to-day work, keeping the repository inside the Linux home directory in WSL can improve tooling compatibility and performance.

## Verification

Recent local checks used during the latest updates:

- `python3 -m py_compile zacaim_v2.py`
- `python3 zacaim_v2.py health`
- `python3 zacaim_v2.py scan 127.0.0.1 --profile quick`
- `python3 zacaim_v2.py web scan https://example.com --profile safe`

## Next Upgrade Ideas

Strong candidates for the next phase:

- deeper parsers for `httpx`, `katana`, `testssl.sh`, and `nmap` output
- confidence and severity scoring
- richer host/service correlation
- CVE candidate enrichment from product/version fingerprints
- session diffing and timelines
- richer `rich` or full TUI layouts for scan review
