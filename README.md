# ZACAIM

`ZACAIM` is a terminal-first security workspace for authorized lab work, internal testing, and customer engagements.

This repository currently contains two tracks:

- `zacaim_v2.py`: the main CLI pentest workbench
- `zacaim_wifi_tool.py`: an older WiFi-oriented script kept as a legacy path

The project direction is centered on operator workflow, evidence capture, and reporting, not blind automation.

## Scope

Use this repository only on systems, applications, and wireless environments you own or are explicitly authorized to assess.

Good fits:

- local lab environments
- TryHackMe / HTB style training boxes
- internal security assessments
- approved customer engagements

## Current Layout

- [`zacaim_v2.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_v2.py): main CLI workbench
- [`zacaim_wifi_tool.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_wifi_tool.py): legacy WiFi menu script
- [`SESSION_HANDOFF.md`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/SESSION_HANDOFF.md): project direction and next-phase notes
- [`.gitignore`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/.gitignore): ignores local app data and Python cache artifacts

## ZACAIM V2

`zacaim_v2.py` is the primary interface and should be treated as the active code path.

### What It Does

- animated terminal boot sequence and live-ready dashboard
- health checks for core tooling
- standalone host scans
- low-impact web URL fingerprinting
- engagement registry and target tracking
- notes and evidence storage
- structured findings and markdown/JSON report generation
- local WiFi workspace status checks

### CLI Areas

- `health`: validate environment and tool availability
- `scan`: run host enumeration against an IP or hostname
- `web scan`: fingerprint an authorized HTTP/S URL
- `engagement init|list|add-target|list-targets|scan`: manage scoped workspaces and scans
- `note add`: attach notes to tracked targets
- `evidence add`: store text or files as evidence
- `wifi status`: inspect local wireless tool and adapter readiness

### Interactive Experience

Running `python3 zacaim_v2.py` starts the interactive CLI with:

- animated startup
- dashboard summary for sessions and engagements
- moving status indicator so long-running work feels alive
- richer scan summaries directly in the terminal

### Scan Outputs

Each scan session writes artifacts under `.zacaim_v2/` and typically includes:

- `artifacts/` command stdout/stderr captures
- `raw/` raw scan output such as Nmap XML/text
- `reports/summary.json`
- `reports/findings.json`
- `reports/report.md`

### App Storage

The application stores data under `.zacaim_v2/` in the current environment.

Important paths:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/notes/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/evidence/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/reports/`
- `.zacaim_v2/engagements/<engagement>/sessions/`

### Tooling

Core tools:

- `python3`
- `curl`
- `nmap`

Optional tools:

- `openssl`
- `whatweb`
- `iw`
- `nmcli`

Missing optional tools do not stop the CLI; their related checks are skipped or downgraded.

## Legacy WiFi Script

`zacaim_wifi_tool.py` is still present as a legacy script and is separate from the main V2 workflow.

It currently provides a menu-driven wireless lab flow around local Aircrack-ng style tooling, including:

- environment preparation
- monitor mode setup
- live wireless capture views
- capture/crack-oriented workflow steps

This script expects a Linux environment with the relevant wireless tooling installed and typically requires elevated privileges.

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

### Web URL Scan

```bash
python3 zacaim_v2.py web scan https://example.com
```

### Create Engagement

```bash
python3 zacaim_v2.py engagement init thm-demo --description "TryHackMe lab" --scope "Lab only"
```

### Register Target

```bash
python3 zacaim_v2.py engagement add-target thm-demo 10.10.10.11 --name dc --tags windows ad
```

### Scan Engagement Target

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

The current workspace is being used from WSL-compatible paths. For heavier day-to-day work, moving the repository into the Linux home directory inside WSL can improve tool compatibility and performance.

## Project Direction

The strongest next phase for `zacaim_v2.py` is:

- service-specific modules for `web`, `smb`, and `ad`
- CVE candidate enrichment from product/version fingerprints
- entity extraction for hosts, domains, users, URLs, and shares
- stronger findings confidence and validation workflow
- scan-to-scan correlation and timeline views

## Verification

Recent local checks used during this update:

- `python3 -m py_compile zacaim_v2.py`
- `python3 zacaim_v2.py health`
- `python3 zacaim_v2.py wifi status`
- `python3 zacaim_v2.py web scan https://example.com`
