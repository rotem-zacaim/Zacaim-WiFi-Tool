# Session Handoff

## Project Goal

`ZACAIM V2` is being reshaped from an old WiFi-oriented prototype into a pentest workbench for:

- PT workflows
- TryHackMe / CTF labs
- authorized internal or customer engagements

The direction is not "exploit automation", but a structured operator workspace:

- scan targets
- store artifacts
- manage engagements
- track notes and evidence
- generate findings and reports

## Current Main File

Use:

- `zacaim_v2.py`

The old file:

- `zacaim_wifi_tool.py`

is still in the repo only as legacy reference and should not be treated as the main implementation.

## What Already Exists

The current CLI in `zacaim_v2.py` supports:

- health check
- standalone target scans
- engagement creation
- adding targets to an engagement
- listing registered targets
- adding notes to targets
- adding evidence to targets
- scanning registered targets inside an engagement

It also creates:

- `summary.json`
- `findings.json`
- `report.md`

for each scan session.

## Storage Layout

App data is stored under `.zacaim_v2/` in the project folder in this environment.

Important paths:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/notes/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/evidence/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/reports/`
- `.zacaim_v2/engagements/<engagement>/sessions/`

## Environment

We now have WSL available.

Useful current path mapping:

- Windows repo: `C:\Users\rotem\Documents\codex\Zacaim-WiFi-Tool`
- WSL repo path: `/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool`

WSL status already verified:

- distro: `Ubuntu`
- WSL version: `2`
- Python available in WSL: `python3 3.12.3`

Recommended next environment step:

- move the repo into the Linux home directory inside WSL for better tooling/performance if continuing serious PT work there

## Important Limitation Right Now

The tool currently does useful discovery and organization, but it is still not strong enough yet for high-quality PT output.

What is missing most:

- service-specific follow-up modules
- CVE candidate enrichment
- entity extraction for users/domains/hosts
- command history timeline
- stronger correlation between multiple scan results

## Best Next Step

The strongest next implementation phase is:

1. add service-specific modules for `web`, `smb`, and `ad`
2. add CVE candidate mapping from service/product/version
3. add entity storage for usernames, domains, hosts, URLs, shares
4. improve findings with confidence and validation steps

## Useful Commands

Health check:

```bash
python3 zacaim_v2.py health
```

Standalone scan:

```bash
python3 zacaim_v2.py scan 10.10.10.10 --profile standard
```

Create engagement:

```bash
python3 zacaim_v2.py engagement init thm-demo --description "TryHackMe lab" --scope "Lab only"
```

Add target:

```bash
python3 zacaim_v2.py engagement add-target thm-demo 10.10.10.11 --name dc --tags windows ad
```

Scan registered target:

```bash
python3 zacaim_v2.py engagement scan thm-demo --target dc --profile deep
```

Add note:

```bash
python3 zacaim_v2.py note add thm-demo dc "Initial SMB observations" --category enum --tags smb windows
```

Add text evidence:

```bash
python3 zacaim_v2.py evidence add thm-demo dc --text "Captured banner" --description "Quick evidence"
```

## Guidance For The Next Session

If continuing development, start by:

1. opening `zacaim_v2.py`
2. treating it as the main codebase
3. ignoring `zacaim_wifi_tool.py` unless legacy behavior needs to be copied
4. deciding whether to continue on `/mnt/c/...` or move the repo into WSL home
5. implementing Phase 2: `web/smb/ad modules + CVE enrichment + entity extraction`
