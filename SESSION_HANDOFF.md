# Session Handoff

## Project Goal

`ZACAIM V2` has moved away from being just an old WiFi-oriented prototype and is now positioned as a terminal-first pentest workbench for:

- PT workflows
- TryHackMe / CTF labs
- authorized internal or customer engagements

The direction is still not "exploit automation".

The current product goal is a structured operator workspace that can:

- scan hosts and URLs
- orchestrate multiple discovery/fingerprinting tools
- store artifacts
- manage engagements
- track notes and evidence
- generate findings and reports
- suggest next steps from observed data

## Current Main File

Use:

- `zacaim_v2.py`

The old file:

- `zacaim_wifi_tool.py`

still exists in the repository but should be treated as a legacy script, not the main implementation.

## What Already Exists

The current CLI in `zacaim_v2.py` now supports:

- health checks
- standalone host scans
- deeper web automation by URL
- engagement creation
- adding targets to engagements
- listing registered targets
- adding notes
- adding evidence
- scanning registered engagement targets
- local WiFi readiness/status checks

The CLI UX has also been upgraded:

- animated matrix-style boot sequence
- modernized logo/banner
- workstation-style dashboard
- richer terminal output
- optional `rich` rendering if the library is installed

## Host Scan Status

Standalone host scanning is now deeper than the original minimal `nmap` wrapper.

Current host scan flow can include:

- `nmap`
- reverse DNS enrichment via `dig` and `host`
- `ssh-keyscan` for exposed SSH services
- HTTP/S endpoint detection from discovered services
- web-side enrichment on discovered endpoints using:
  - `curl`
  - `openssl`
  - `whatweb`
  - `httpx`
  - `wafw00f`
  - `katana`
  - `testssl.sh`

Current host summaries/reporting include:

- service groups such as `web`, `admin`, `files`, `database`
- reverse DNS observations
- SSH host key metadata
- TLS highlights
- recommended next steps

## Web Scan Status

The URL workflow is no longer just a shallow fingerprint.

Current `web scan` supports profiles:

- `safe`
- `standard`
- `deep`

Depending on installed tooling and profile, the web pipeline can use:

- `curl`
- `openssl`
- `whatweb`
- `httpx`
- `wafw00f`
- `katana`
- `testssl.sh`

It also checks common paths:

- `/robots.txt`
- `/sitemap.xml`
- `/.well-known/security.txt`
- `/security.txt`

Current web summaries/reporting include:

- endpoint status/title/server data
- technology hints
- WAF/CDN hints
- crawl URL counts and crawl samples
- reachable known paths
- TLS highlights
- recommended next steps

## Reports And Artifacts

Each scan session currently writes:

- `summary.json`
- `findings.json`
- `report.md`

and supporting command output under:

- `artifacts/`
- `raw/`
- `reports/`

The report now includes:

- scope metadata
- service summary
- host automation summary
- web automation summary
- findings and leads
- recommended next steps
- command execution results

## Storage Layout

App data is stored under `.zacaim_v2/` in the project folder in this environment.

Important paths:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/notes/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/evidence/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/reports/`
- `.zacaim_v2/engagements/<engagement>/sessions/`

## Environment

Current environment details:

- Windows repo path: `C:\Users\rotem\Documents\codex\Zacaim-WiFi-Tool`
- WSL repo path: `/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool`
- distro: `Ubuntu`
- WSL version: `2`
- Python in WSL: `python3 3.12.3`

GitHub has already been configured in this environment:

- remote: `origin -> https://github.com/rotem-zacaim/Zacaim-WiFi-Tool.git`
- `gh` login completed
- pushes from this environment are working

Developer tooling that was verified/installed in WSL during this session:

- `node`
- `npm`
- `pnpm`
- `git`
- `docker`
- `docker compose`
- `psql`
- `pg_isready`
- `tmux`
- `tsc`
- `eslint`
- `prettier`
- `nodemon`
- `corepack`
- `gh`

Recommended environment improvement if development continues heavily:

- move the repository into the Linux home directory inside WSL for better performance and tool compatibility

## Important Limitation Right Now

The workbench is much stronger than before, but it is still mostly a discovery/fingerprinting/reporting layer.

What is still missing most:

- deeper parsers for external tool output
- stronger severity/confidence scoring
- CVE candidate enrichment from version fingerprints
- service-specific follow-up modules for `web`, `smb`, and `ad`
- entity extraction for users/domains/hosts/URLs/shares
- better cross-scan correlation and session diffing
- richer scan review screens if `rich` or a full TUI layer is expanded further

## Best Next Step

The strongest next implementation phase is:

1. add structured parsers for `httpx`, `katana`, `testssl.sh`, and richer `nmap` output
2. add CVE candidate mapping from service/product/version
3. add entity storage for usernames, domains, hosts, URLs, shares
4. improve findings with confidence/severity/validation steps
5. add scan-to-scan diffing and correlation

## Useful Commands

Health check:

```bash
python3 zacaim_v2.py health
```

Standalone host scan:

```bash
python3 zacaim_v2.py scan 10.10.10.10 --profile standard
```

Deep host scan:

```bash
python3 zacaim_v2.py scan 10.10.10.10 --profile deep
```

Web scan:

```bash
python3 zacaim_v2.py web scan https://example.com --profile standard
```

Deep web scan:

```bash
python3 zacaim_v2.py web scan https://example.com --profile deep
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

WiFi status:

```bash
python3 zacaim_v2.py wifi status
```

Clone into a new folder:

```bash
git clone https://github.com/rotem-zacaim/Zacaim-WiFi-Tool.git
cd Zacaim-WiFi-Tool
```

## Guidance For The Next Session

If continuing development, start by:

1. opening `zacaim_v2.py`
2. treating it as the main codebase
3. ignoring `zacaim_wifi_tool.py` unless legacy behavior specifically needs to be copied
4. deciding whether to keep working on `/mnt/c/...` or move the repo into WSL home
5. implementing Phase 2:
   `parser enrichment + CVE enrichment + entity extraction + stronger finding scoring`
