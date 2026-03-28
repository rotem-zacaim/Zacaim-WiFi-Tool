# Session Handoff

## Project Summary

`ZACAIM V2` is the active codebase for this repository.

The project is a terminal-first operator workbench for:

- authorized host discovery
- authorized web discovery and fingerprinting
- engagement tracking
- notes and evidence storage
- report generation

The current direction is intentionally centered on discovery, enrichment, documentation, and reporting.
It is not positioned as exploit automation.

## Main Files

Primary implementation:

- `zacaim/`
- `zacaim_v2.py`

Archived legacy material:

- `legacy/zacaim_wifi_tool.py`
- `zacaim_wifi_tool.py` now exists only as a deprecation stub

All current product work should start in the `zacaim/` package.

## Current Architecture

The previous single-file implementation was refactored into modules:

- `zacaim/app.py`: CLI entrypoint and interactive flow
- `zacaim/ui.py`: console rendering and live status helpers
- `zacaim/scanners.py`: host and web orchestration
- `zacaim/engagements.py`: engagement, note, and evidence storage
- `zacaim/reports.py`: markdown and JSON report generation
- `zacaim/health.py`: environment and WiFi readiness checks
- `zacaim/filesystem.py`: writable app-dir resolution and storage helpers
- `zacaim/models.py`: dataclasses shared across the product

## Current Product Scope

The CLI currently supports:

- `health`
- standalone host scanning with profiles
- URL-based web scanning with profiles
- engagement creation
- target registration inside engagements
- listing engagements and targets
- engagement-scoped scanning
- note storage
- evidence storage
- local WiFi readiness/status checks

## Hardening Work Completed

This session addressed several foundational issues:

- writable app data selection now verifies actual file writes before choosing a storage location
- the writable current working directory is preferred before falling back to home-directory locations
- the command runner now streams stdout/stderr directly into artifact files instead of buffering large outputs in memory
- nested CLI subcommands now use `argparse` required subparsers instead of silently falling into interactive mode
- profiles are now configuration-driven and directly control which enrichment steps run

## CLI UX State

The CLI still keeps a terminal-first workflow with:

- optional `rich` rendering
- static dashboard and menu flow
- live status feedback during long-running tasks
- compatibility with `python3 zacaim_v2.py`, `python3 -m zacaim`, and installed `zacaim`

The current UX preference is still a calmer, mostly static interface instead of constant motion.

## Host Scan Status

Current host automation can combine:

- `nmap`
- reverse DNS enrichment via `dig`
- reverse DNS enrichment via `host`
- `ssh-keyscan`
- HTTP/S endpoint discovery from identified services
- web-side enrichment on discovered web endpoints

Current host profiles:

- `quick`
- `standard`
- `deep`

## Web Scan Status

Current web profiles:

- `safe`
- `standard`
- `deep`

Depending on installed tools and profile, the pipeline can use:

- `curl`
- `openssl`
- `whatweb`
- `httpx`
- `wafw00f`
- `katana`
- `testssl.sh`

Known high-signal paths checked:

- `/robots.txt`
- `/sitemap.xml`
- `/.well-known/security.txt`
- `/security.txt`

## Findings And Reporting

Each scan session writes:

- `summary.json`
- `findings.json`
- `report.md`

Supporting stdout/stderr is stored under per-session artifact folders.

## Storage Layout

Application data is stored under `.zacaim_v2/` in the active writable location chosen by the app.

Important locations:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/`
- `.zacaim_v2/engagements/<engagement>/targets/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/notes/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/evidence/`
- `.zacaim_v2/engagements/<engagement>/targets/<target>/reports/`
- `.zacaim_v2/engagements/<engagement>/sessions/`

## Quality And DX

The repository now includes:

- `pyproject.toml` for packaging and install metadata
- an installable console entrypoint: `zacaim`
- `tests/` with basic coverage for validation, CLI parsing, path resolution, and reporting

## Recommended Next Steps

Strong next implementation candidates:

1. deepen structured parsing for `httpx`, `katana`, `testssl.sh`, and richer Nmap output
2. add confidence and severity scoring beyond heuristic `info` findings
3. add CVE candidate enrichment where product and version data are strong enough
4. add entity extraction and cross-scan diffing
5. expand service-specific enrichment for `web`, `smb`, and `ad`
