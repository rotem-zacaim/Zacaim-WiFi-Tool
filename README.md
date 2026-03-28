# ZACAIM

`ZACAIM` is a terminal-first operator workbench for authorized host discovery, web reconnaissance, evidence capture, and engagement reporting.

The active product path is the modular `ZACAIM V2` package under [`zacaim/`](zacaim/). The older WiFi-oriented material is archived under [`legacy/`](legacy/).

This repository is designed for structured recon and reporting workflows. It is not positioned as exploit automation.

## Authorized Use Only

Use this repository only on systems, applications, networks, and wireless environments you own or are explicitly authorized to assess.

Recommended use cases:

- internal security testing
- customer engagements with written approval
- labs and training environments
- scoped infrastructure validation

## What ZACAIM Does

ZACAIM combines a terminal UI, profile-driven scan pipelines, and reporting artifacts in one workflow.

Core capabilities:

- tool readiness and local environment validation
- interactive cyber dashboard with guided actions
- standalone host reconnaissance
- standalone web reconnaissance
- engagement creation and target registry management
- note and evidence capture
- JSON and Markdown report generation
- live progress checklists with elapsed time and estimated remaining time

## Current Product Layout

- [`zacaim/`](zacaim/): active application package
- [`zacaim_v2.py`](zacaim_v2.py): compatibility wrapper
- [`pyproject.toml`](pyproject.toml): packaging and entrypoint definition
- [`tests/`](tests/): unit and smoke tests
- [`SESSION_HANDOFF.md`](SESSION_HANDOFF.md): implementation direction and handoff notes
- [`legacy/`](legacy/): archived historical material

Important modules:

- [`zacaim/app.py`](zacaim/app.py): CLI entrypoints and interactive flows
- [`zacaim/scanners.py`](zacaim/scanners.py): host and web pipelines
- [`zacaim/ui.py`](zacaim/ui.py): cyber dashboard, boot sequence, and live progress UI
- [`zacaim/reports.py`](zacaim/reports.py): Markdown and JSON report generation
- [`zacaim/engagements.py`](zacaim/engagements.py): engagements, targets, notes, and evidence
- [`zacaim/health.py`](zacaim/health.py): tool readiness and supported installer flow

## Installation

Requirements:

- Python `3.11+`
- Linux environment recommended for the external tooling workflow
- optional system tools depending on the selected profile

Run directly:

```bash
python3 zacaim_v2.py
```

Run as a module:

```bash
python3 -m zacaim
```

Install editable package:

```bash
python3 -m pip install -e .
```

Install with Rich UI support:

```bash
python3 -m pip install -e ".[rich]"
```

Install developer extras:

```bash
python3 -m pip install -e ".[dev,rich]"
```

After installation, the console script is available:

```bash
zacaim health
```

## Quick Start

Launch the interactive console:

```bash
python3 zacaim_v2.py
```

Useful direct commands:

```bash
python3 zacaim_v2.py health
python3 zacaim_v2.py health --install-missing
python3 zacaim_v2.py scan 10.10.10.10 --profile standard
python3 zacaim_v2.py web scan https://example.com --profile standard
python3 zacaim_v2.py engagement init "Customer Internal" --description "Quarterly recon" --scope "Authorized internal scope"
python3 zacaim_v2.py engagement add-target customer_internal 10.10.10.10 --name edge-fw --tags perimeter vpn
python3 zacaim_v2.py engagement scan customer_internal --all --profile standard
python3 zacaim_v2.py note add customer_internal edge-fw "Observed admin portal on 8443" --category finding --tags web admin
python3 zacaim_v2.py evidence add customer_internal edge-fw --text "Screenshot placeholder" --description "Login page summary"
python3 zacaim_v2.py wifi status
```

## Interactive Console

The interactive UI includes:

- cyber-style boot sequence
- compact dashboard with quick actions
- `Tool Readiness` screen
- `Web Recon` and `Host Recon` workflows
- engagement and target management
- notes and evidence actions

When you run a recon flow in a TTY, ZACAIM shows:

- current module
- elapsed time
- estimated remaining time
- checklist of completed, running, skipped, and failed stages

## Tool Readiness

`Tool Readiness` checks available dependencies and can install supported missing packages on apt-based systems.

Supported auto-install examples:

- `nmap`
- `curl`
- `openssl`
- `whatweb`
- `ffuf`
- `nikto`
- `sslscan`
- `ldapsearch`
- `snmpwalk`
- `ike-scan`
- `wafw00f`
- `testssl.sh`
- `dig`
- `host`
- `ssh-keyscan`
- `iw`
- `nmcli`

Manual-install examples:

- `httpx`
- `katana`
- `dnsx`
- `naabu`
- `subfinder`
- `gau`
- `enum4linux-ng`
- `rdpscan`

Missing optional tools do not stop the scan. The relevant stages are marked as skipped and recorded in the session artifacts and reports.

## Host Recon

Host recon is available through:

```bash
python3 zacaim_v2.py scan <target> --profile <profile>
```

Profiles:

- `quick`
- `standard`
- `deep`

Typical host pipeline coverage:

- `nmap`
- reverse DNS with `dig` and `host`
- `ssh-keyscan`
- `naabu`
- `dnsx`
- `sslscan`
- `enum4linux-ng`
- `ldapsearch`
- `snmpwalk`
- `rdpscan`
- `ike-scan`
- embedded web enrichment on discovered HTTP/S services

Host output focuses on:

- open services and banners
- service grouping
- DNS and PTR hints
- TLS highlights
- SMB and LDAP metadata
- RDP and VPN responder observations
- linked web endpoints discovered on the target

## Web Recon

Web recon is available through:

```bash
python3 zacaim_v2.py web scan <url> --profile <profile>
```

Profiles:

- `safe`
- `standard`
- `deep`

Typical web pipeline coverage:

- DNS resolution
- reverse DNS checks
- `dnsx`
- `naabu`
- `curl` HTTP probes
- response parsing
- cookie and redirect analysis
- favicon hashing
- TLS probing
- `whatweb`
- `httpx`
- `ffuf`
- `nikto`
- `robots.txt` parsing
- `sitemap.xml` parsing
- `security.txt` parsing
- `gau`
- `subfinder` in deep profile
- `wafw00f`
- route clustering
- `katana`
- `testssl.sh` in deep profile

Web output focuses on:

- reachable endpoints and titles
- technologies and server headers
- headers, cookies, redirects, and body metrics
- DNS, certificate, and port hints
- forms, scripts, page links, and HTML comments
- exposed emails and contacts
- external domains referenced by the page
- route highlights such as auth, admin, API, GraphQL, Swagger, and OpenAPI paths
- parsed `robots.txt`, `sitemap.xml`, and `security.txt`
- historical URLs and passive related hosts when tooling is available

## Profiles At A Glance

### Host Profiles

`quick`

- lighter service fingerprinting
- no heavy enrichment modules
- fastest option when you only need an initial picture

`standard`

- balanced default profile
- adds `naabu`, `dnsx`, `sslscan`, `enum4linux-ng`, `ldapsearch`, `rdpscan`
- includes embedded web enrichment for discovered HTTP/S services

`deep`

- broadest host workflow
- adds `snmpwalk`, `ike-scan`, deep TLS and deeper web follow-up
- best for slower, more complete collection when scope and time allow it

### Web Profiles

`safe`

- lower-impact profile
- no content discovery or deep crawling
- good baseline for a first pass

`standard`

- balanced default profile
- includes `dnsx`, `naabu`, `ffuf`, `nikto`, `gau`, `wafw00f`, `katana`

`deep`

- fullest web pipeline
- adds `subfinder`, deep `katana`, and `testssl.sh`

## Reports And Artifacts

Each run creates a session directory and stores both machine-readable and human-readable output.

Typical session layout:

- `artifacts/`: stdout and stderr for external tools
- `raw/`: source files such as `nmap.xml` and `nmap.txt`
- `reports/summary.json`
- `reports/findings.json`
- `reports/report.md`

Report outputs include:

- scan summary
- structured services and endpoints
- host and web observations
- generated findings and follow-up ideas
- command execution results

## Data Storage

Application data is stored under `.zacaim_v2/` in the current working directory when writable.

If the current directory is not writable, ZACAIM falls back to another writable location. The application now validates writeability before selecting the storage path.

Typical storage layout:

- `.zacaim_v2/sessions/`
- `.zacaim_v2/engagements/`
- `.zacaim_v2/config.json`

## Engagement Workflow

ZACAIM supports lightweight engagement management for repeated work.

Typical flow:

1. Create an engagement.
2. Register one or more targets.
3. Run standalone or engagement-linked scans.
4. Add notes and evidence.
5. Review Markdown and JSON reports.

## Testing

Run the current unit and smoke suite:

```bash
python3 -m unittest discover -s tests -v
```

You can also validate syntax quickly:

```bash
python3 -m py_compile zacaim/*.py tests/*.py zacaim_v2.py
```

## Project Direction

Current priorities in the active code path:

- modular CLI architecture
- richer host and web recon collection
- cleaner operator-facing terminal UX
- more structured findings and reports
- safer workflow defaults and dependency visibility

## Legacy Material

The historical WiFi-oriented script is archived here:

- [`legacy/zacaim_wifi_tool.py`](legacy/zacaim_wifi_tool.py)

The top-level compatibility stub remains here:

- [`zacaim_wifi_tool.py`](zacaim_wifi_tool.py)

It is intentionally not part of the active product path.
