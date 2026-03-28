# ZACAIM

`ZACAIM` is a terminal-first operator workstation for authorized host discovery, web mapping, evidence collection, and engagement reporting.

The active product path is now packaged and modular:

- [`zacaim/`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim): active application package
- [`zacaim_v2.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_v2.py): compatibility wrapper for the packaged CLI
- [`legacy/`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/legacy): archived historical material

The project direction remains workflow orchestration and structured analysis, not exploit automation.

## Scope

Use this repository only on systems, applications, networks, and wireless environments you own or are explicitly authorized to assess.

Good fits:

- local labs
- CTF / training environments
- internal security testing
- approved customer engagements

## Repository Layout

- [`zacaim/app.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim/app.py): CLI entrypoint and interactive flows
- [`zacaim/scanners.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim/scanners.py): host and web pipelines
- [`zacaim/engagements.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim/engagements.py): engagement, note, and evidence storage
- [`zacaim/reports.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim/reports.py): markdown and JSON reporting
- [`tests/`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/tests): smoke and logic tests
- [`SESSION_HANDOFF.md`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/SESSION_HANDOFF.md): current direction and implementation notes
- [`pyproject.toml`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/pyproject.toml): packaging and test metadata

## ZACAIM V2

`ZACAIM V2` is the active implementation and supports:

- environment and tool health checks
- standalone host scanning with profile-driven multi-tool enrichment
- web automation profiles for authorized HTTP/S targets
- engagement and target registry management
- notes and evidence capture
- structured findings and markdown/JSON reporting
- local WiFi workspace readiness checks

### Host Profiles

- `quick`
- `standard`
- `deep`

### Web Profiles

- `safe`
- `standard`
- `deep`

### Pipeline Notes

Depending on the installed tooling and selected profile, the application can use:

- `nmap`
- `curl`
- `openssl`
- `whatweb`
- `httpx`
- `wafw00f`
- `katana`
- `testssl.sh`
- `dig`
- `host`
- `ssh-keyscan`

Missing optional tools do not stop execution. The related steps are skipped and recorded in the artifacts and reports.

## Installation

### Run Directly

```bash
python3 zacaim_v2.py
```

### Run As A Module

```bash
python3 -m zacaim
```

### Install In Editable Mode

```bash
python3 -m pip install -e .
```

After that you can use:

```bash
zacaim health
```

### Install Optional Developer Extras

```bash
python3 -m pip install -e ".[dev,rich]"
```

## Common Commands

```bash
python3 zacaim_v2.py health
python3 zacaim_v2.py scan 10.10.10.10 --profile standard
python3 zacaim_v2.py web scan https://example.com --profile deep
python3 zacaim_v2.py engagement init "Customer Internal"
python3 zacaim_v2.py engagement add-target customer_internal 10.10.10.10 --name edge-fw
python3 zacaim_v2.py engagement scan customer_internal --all --profile standard
```

## Reports And Artifacts

Application data is stored under `.zacaim_v2/` in the current working directory when writable, with fallback to other writable OS locations if needed.

Typical session layout:

- `artifacts/`: stdout and stderr from external tools
- `raw/`: source artifacts such as Nmap XML/text
- `reports/summary.json`
- `reports/findings.json`
- `reports/report.md`

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Legacy Material

The historical WiFi-oriented script is archived under [`legacy/zacaim_wifi_tool.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/legacy/zacaim_wifi_tool.py).

The top-level [`zacaim_wifi_tool.py`](/mnt/c/Users/rotem/Documents/codex/Zacaim-WiFi-Tool/zacaim_wifi_tool.py) now only points to the archived location and is intentionally not part of the active product path.
