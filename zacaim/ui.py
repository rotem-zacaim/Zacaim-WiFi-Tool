"""Console and interactive UI helpers."""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from datetime import datetime
from typing import Any

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    Console = Panel = Rule = Table = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

from .constants import APP_TAGLINE, APP_VERSION
from .health import HealthChecker


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


LIVE_FRAMES = ["[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]"]
AWAITING_SELECTION_MESSAGES = [
    "awaiting operator selection",
    "control surface standing by",
    "ready for next command",
]
BOOT_FEED_STEPS = [
    ("workspace", "mounting operator workspace"),
    ("registry", "loading engagement registry"),
    ("host bus", "binding host pipeline"),
    ("web bus", "arming web discovery engine"),
    ("reports", "syncing report renderer"),
]
BOOT_TITLE_LINES = [
    "██████╗  ██████╗ ████████╗███████╗███╗   ███╗",
    "██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝████╗ ████║",
    "██████╔╝██║   ██║   ██║   █████╗  ██╔████╔██║",
    "██╔══██╗██║   ██║   ██║   ██╔══╝  ██║╚██╔╝██║",
    "██║  ██║╚██████╔╝   ██║   ███████╗██║ ╚═╝ ██║",
    "╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝╚═╝     ╚═╝",
]
BOOT_SUBTITLE = "cyber tools"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


class LiveStatus:
    def __init__(self, message: str, success_message: str = ""):
        self.message = message
        self.success_message = success_message or message
        self.enabled = sys.stdout.isatty()
        self.rich_enabled = RICH_AVAILABLE and self.enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at = time.time()
        self._rich_console = Console() if self.rich_enabled else None
        self._rich_status: Any = None

    def _render(self) -> None:
        frame_index = 0
        while not self._stop.is_set():
            elapsed = time.time() - self._started_at
            frame = LIVE_FRAMES[frame_index % len(LIVE_FRAMES)]
            sys.stdout.write(
                f"\r{Colors.CYAN}{frame}{Colors.RESET} {self.message} {Colors.YELLOW}{elapsed:>4.1f}s{Colors.RESET}"
            )
            sys.stdout.flush()
            frame_index += 1
            time.sleep(0.12)
        sys.stdout.write("\r" + (" " * 96) + "\r")
        sys.stdout.flush()

    def __enter__(self) -> "LiveStatus":
        if self.rich_enabled and self._rich_console is not None:
            self._rich_status = self._rich_console.status(f"[bold cyan]{self.message}[/bold cyan]", spinner="dots")
            self._rich_status.__enter__()
        elif self.enabled:
            self._thread = threading.Thread(target=self._render, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, _: Any) -> None:
        if self._rich_status is not None:
            self._rich_status.__exit__(exc_type, exc, _)
        elif self.enabled:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=0.5)
        if self.rich_enabled and self._rich_console is not None:
            label = "[green]ready[/green]" if exc is None else "[red]error[/red]"
            self._rich_console.print(f"{label} {self.success_message}")
        else:
            color = Colors.GREEN if exc is None else Colors.RED
            label = "ready" if exc is None else "error"
            print(f"{color}[{label}]{Colors.RESET} {self.success_message}")


class IdlePromptStatus:
    def __init__(self, prompt_text: str):
        self.prompt_text = prompt_text
        self.enabled = sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _render_line(self, frame_index: int) -> str:
        frame = LIVE_FRAMES[frame_index % len(LIVE_FRAMES)]
        message = AWAITING_SELECTION_MESSAGES[frame_index % len(AWAITING_SELECTION_MESSAGES)]
        return f"{Colors.BLUE}{frame}{Colors.RESET} {Colors.CYAN}{message}{Colors.RESET}"

    def _render(self) -> None:
        frame_index = 0
        while not self._stop.is_set():
            line = self._render_line(frame_index)
            sys.stdout.write("\033[s")
            sys.stdout.write("\033[1A")
            sys.stdout.write("\r\033[2K")
            sys.stdout.write(line)
            sys.stdout.write("\033[u")
            sys.stdout.flush()
            frame_index += 1
            time.sleep(0.3)

        sys.stdout.write("\033[s")
        sys.stdout.write("\033[1A")
        sys.stdout.write("\r\033[2K")
        sys.stdout.write(f"{Colors.GREEN}[ready]{Colors.RESET} {Colors.CYAN}{self.prompt_text}{Colors.RESET}")
        sys.stdout.write("\033[u")
        sys.stdout.flush()

    def run_input(self) -> str:
        if not self.enabled:
            print(f"{Colors.GREEN}[ready]{Colors.RESET} {self.prompt_text}")
            return input(f"\n{Colors.GREEN}zacaim{Colors.RESET}{Colors.CYAN}::ops{Colors.RESET}> ").strip()

        print(f"{Colors.GREEN}[ready]{Colors.RESET} {self.prompt_text}")
        self._thread = threading.Thread(target=self._render, daemon=True)
        self._thread.start()
        try:
            return input(f"\n{Colors.GREEN}zacaim{Colors.RESET}{Colors.CYAN}::ops{Colors.RESET}> ").strip()
        finally:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=0.4)


class ConsoleUI:
    _rich_console = Console() if RICH_AVAILABLE else None
    _boot_seen = False

    @staticmethod
    def use_rich() -> bool:
        return RICH_AVAILABLE and ConsoleUI._rich_console is not None and sys.stdout.isatty()

    @staticmethod
    def supports_animation() -> bool:
        return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"

    @staticmethod
    def _width() -> int:
        return max(72, shutil.get_terminal_size((120, 40)).columns)

    @staticmethod
    def _rule(char: str = "-") -> str:
        return char * min(ConsoleUI._width(), 104)

    @staticmethod
    def _clear_ansi() -> None:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    @staticmethod
    def _center_line(text: str) -> str:
        width = ConsoleUI._width()
        return text.center(width)

    @staticmethod
    def _boot_title_rows(revealed_rows: int) -> list[str]:
        visible_from = max(0, len(BOOT_TITLE_LINES) - revealed_rows)
        rows: list[str] = []
        for index, line in enumerate(BOOT_TITLE_LINES):
            if index < visible_from:
                rows.append("")
                continue
            color = Colors.GREEN if index < len(BOOT_TITLE_LINES) - 1 else Colors.CYAN
            rows.append(f"{color}{ConsoleUI._center_line(line)}{Colors.RESET}")
        return rows

    @staticmethod
    def _boot_subtitle(progress_chars: int) -> str:
        lit = BOOT_SUBTITLE[:progress_chars]
        dimmed = BOOT_SUBTITLE[progress_chars:]
        return (
            f"{Colors.CYAN}{ConsoleUI._center_line(lit)}{Colors.RESET}"
            if progress_chars >= len(BOOT_SUBTITLE)
            else f"{Colors.CYAN}{ConsoleUI._center_line(lit)}{Colors.RESET}".replace(
                ConsoleUI._center_line(lit),
                ConsoleUI._center_line(f"{lit}{Colors.BLUE}{dimmed}{Colors.RESET}")
            )
        )

    @staticmethod
    def _boot_feed_lines(frame_index: int) -> list[str]:
        lines: list[str] = []
        active_step = min(len(BOOT_FEED_STEPS) - 1, frame_index // 5)
        for index, (label, message) in enumerate(BOOT_FEED_STEPS):
            if index < active_step:
                lines.append(
                    f"{Colors.GREEN}[ online ]{Colors.RESET} "
                    f"{Colors.CYAN}{label:<10}{Colors.RESET} {message}"
                )
            elif index == active_step:
                spinner = LIVE_FRAMES[frame_index % len(LIVE_FRAMES)]
                lines.append(
                    f"{Colors.YELLOW}{spinner}{Colors.RESET} "
                    f"{Colors.CYAN}{label:<10}{Colors.RESET} {message}"
                )
            else:
                lines.append(
                    f"{Colors.BLUE}[ queued ]{Colors.RESET} "
                    f"{Colors.BLUE}{label:<10}{Colors.RESET} {message}"
                )
        return lines

    @staticmethod
    def _print_boot_frame(frame_index: int, title_offset: int, revealed_rows: int, subtitle_chars: int) -> None:
        ConsoleUI._clear_ansi()
        print(f"{Colors.BLUE}{ConsoleUI._rule('~')}{Colors.RESET}")
        for _ in range(title_offset):
            print()
        for row in ConsoleUI._boot_title_rows(revealed_rows):
            print(row)
        print()
        subtitle_centered = f"{BOOT_SUBTITLE[:subtitle_chars]}{BOOT_SUBTITLE[subtitle_chars:]}"
        lit = BOOT_SUBTITLE[:subtitle_chars]
        dimmed = BOOT_SUBTITLE[subtitle_chars:]
        print(
            f"{ConsoleUI._center_line(f'{Colors.CYAN}{lit}{Colors.BLUE}{dimmed}{Colors.RESET}')}"
        )
        print()
        for line in ConsoleUI._boot_feed_lines(frame_index):
            print(ConsoleUI._center_line(line))
        print()
        pulse = " ".join("■" if index == frame_index % 10 else "·" for index in range(10))
        print(
            f"{ConsoleUI._center_line(f'{Colors.MAGENTA}telemetry pulse {pulse}{Colors.RESET}')}"
        )
        print(f"{Colors.BLUE}{ConsoleUI._rule('~')}{Colors.RESET}")

    @classmethod
    def boot_sequence(cls) -> None:
        if cls._boot_seen:
            return
        cls._boot_seen = True
        if not cls.supports_animation():
            return

        total_frames = 24
        start_offset = 7
        final_offset = 2
        subtitle_total = len(BOOT_SUBTITLE)

        for frame_index in range(total_frames):
            rise_progress = frame_index / max(1, total_frames - 1)
            title_offset = start_offset - int((start_offset - final_offset) * rise_progress)
            revealed_rows = max(1, min(len(BOOT_TITLE_LINES), 1 + frame_index // 3))
            subtitle_chars = min(subtitle_total, max(0, frame_index - 6))
            cls._print_boot_frame(frame_index, title_offset, revealed_rows, subtitle_chars)
            time.sleep(0.12)

        cls._clear_ansi()
        print(f"{Colors.BLUE}{cls._rule('~')}{Colors.RESET}")
        for row in cls._boot_title_rows(len(BOOT_TITLE_LINES)):
            print(row)
        print(f"{Colors.CYAN}{cls._center_line(BOOT_SUBTITLE)}{Colors.RESET}")
        print()
        for label, message in BOOT_FEED_STEPS:
            print(
                cls._center_line(
                    f"{Colors.GREEN}[ online ]{Colors.RESET} {Colors.CYAN}{label:<10}{Colors.RESET} {message}"
                )
            )
        print()
        print(cls._center_line(f"{Colors.GREEN}control surface ready{Colors.RESET}"))
        print(f"{Colors.BLUE}{cls._rule('~')}{Colors.RESET}")
        time.sleep(0.8)
        cls._clear_ansi()

    @staticmethod
    def banner() -> None:
        title = f"ZACAIM // OPERATOR CONSOLE // v{APP_VERSION}"
        if ConsoleUI.use_rich():
            ConsoleUI._rich_console.print(
                Panel(
                    f"[bold cyan]{title}[/bold cyan]\n[yellow]{APP_TAGLINE}[/yellow]\n[green]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/green]",
                    border_style="cyan",
                )
            )
            return
        print(f"{Colors.CYAN}{ConsoleUI._rule('=')}{Colors.RESET}")
        print(f"{Colors.GREEN}{title.center(ConsoleUI._width())}{Colors.RESET}")
        print(f"{Colors.YELLOW}{APP_TAGLINE.center(ConsoleUI._width())}{Colors.RESET}")
        print(f"{Colors.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S').center(ConsoleUI._width())}{Colors.RESET}")
        print(f"{Colors.CYAN}{ConsoleUI._rule('=')}{Colors.RESET}")

    @staticmethod
    def section(title: str) -> None:
        if ConsoleUI.use_rich():
            ConsoleUI._rich_console.print(Rule(f"[bold magenta]{title}[/bold magenta]", style="magenta"))
            return
        print(f"{Colors.MAGENTA}{Colors.BOLD}-- {title.upper()} {ConsoleUI._rule('-')[len(title) + 5:]}{Colors.RESET}")

    @staticmethod
    def print_record(title: str, payload: dict[str, object]) -> None:
        if ConsoleUI.use_rich():
            table = Table(box=None, show_header=False, expand=True)
            table.add_column("key", style="bold cyan", width=18)
            table.add_column("value", style="white", overflow="fold")
            for key, value in payload.items():
                table.add_row(str(key), str(value))
            ConsoleUI._rich_console.print(Panel(table, title=f"[bold]{title}[/bold]", border_style="magenta"))
            return
        ConsoleUI.section(title)
        for key, value in payload.items():
            print(f"- {key}: {value}")

    @staticmethod
    def health_view(payload: dict[str, object]) -> None:
        if ConsoleUI.use_rich():
            env = Table(box=None, expand=True, show_header=False)
            env.add_column("key", style="cyan", width=14)
            env.add_column("value", style="white")
            env.add_row("Python", str(payload["python"]))
            env.add_row("Hostname", str(payload["hostname"]))
            env.add_row("Sessions", str(payload["sessions_dir"]))
            env.add_row("Engagements", str(payload["engagements_dir"]))
            env.add_row("Root", str(payload["root"]))
            tools = Table(title="Tool Readiness", expand=True)
            tools.add_column("Tool", style="bold cyan")
            tools.add_column("State")
            tools.add_column("Location", overflow="fold")
            for tool, location in dict(payload["tools"]).items():
                state = "[green]online[/green]" if location else "[red]missing[/red]"
                tools.add_row(str(tool), state, str(location or "-"))
            ConsoleUI._rich_console.print(Panel(env, title="[bold]Environment[/bold]", border_style="magenta"))
            ConsoleUI._rich_console.print(tools)
            return
        ConsoleUI.section("Environment")
        print(f"{Colors.BLUE}Python:{Colors.RESET} {payload['python']}")
        print(f"{Colors.BLUE}Hostname:{Colors.RESET} {payload['hostname']}")
        print(f"{Colors.BLUE}Sessions:{Colors.RESET} {payload['sessions_dir']}")
        print(f"{Colors.BLUE}Engagements:{Colors.RESET} {payload['engagements_dir']}")
        print(f"{Colors.BLUE}Root:{Colors.RESET} {payload['root']}")
        print(f"{Colors.BLUE}Tools:{Colors.RESET}")
        for tool, location in dict(payload["tools"]).items():
            state = location if location else "missing"
            color = Colors.GREEN if location else Colors.RED
            print(f"  - {tool:<10} {color}{state}{Colors.RESET}")

    @staticmethod
    def dashboard(manager: Any) -> None:
        from .filesystem import CONFIG_FILE, SESSIONS_DIR, read_json

        engagements = manager.list_engagements()
        sessions_count = len(list(SESSIONS_DIR.iterdir())) if SESSIONS_DIR.exists() else 0
        config = read_json(CONFIG_FILE, {})
        available_tools = sum(1 for location in config.get("tools", {}).values() if location)
        total_tools = len(config.get("tools", {})) or len(HealthChecker.REQUIRED_TOOLS) + len(HealthChecker.OPTIONAL_TOOLS)
        body = {
            "engagements": len(engagements),
            "sessions": sessions_count,
            "tools_ready": f"{available_tools}/{total_tools}",
            "mode": "interactive workstation",
        }
        ConsoleUI.print_record("Workspace", body)

    @staticmethod
    def print_engagements(engagements: list[dict[str, object]]) -> None:
        if ConsoleUI.use_rich():
            if not engagements:
                ConsoleUI._rich_console.print(Panel("No engagements registered yet.", border_style="yellow"))
                return
            table = Table(title="Engagements", expand=True)
            table.add_column("ID", style="bold cyan")
            table.add_column("Name", style="white")
            table.add_column("Created", style="green")
            table.add_column("Scope", style="yellow")
            for engagement in engagements:
                table.add_row(str(engagement["id"]), str(engagement["name"]), str(engagement.get("created_at", "n/a")), str(engagement.get("scope", "") or "n/a"))
            ConsoleUI._rich_console.print(table)
            return
        ConsoleUI.section("Engagements")
        if not engagements:
            print("No engagements registered yet.")
            return
        for engagement in engagements:
            print(f"- {engagement['id']} | {engagement['name']} | created={engagement.get('created_at', 'n/a')} | scope={engagement.get('scope', '') or 'n/a'}")

    @staticmethod
    def print_targets(targets: list[dict[str, object]]) -> None:
        if ConsoleUI.use_rich():
            if not targets:
                ConsoleUI._rich_console.print(Panel("No targets registered.", border_style="yellow"))
                return
            table = Table(title="Targets", expand=True)
            table.add_column("Target", style="bold cyan")
            table.add_column("Address", style="white")
            table.add_column("Services", justify="right")
            table.add_column("Findings", justify="right")
            table.add_column("Notes", justify="right")
            table.add_column("Evidence", justify="right")
            for target in targets:
                table.add_row(
                    str(target["target_id"]),
                    str(target["address"]),
                    str(target["service_count"]),
                    str(target["findings_count"]),
                    str(target["note_count"]),
                    str(target["evidence_count"]),
                )
            ConsoleUI._rich_console.print(table)
            return
        ConsoleUI.section("Targets")
        if not targets:
            print("No targets registered.")
            return
        for target in targets:
            print(f"- {target['target_id']} | {target['address']} | services={target['service_count']} | findings={target['findings_count']} | notes={target['note_count']} | evidence={target['evidence_count']}")

    @staticmethod
    def print_wifi_status(payload: dict[str, object]) -> None:
        ConsoleUI.print_record("WiFi Status", {"note": payload["note"]})
        tools = dict(payload["tools"])
        for tool, location in tools.items():
            print(f"- tool {tool}: {location or 'missing'}")
        for interface in list(payload["interfaces"]):
            print(f"- iface {interface.get('name', 'unknown')} | type={interface.get('type', 'n/a')} | channel={interface.get('channel', 'n/a')} | state={interface.get('state', 'n/a')}")

    @staticmethod
    def print_scan_report(output: dict[str, str]) -> None:
        from pathlib import Path
        from .filesystem import read_json

        summary = read_json(Path(output["summary_json"]), {})
        findings = read_json(Path(output["findings_json"]), [])
        if not summary:
            print(output)
            return

        ConsoleUI.print_record(
            "Scan Summary",
            {
                "target": summary.get("target", "n/a"),
                "profile": summary.get("profile", "n/a"),
                "session": summary.get("session_id", "n/a"),
                "output": summary.get("output_dir", "n/a"),
            },
        )
        ConsoleUI.section("Services")
        services = summary.get("open_services", [])
        if services:
            for service in services:
                print(f"- {service.get('port', 'n/a')}/{service.get('protocol', 'tcp')} | {service.get('service', 'unknown')} {service.get('product', '')} {service.get('version', '')}".rstrip())
        else:
            print("- No services were parsed.")

        ConsoleUI.section("Findings")
        if findings:
            for finding in findings:
                print(f"- [{finding.get('severity', 'info').upper()}] {finding.get('title', 'Untitled')}: {finding.get('description', '')}")
        else:
            print("- No structured findings were generated.")

        ConsoleUI.section("Artifacts")
        print(f"- summary: {output['summary_json']}")
        print(f"- findings: {output['findings_json']}")
        print(f"- report: {output['report_md']}")

    @staticmethod
    def print_scan_reports(outputs: list[dict[str, str]]) -> None:
        for index, output in enumerate(outputs, start=1):
            if len(outputs) > 1:
                ConsoleUI.section(f"Result {index}/{len(outputs)}")
            ConsoleUI.print_scan_report(output)

    @staticmethod
    def prompt_main() -> str:
        print("1. Health Check")
        print("2. Web URL Scan")
        print("3. Standalone Host Scan")
        print("4. Create Engagement")
        print("5. List Engagements")
        print("6. Add Target To Engagement")
        print("7. List Engagement Targets")
        print("8. Scan Engagement Target(s)")
        print("9. Add Note")
        print("10. Add Evidence")
        print("11. WiFi Status")
        print("12. Exit")
        return IdlePromptStatus("menu input channel live").run_input()
