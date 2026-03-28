"""Application entrypoints."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .constants import APP_NAME, HOST_PROFILES, WEB_PROFILES
from .engagements import EngagementManager
from .filesystem import ensure_app_dirs
from .health import HealthChecker, WifiInspector
from .reports import ReportBuilder
from .scanners import TargetScanner, WebScanner
from .ui import ConsoleUI, LiveStatus, clear_screen
from .validators import normalize_url
from .workspace import WorkspaceManager


def run_health_check() -> dict[str, object]:
    payload = HealthChecker.run()
    ConsoleUI.health_view(payload)
    return payload


def run_standalone_scan(target: str, profile: str) -> dict[str, str]:
    ensure_app_dirs()
    session_dir = WorkspaceManager().create_session(target, profile)
    scanner = TargetScanner(session_dir)
    summary = scanner.scan(target, profile)
    return {"session_dir": str(session_dir), **ReportBuilder.build(summary, session_dir)}


def run_web_scan(url: str, profile: str = "standard") -> dict[str, str]:
    ensure_app_dirs()
    normalized = normalize_url(url)
    session_dir = WorkspaceManager().create_session(normalized["host"], f"web_{profile}")
    scanner = WebScanner(session_dir)
    summary = scanner.scan(url, profile=profile)
    return {"session_dir": str(session_dir), **ReportBuilder.build(summary, session_dir)}


def run_engagement_scan(
    engagement_id: str,
    profile: str,
    target_ref: str = "",
    all_targets: bool = False,
) -> list[dict[str, str]]:
    manager = EngagementManager()
    metadata = manager.load_metadata(engagement_id)
    targets = manager.load_targets(engagement_id)
    if target_ref:
        targets = [manager.resolve_target(engagement_id, target_ref)]
    elif not all_targets and targets:
        targets = [targets[0]]

    if not targets:
        raise ValueError("No targets registered for this engagement.")

    engagement_dir = manager.get_engagement_dir(engagement_id)
    outputs: list[dict[str, str]] = []
    for target in targets:
        session_dir = WorkspaceManager().create_session(str(target["address"]), profile, sessions_root=engagement_dir / "sessions")
        scanner = TargetScanner(session_dir)
        summary = scanner.scan(str(target["address"]), profile)
        summary.engagement_id = str(metadata["id"])
        summary.target_label = str(target["name"])
        reports = ReportBuilder.build(summary, session_dir)
        manager.update_target_after_scan(engagement_id, str(target["target_id"]), summary, reports)
        outputs.append({"target_id": str(target["target_id"]), "target": str(target["address"]), "session_dir": str(session_dir), **reports})
    return outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=APP_NAME)
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("health", help="Run dependency and environment checks.")

    scan_parser = subparsers.add_parser("scan", help="Run standalone target enumeration.")
    scan_parser.add_argument("target", help="Target IP address or hostname.")
    scan_parser.add_argument("--profile", choices=sorted(HOST_PROFILES), default="standard")

    engagement_parser = subparsers.add_parser("engagement", help="Manage engagements and target registries.")
    engagement_subparsers = engagement_parser.add_subparsers(dest="engagement_command", required=True)

    engagement_init = engagement_subparsers.add_parser("init", help="Create a new engagement workspace.")
    engagement_init.add_argument("name", help="Display name for the engagement.")
    engagement_init.add_argument("--description", default="", help="Short description.")
    engagement_init.add_argument("--scope", default="", help="Authorized scope note.")

    engagement_subparsers.add_parser("list", help="List all engagements.")

    engagement_add_target = engagement_subparsers.add_parser("add-target", help="Register a target.")
    engagement_add_target.add_argument("engagement", help="Engagement id.")
    engagement_add_target.add_argument("target", help="Target IP address or hostname.")
    engagement_add_target.add_argument("--name", default="", help="Friendly target label.")
    engagement_add_target.add_argument("--tags", nargs="*", default=[], help="Optional tags.")

    engagement_list_targets = engagement_subparsers.add_parser("list-targets", help="List registered targets.")
    engagement_list_targets.add_argument("engagement", help="Engagement id.")

    engagement_scan = engagement_subparsers.add_parser("scan", help="Scan one or more registered targets.")
    engagement_scan.add_argument("engagement", help="Engagement id.")
    engagement_scan.add_argument("--target", default="", help="Target id, name, or address.")
    engagement_scan.add_argument("--all", action="store_true", help="Scan all registered targets.")
    engagement_scan.add_argument("--profile", choices=sorted(HOST_PROFILES), default="standard")

    note_parser = subparsers.add_parser("note", help="Manage target notes.")
    note_subparsers = note_parser.add_subparsers(dest="note_command", required=True)
    note_add = note_subparsers.add_parser("add", help="Add a note to a target.")
    note_add.add_argument("engagement", help="Engagement id.")
    note_add.add_argument("target", help="Target id, name, or address.")
    note_add.add_argument("text", help="Note text.")
    note_add.add_argument("--category", default="note", help="Note category.")
    note_add.add_argument("--tags", nargs="*", default=[], help="Optional tags.")

    evidence_parser = subparsers.add_parser("evidence", help="Manage target evidence.")
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_subparsers.add_parser("add", help="Add evidence to a target.")
    evidence_add.add_argument("engagement", help="Engagement id.")
    evidence_add.add_argument("target", help="Target id, name, or address.")
    evidence_group = evidence_add.add_mutually_exclusive_group(required=True)
    evidence_group.add_argument("--text", default="", help="Store evidence as text.")
    evidence_group.add_argument("--file", default="", help="Copy a file into the evidence store.")
    evidence_add.add_argument("--description", default="", help="Optional description.")

    web_parser = subparsers.add_parser("web", help="Authorized web automation and fingerprinting.")
    web_subparsers = web_parser.add_subparsers(dest="web_command", required=True)
    web_scan = web_subparsers.add_parser("scan", help="Run an authorized web discovery automation profile.")
    web_scan.add_argument("url", help="Target http/https URL.")
    web_scan.add_argument("--profile", choices=sorted(WEB_PROFILES), default="standard")

    wifi_parser = subparsers.add_parser("wifi", help="Inspect local wireless workspace readiness.")
    wifi_subparsers = wifi_parser.add_subparsers(dest="wifi_command", required=True)
    wifi_subparsers.add_parser("status", help="Show local wireless adapter and tool status.")

    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    return parser.parse_args(list(argv) if argv is not None else None)


def interactive_main() -> None:
    ensure_app_dirs()
    manager = EngagementManager()
    ConsoleUI.boot_sequence()

    while True:
        clear_screen()
        ConsoleUI.banner()
        ConsoleUI.dashboard(manager)
        choice = ConsoleUI.prompt_main()

        try:
            if choice == "1":
                clear_screen()
                ConsoleUI.banner()
                with LiveStatus("running environment checks", "health check complete"):
                    payload = HealthChecker.run()
                ConsoleUI.health_view(payload)
            elif choice == "2":
                clear_screen()
                ConsoleUI.banner()
                url = input("Target URL: ").strip()
                profile = input("Web profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running web automation pipeline", "web automation complete"):
                    output = run_web_scan(url, profile=profile)
                ConsoleUI.print_scan_report(output)
            elif choice == "3":
                clear_screen()
                ConsoleUI.banner()
                target = input("Target IP/hostname: ").strip()
                profile = input("Profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running host scan", "host scan complete"):
                    output = run_standalone_scan(target, profile)
                ConsoleUI.print_scan_report(output)
            elif choice == "4":
                clear_screen()
                ConsoleUI.banner()
                name = input("Engagement name: ").strip()
                description = input("Description: ").strip()
                scope = input("Scope note: ").strip()
                ConsoleUI.print_record("Engagement Created", manager.create(name, description, scope))
            elif choice == "5":
                clear_screen()
                ConsoleUI.banner()
                ConsoleUI.print_engagements(manager.list_engagements())
            elif choice == "6":
                clear_screen()
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target IP/hostname: ").strip()
                name = input("Friendly name (optional): ").strip()
                tags = input("Tags (space separated): ").strip().split()
                ConsoleUI.print_record("Target Added", manager.add_target(engagement, target, name, tags))
            elif choice == "7":
                clear_screen()
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                ConsoleUI.print_targets(manager.load_targets(engagement))
            elif choice == "8":
                clear_screen()
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Specific target id/name/address (blank for all): ").strip()
                profile = input("Profile [standard]: ").strip().lower() or "standard"
                with LiveStatus("running engagement scans", "engagement scans complete"):
                    outputs = run_engagement_scan(engagement, profile, target_ref=target, all_targets=not target)
                ConsoleUI.print_scan_reports(outputs)
            elif choice == "9":
                clear_screen()
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target id/name/address: ").strip()
                category = input("Category [note]: ").strip() or "note"
                tags = input("Tags (space separated): ").strip().split()
                text = input("Note text: ").strip()
                ConsoleUI.print_record("Note Added", manager.add_note(engagement, target, text, category, tags))
            elif choice == "10":
                clear_screen()
                ConsoleUI.banner()
                engagement = input("Engagement id: ").strip()
                target = input("Target id/name/address: ").strip()
                description = input("Description: ").strip()
                text = input("Evidence text (leave blank to use file path): ").strip()
                if text:
                    result = manager.add_evidence(engagement, target, description=description, text=text)
                else:
                    file_path = input("Evidence file path: ").strip()
                    result = manager.add_evidence(engagement, target, description=description, file_path=file_path)
                ConsoleUI.print_record("Evidence Added", result)
            elif choice == "11":
                clear_screen()
                ConsoleUI.banner()
                with LiveStatus("collecting wireless adapter status", "wifi status ready"):
                    payload = WifiInspector.run()
                ConsoleUI.print_wifi_status(payload)
            elif choice == "12":
                print("Good hunting. Stay within scope.")
                return
            else:
                print("Invalid option.")
        except Exception as exc:
            print(f"[!] {exc}")

        input("\nPress Enter to continue...")


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None and len(sys.argv) == 1:
        interactive_main()
        return 0

    args = parse_args(argv)
    manager = EngagementManager()

    if args.command == "health":
        run_health_check()
        return 0

    if args.command == "scan":
        output = run_standalone_scan(args.target, args.profile)
        if sys.stdout.isatty():
            ConsoleUI.print_scan_report(output)
        else:
            print(json.dumps(output, indent=2))
        return 0

    if args.command == "web" and args.web_command == "scan":
        output = run_web_scan(args.url, profile=args.profile)
        if sys.stdout.isatty():
            ConsoleUI.print_scan_report(output)
        else:
            print(json.dumps(output, indent=2))
        return 0

    if args.command == "wifi" and args.wifi_command == "status":
        payload = WifiInspector.run()
        if sys.stdout.isatty():
            ConsoleUI.print_wifi_status(payload)
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if args.command == "engagement":
        if args.engagement_command == "init":
            payload = manager.create(args.name, args.description, args.scope)
        elif args.engagement_command == "list":
            payload = manager.list_engagements()
        elif args.engagement_command == "add-target":
            payload = manager.add_target(args.engagement, args.target, args.name, args.tags)
        elif args.engagement_command == "list-targets":
            payload = manager.load_targets(args.engagement)
        else:
            payload = run_engagement_scan(args.engagement, args.profile, args.target, args.all)

        if sys.stdout.isatty():
            if isinstance(payload, list):
                ConsoleUI.print_scan_reports(payload)
            elif args.engagement_command == "list":
                ConsoleUI.print_engagements(payload)
            elif args.engagement_command == "list-targets":
                ConsoleUI.print_targets(payload)
            else:
                ConsoleUI.print_record("Engagement Result", payload)
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if args.command == "note" and args.note_command == "add":
        payload = manager.add_note(args.engagement, args.target, args.text, args.category, args.tags)
        if sys.stdout.isatty():
            ConsoleUI.print_record("Note Added", payload)
        else:
            print(json.dumps(payload, indent=2))
        return 0

    if args.command == "evidence" and args.evidence_command == "add":
        payload = manager.add_evidence(args.engagement, args.target, description=args.description, text=args.text, file_path=args.file)
        if sys.stdout.isatty():
            ConsoleUI.print_record("Evidence Added", payload)
        else:
            print(json.dumps(payload, indent=2))
        return 0

    raise AssertionError("Unhandled CLI state.")
