#!/usr/bin/env python3
"""Archived legacy WiFi script kept for historical reference only."""

import os
import subprocess


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def banner() -> None:
    print(
        f"""{Colors.CYAN}{Colors.BOLD}
    ███████╗ █████╗  ██████╗ █████╗ ██╗███╗   ███╗
    ╚══███╔╝██╔══██╗██╔════╝██╔══██╗██║████╗ ████║
      ███╔╝ ███████║██║     ███████║██║██╔████╔██║
     ███╔╝  ██╔══██║██║     ██╔══██║██║██║╚██╔╝██║
    ███████╗██║  ██║╚██████╗██║  ██║██║██║ ╚═╝ ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝
    {Colors.YELLOW}>> Archived WiFi Lab Tool <<{Colors.RESET}
    """
    )


def get_interfaces() -> list[str]:
    res = subprocess.check_output("iw dev | grep Interface | cut -d' ' -f2", shell=True)
    return res.decode().split()


def kill_conflicting_processes() -> None:
    print(f"{Colors.YELLOW}[*] Killing conflicting processes...{Colors.RESET}")
    subprocess.run("sudo airmon-ng check kill", shell=True, check=False)


def start_monitor(iface: str) -> str:
    print(f"{Colors.GREEN}[+] Enabling monitor mode on {iface}...{Colors.RESET}")
    subprocess.run(f"sudo airmon-ng start {iface}", shell=True, check=False)
    return iface + "mon"


def main_menu() -> str:
    os.system("clear")
    banner()
    print(f"{Colors.BOLD}1.{Colors.RESET} Setup Environment")
    print(f"{Colors.BOLD}2.{Colors.RESET} Live Network Scanner")
    print(f"{Colors.BOLD}3.{Colors.RESET} Reset Network & Exit")
    print("-" * 45)
    return input(f"{Colors.GREEN}legacy@zacaim{Colors.RESET}:~# ")


def main() -> None:
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] Error: Run as root.{Colors.RESET}")
        return

    while True:
        choice = main_menu()
        if choice == "1":
            kill_conflicting_processes()
            interfaces = get_interfaces()
            if interfaces:
                start_monitor(interfaces[0])
            input("\nDone. Press Enter...")
        elif choice == "2":
            subprocess.run("sudo airodump-ng wlan0mon", shell=True, check=False)
        elif choice == "3":
            subprocess.run("sudo airmon-ng stop wlan0mon && sudo systemctl start NetworkManager", shell=True, check=False)
            break


if __name__ == "__main__":
    main()
