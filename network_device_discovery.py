# A tool to perform network device discovery using Python

import ctypes
import json
import os
import re
import socket
import subprocess

import requests
from colorama import Fore, init as colorama_init

B = Fore.BLUE
C = Fore.CYAN
G = Fore.GREEN
R = Fore.RED
RE = Fore.RESET
W = Fore.WHITE
Y = Fore.YELLOW

regex_arp_entry = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\s+.{3}-.{3}")
regex_ip_addr = re.compile(r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")
regex_mac_addr = re.compile(r"(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})")
regex_arp_interface = re.compile(r"Interface: (.+?) ---")


def print_status(code, clear_screen=False, device={}):
    status_switch = {
        "banner": f"""{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠃⠀⠀⠀⠀⠀⠀⠰⣶⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠁⣴⠇⠀⠀⠀⠀⠸⣦⠈⢿⡄
⠀⠀⠀⠀⠀⠀⠀⠀⣾⡇⢸⡏⢰⡇⠀⠀⢸⡆⢸⡆⢸⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠘⣧⡈⠃{C}⢰⡆{G}⠘⢁⣼⠁⣸⡇ ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣄⠘⠃⠀{C}⢸⡇{G}⠀⠘⠁⣰⡟⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠃⠀⠀{C}⢸⡇{G}⠀⠀⠘⠋⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⢸⡇░░░▒▒▓██████████████████████████{G}█{C}█{G}█{C}█{Y}█{C}█{G}█{C}██▓▒▒░░░{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⢸⡇░░░▒▒▓█  {W}Network Device Discovery 2.0.1 {C}█▓▒▒░░░{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⠘⠃░░░▒▒▓███████████████████████████████████▓▒▒░░░{G}
                    {C}▒▓█▓▒                             ▒▓█▓▒{RE}⠀⠀
            """,
        "not_windows": f"{R}[-] {RE}Please run NDD.py on a Windows machine",
        "scanning": f"{G}Scanning for local network devices ...{RE}",
        "device_table_headers": f"""
        ID         Interface              IPv4 address           MAC address              Vendor
        ---        ---------------        ---------------        -----------------        ---------------
        """,
    }

    if clear_screen:
        subprocess.call("cls" if os.name == "nt" else "clear", shell=True)
    print(status_switch.get(code))


def get_arp_table():
    process = subprocess.Popen(
        "arp -a",
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    arp_table_output = (process.stdout.read() + process.stderr.read()).decode()
    arp_table_split = arp_table_output.split("\n")
    arp_table = [line.strip() for line in arp_table_split]
    return arp_table


def process_arp_table(arp_table):
    devices_found = {}
    entry_num = 0
    interface_addr = ""

    for line in arp_table:

        interface = re.search(regex_arp_interface, line)
        if interface:
            interface_addr = interface.group(1)
            continue

        entry = re.search(regex_arp_entry, line)
        if entry:
            entry_num += 1
            device_addr = re.search(regex_ip_addr, line).group(0)
            device_mac = (
                re.search(regex_mac_addr, line).group(0).replace("-", ":").upper()
            )
            device_vendor = lookup_mac_addr_oui(device_mac)

            devices_found.update(
                {
                    device_addr: {
                        "num": entry_num,
                        "address": device_addr,
                        "mac": device_mac,
                        "vendor": device_vendor,
                        "interface": interface_addr,
                    }
                }
            )

    return devices_found


def lookup_mac_addr_oui(mac_addr):
    # Organizationally Unique Identifier (OUI)
    # The OUI is found in the first three octets of a MAC address
    try:
        oui_info = json.loads(requests.get("http://macvendors.co/api/" + mac_addr).text)
        vendor = oui_info["result"]["company"]
    except:
        vendor = f"{R}-- unknown --{RE}"

    return vendor


def main():
    colorama_init(convert=True)

    if os.name != "nt":
        print_status("not_windows")
        return

    ctypes.windll.kernel32.SetConsoleTitleW("Network Device Discovery")

    print_status("banner", clear_screen=True)
    print_status("scanning")

    arp_table = get_arp_table()
    devices_found = process_arp_table(arp_table)

    print_status("banner", clear_screen=True)
    print_status("device_table_headers")

    for device in devices_found.values():
        print(
            f'        {B}{device["num"]:<11}{W}{device["interface"]:<23}{C}{device["address"]:<23}{Y}{device["mac"]:<25}{G}{device["vendor"]}'
        )


if __name__ == "__main__":
    main()
