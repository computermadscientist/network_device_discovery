# A tool to perform network device discovery using Python

import ctypes
import json
import os
import re
import socket
import subprocess

from pprint import pprint

import requests
from colorama import Fore, init as colorama_init

B = Fore.BLUE
C = Fore.CYAN
G = Fore.GREEN
M = Fore.MAGENTA
R = Fore.RED
RE = Fore.RESET
W = Fore.WHITE
Y = Fore.YELLOW

regex_arp_entry = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\s+.{3}-.{3}")
regex_ip_addr = re.compile(r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")
regex_mac_addr = re.compile(r"(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})")
regex_arp_interface = re.compile(r"Interface: (.+?) ---")
regex_upnp_location = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)


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
        "scanning_arp": f"{G}Scanning for local network devices using {Y}ARP {G}...{RE}",
        "scanning_upnp": f"{G}Scanning for local network devices using {Y}UPNP {G}...{RE}",
        "device_table_headers": f"{'ID':<6}{'Interface':<19}{'IPv4 address':<18}{'MAC address':<20}{'Vendor':<30}{'UPNP Locations':<25}\n"
        + f"{'---':<6}{'---------------':<19}{'---------------':<18}{'-----------------':<20}{'-----------------------':<30}{'-----------------------':<25}",
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


def get_upnp_locations():
    locations = set()
    ssdpDiscover = (
        "M-SEARCH * HTTP/1.1\r\n"
        + "HOST: 239.255.255.250:1900\r\n"
        + 'MAN: "ssdp:discover"\r\n'
        + "MX: 1\r\n"
        + "ST: ssdp:all\r\n"
        + "\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(ssdpDiscover.encode("ASCII"), ("239.255.255.250", 1900))
    sock.settimeout(3)
    try:
        while True:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
            location_result = regex_upnp_location.search(data.decode("ASCII"))
            if location_result and (location_result.group(1) in locations) == False:
                locations.add(location_result.group(1))
    except socket.error:
        sock.close()

    return locations


def process_upnp_locations(upnp_locations):
    devices_found = {}

    for location in upnp_locations:
        device_addr = re.search(regex_ip_addr, location).group(1)
        devices_found.setdefault(device_addr, {"upnp_locations": []})
        devices_found[device_addr]["upnp_locations"].append(location)

    return devices_found


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
                        "upnp_locations": [],
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


def combine_devices_found(arp_devices_found, upnp_devices_found):
    # TODO
    # There should be a simpler way to do this
    devices_found = arp_devices_found.copy()

    for device_addr in devices_found:
        devices_found[device_addr]["upnp_locations"] = upnp_devices_found.get(
            device_addr, {}
        ).get("upnp_locations", [])

    return devices_found


def main():
    colorama_init(convert=True)

    if os.name != "nt":
        print_status("not_windows")
        return

    ctypes.windll.kernel32.SetConsoleTitleW("Network Device Discovery")

    print_status("banner", clear_screen=True)
    print_status("scanning_arp")

    arp_table = get_arp_table()
    arp_devices_found = process_arp_table(arp_table)

    print_status("scanning_upnp")

    upnp_locations = get_upnp_locations()
    upnp_devices_found = process_upnp_locations(upnp_locations)

    devices_found = combine_devices_found(arp_devices_found, upnp_devices_found)

    # print_status("banner", clear_screen=True)
    print_status("device_table_headers")

    # TODO
    # This was quick and dirty to test formatting, clean-up
    for device in devices_found.values():
        if len(device["upnp_locations"]) == 0:
            print(
                f'{C}{device["num"]:<6}{W}{device["interface"]:<19}{C}{device["address"]:<18}{Y}{device["mac"]:<20}{G}{device["vendor"]:<30}{M}{"":<25}'
            )
        elif len(device["upnp_locations"]) == 1:
            print(
                f'{C}{device["num"]:<6}{W}{device["interface"]:<19}{C}{device["address"]:<18}{Y}{device["mac"]:<20}{G}{device["vendor"]:<30}{M}{device["upnp_locations"][0]:<25}'
            )
        elif len(device["upnp_locations"]) > 1:
            print(
                f'{C}{device["num"]:<6}{W}{device["interface"]:<19}{C}{device["address"]:<18}{Y}{device["mac"]:<20}{G}{device["vendor"]:<30}{M}{device["upnp_locations"][0]:<25}'
            )
            for d in device["upnp_locations"][1:]:
                print(
                    f"                                                                                             {M}{d:<25}"
                )


if __name__ == "__main__":
    main()
