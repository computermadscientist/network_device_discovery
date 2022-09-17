# A Python script to perform network device discovery using ARP, UPNP

import ctypes
import json
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from pprint import pprint
from sys import platform

import requests
from colorama import Fore
from colorama import init as colorama_init

B = Fore.BLUE
C = Fore.CYAN
G = Fore.GREEN
M = Fore.MAGENTA
R = Fore.RED
RE = Fore.RESET
W = Fore.WHITE
Y = Fore.YELLOW

regex_arp_windows_interface = re.compile(r"Interface: (.+?) ---")
regex_arp_entry_windows = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\s+.{3}-.{3}")
regex_arp_entry_linux = re.compile(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}.*at.*on")
regex_arp_entry_linux_interface = re.compile(r".*at.*on\s(\S*)\s?")
regex_ip_addr = re.compile(r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")
regex_mac_addr = re.compile(r"(.{2}[-:].{2}[-:].{2}[-:].{2}[-:].{2}[-:].{2})")
regex_upnp_location = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)

xml_urn_schema = (
    "./{urn:schemas-upnp-org:device-1-0}device/{urn:schemas-upnp-org:device-1-0}"
)


def print_status(code, clear_screen=False) -> None:
    status_switch = {
        "banner": f"""{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠃⠀⠀⠀⠀⠀⠀⠰⣶⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠁⣴⠇⠀⠀⠀⠀⠸⣦⠈⢿⡄
⠀⠀⠀⠀⠀⠀⠀⠀⣾⡇⢸⡏⢰⡇⠀⠀⢸⡆⢸⡆⢸⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠘⣧⡈⠃{C}⢰⡆{G}⠘⢁⣼⠁⣸⡇ ⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣄⠘⠃⠀{C}⢸⡇{G}⠀⠘⠁⣰⡟⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠃⠀⠀{C}⢸⡇{G}⠀⠀⠘⠋⠀⠀⠀ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⢸⡇░░░▒▒▓██████████████████████████{G}█{C}█{G}█{C}█{Y}█{C}█{G}█{C}██▓▒▒░░░{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⢸⡇░░░▒▒▓█  {W}Network Device Discovery 3.0.2 {C}█▓▒▒░░░{G}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{C}⠘⠃░░░▒▒▓███████████████████████████████████▓▒▒░░░{G}
                    {C}▒▓█▓▒                             ▒▓█▓▒{RE}⠀⠀
            """,
        "win32": f"{Y}Windows{G} operating system detected.{RE}",
        "linux": f"{Y}Linux{G} operating system detected.{RE}",
        "wsl": f"{Y}WSL{G} environment detected.{RE}",
        "os_not_supported": f"{R}The detected operating system is not supported.{RE}",
        "scanning_arp": f"{G}Scanning for local network devices using {Y}ARP {G}...{RE}",
        "scanning_upnp": f"{G}Scanning for local network devices using {Y}UPNP {G}...{RE}",
        "device_table_headers": f"\n{'ID':<6}{'Interface':<19}{'IPv4 address':<18}{'MAC address':<20}{'Vendor':<30}\n"
        + f"{'---':<6}{'---------------':<19}{'---------------':<18}{'-----------------':<20}{'-----------------------':<30}",
        "upnp_socket_error": f"{R}Error: No data received from socket when performing UPNP broadcast \n"
        + f"{Y}If you are running this script in a VM, try changing the network connection to Bridged.{RE}",
    }

    if clear_screen:
        subprocess.call("cls" if os.name == "nt" else "clear", shell=True)
    print(status_switch.get(code))


def get_arp_table() -> list:
    command = ""
    arp_table = []

    if platform == "win32":
        command = "arp -a"
    elif platform == "linux":
        command = "arp -a"
        if "Microsoft" in os.uname().release:
            command = "arp.exe -a"
    else:
        return arp_table

    process = subprocess.Popen(
        # "arp -a",
        command,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    arp_table_output = (process.stdout.read() + process.stderr.read()).decode()
    arp_table_split = arp_table_output.split("\n")
    arp_table = [line.strip() for line in arp_table_split]
    return arp_table


def get_upnp_locations() -> set:
    upnp_locations = set()
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
            if (
                location_result
                and (location_result.group(1) in upnp_locations) == False
            ):
                upnp_locations.add(location_result.group(1))
    except socket.error:
        print_status("upnp_socket_error")
        sock.close()

    return upnp_locations


def process_upnp_locations(upnp_locations) -> dict:
    devices_found = {}

    for location in upnp_locations:
        device_addr = re.search(regex_ip_addr, location).group(1)
        devices_found.setdefault(device_addr, {"upnp_locations": []})
        devices_found[device_addr]["upnp_locations"].append(location)

    return devices_found


def process_arp_table(arp_table) -> dict:
    devices_found = {}
    entry_num = 0
    interface_addr = ""

    for line in arp_table:

        interface = re.search(regex_arp_windows_interface, line)
        if interface:
            interface_addr = interface.group(1)
            continue

        windows_entry = re.search(regex_arp_entry_windows, line)
        linux_entry = re.search(regex_arp_entry_linux, line)

        if linux_entry:
            interface_addr = re.search(regex_arp_entry_linux_interface, line).group(1)

        if windows_entry or linux_entry:
            entry_num += 1
            device_addr = re.search(regex_ip_addr, line).group(0)
            device_mac = re.search(regex_mac_addr, line).group(0)
            device_mac = device_mac.replace("-", ":").upper()
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


def lookup_mac_addr_oui(mac_addr) -> str:
    # Organizationally Unique Identifier (OUI)
    # The OUI is found in the first three octets of a MAC address
    vendor = None

    try:
        oui_info = json.loads(
            requests.get(f"http://macvendors.co/api/{mac_addr}", timeout=5).text
        )
        vendor = oui_info["result"]["company"]
    except:
        pass

    if not vendor:
        match = None
        with open("wireshark_manufacturer_database.txt") as f:
            lines = [line for line in f if line.strip() and not line.startswith("#")]

        # Try matching on full 6 octets
        for l in lines:
            if l.startswith(mac_addr):
                match = l
                break

        # Try matching on first 3 octets
        if not match:
            for j in lines:
                if j.startswith(mac_addr[:8]):
                    match = j
                    break

        vendor = f"{R}-- unknown --{RE}"
        if match:
            _, ven, *ven2 = match.strip().split("\t")
            vendor = ven2[0] if ven2 else ven

    return vendor


def combine_devices_found(arp_devices_found, upnp_devices_found) -> dict:
    # TODO
    # Simpler implementation
    devices_found = arp_devices_found.copy()

    for device_addr in devices_found:
        devices_found[device_addr]["upnp_locations"] = upnp_devices_found.get(
            device_addr, {}
        ).get("upnp_locations", [])

    return devices_found


def parse_xml_attribute(xml, xml_name) -> str:
    try:
        return xml.find(xml_name).text
    except AttributeError:
        return ""
    return ""


def get_upnp_location_data(upnp_location) -> dict:
    device_data = {}

    try:
        resp = requests.get(upnp_location, timeout=2)
        if resp.headers.get("server"):
            device_data["Server String"] = resp.headers["server"]
    except:
        return device_data

    try:
        xmlRoot = ET.fromstring(resp.text)
    except:
        return device_data

    device_attr = {
        "Device Type": "deviceType",
        "Friendly Name": "friendlyName",
        "Manufacturer": "manufacturer",
        "Manufacturer URL": "manufacturerURL",
        "Model Description": "modelDescription",
        "Model Name": "modelName",
        "Model Number": "modelNumber",
    }

    for key, value in device_attr.items():
        device_data[key] = parse_xml_attribute(xmlRoot, f"{xml_urn_schema}{value}")

    return device_data


def print_discovery_results(devices_found) -> None:
    # TODO
    # Clean-up
    # Determine better layout as more info is added
    for device in devices_found.values():

        print(
            f'{C}{device["num"]:<6}{W}{device["interface"]:<19}{C}{device["address"]:<18}{Y}{device["mac"]:<20}{G}{device["vendor"]:<30}'
        )

        already_printed = False

        if device["upnp_locations"]:
            print(f'{" "*63}{W}UPNP Locations')
            print(f'{" "*63}{W}------------------------')
            print(f'{" "*63}{M}{", ".join(device["upnp_locations"])}')

            for location in device["upnp_locations"]:
                upnp_data = get_upnp_location_data(location)
                if upnp_data and not already_printed:
                    for key, value in upnp_data.items():
                        print(f"{M}{key:>61}: {G}{value}")
                        already_printed = True


def check_operating_system() -> str:
    if platform == "win32":
        print_status("win32")
        ctypes.windll.kernel32.SetConsoleTitleW("Network Device Discovery")
    elif platform == "linux":
        print_status("linux")
        if "Microsoft" in os.uname().release:
            print_status("wsl")
    else:
        print_status("os_not_supported")
        return ""

    return platform


def main():
    print_status("banner", clear_screen=True)

    supported_os = check_operating_system()
    if not supported_os:
        return

    print_status("scanning_arp")
    arp_table = get_arp_table()
    arp_devices_found = process_arp_table(arp_table)

    print_status("scanning_upnp")
    upnp_locations = get_upnp_locations()
    upnp_devices_found = process_upnp_locations(upnp_locations)

    devices_found = combine_devices_found(arp_devices_found, upnp_devices_found)

    print_status("device_table_headers")
    print_discovery_results(devices_found)


if __name__ == "__main__":
    colorama_init(convert=True)
    main()
