# Network Device Discovery
A Python script for discovering devices on the local network using ARP, UPNP.

Currently this script only works on Windows.

*Code formatters: Black, isort*

## Example Output

![screenshot](https://github.com/computermadscientist/network_device_discovery/blob/main/resources/screenshot_001.png)

## Passive Discovery Methods

### Address Resolution Protocol (ARP)

1. Retrieve the current ARP cache tables for all interfaces.
2. Parse the ARP caches tables for individual device entries.
3. Perform OUI lookup of device MAC address to obtain device vendor.

## Active Discovery Methods

### Universal Plug and Play (UPNP)

1. Send M-SEARCH request via Multicast UDP.
2. Receive Unicast UDP response from compatible devices.
3. Retrieve and parse the XML description file from each device to obtain device attributes.

## Dependencies

Requires Python 3.9+ installed. 
You can download the latest version of Python 3 via the [official website](https://www.python.org/downloads/)

Once Python has been installed, ensure you have the Python library dependencies installed as well.
```bash
$ cd .\network_device_discovery\
$ python -m pip install -r requirements.txt
```

## Usage

To run the script, you simply use the Python command:
```bash
$ python discover.py
```
Results will be displayed to the terminal in a color coded table with some nice ascii art.