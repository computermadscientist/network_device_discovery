# Network Device Discovery
A tool for discovering devices on the local network using ARP, UPNP.

Currently this tool only works on Windows.

![screenshot](https://github.com/computermadscientist/network_device_discovery/blob/main/resources/screenshot_001.png)

## Discovery Methods

### Address Resolution Protocol (ARP)

1. Get the current ARP cache tables for all interfaces.
2. Parse the ARP caches tables for individual device entries.

### Universal Plug and Play (UPNP)

1. Send M-SEARCH request via Multicast UDP
2. Receive Unicast UDP response from compatible devices
3. Get and parse XML description file from device

## Installation

Requires Python 3.9+ installed. 
You can download the latest version of Python 3 via the [official website](https://www.python.org/downloads/)

Once Python has been installed, ensure you have the Python library dependencies installed.
```bash
$ cd .\network_device_discovery\
$ python -m pip install -r requirements.txt
```

## Usage

To run the script, you simply use the Python command:
```bash
$ python network_device_discovery.py
```
Results will be displayed to the terminal.