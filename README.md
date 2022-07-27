# Network Device Discovery
A Python script for discovering devices on the local network using ARP, UPNP.

Currently this script works for Windows, WSL and Linux.

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

On Linux Arp may need to be installed as part of the net-tools package

```bash
sudo apt-get install net-tools
```

## Usage

To run the script, you simply use the Python command:
```bash
$ python discover.py
```
Results will be displayed to the terminal in a color coded table with some nice ascii art.

*Note*: 

Although this script can be used inside a VM, the results may be limited, depending on how your VM is networked. Try the VM network connection as Bridged (Connected directly to the physical network) and not NAT (Sharing the host's IP address). Otherwise some of the discovery methods relying on sockets may not work.
