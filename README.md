# v2g-sniffing

Tool for sniffing the traffic between an Electric Vehicle (EV) and and Electric Vehicle Supply Equipment (EVSE) / Charging Station

## Available Tools:
- find_nid_nmk.py: extract the SLAC Network ID (NID) and Network Membership Key (NMK) from a pcap file or from live traffic
- set_slac_nid_nmk.py: set the NID and the NMK for a modem to be able to listen to the communication

## Getting Started
In order to include the third-party libraries when cloning v2g-sniffing, use the proper git options. For example:

```
git clone --recurse-submodules <clone url>
git submodule sync
```

If you encounter errors about git not locating specific repository versions, using this dirty hack seems to work:

```
git submodule update --force --recursive --init --remote
```