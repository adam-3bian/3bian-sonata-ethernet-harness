## IPv6 Ethernet Harness

Contains experimental code for testing and extending network functionality.

**Note:** This is not intended as production-ready code.

### Current Parsing Paths

```
Ethernet Header
├── IPv4 Header
│   ├── TCP Header
│   ├── UDP Header
│   │   └── DHCPv6 Header
│   ├── ICMP Header
│   ├── IGMP Header
│   └── Unknown Protocol
├── IPv6 Header
│   ├── Hop-by-Hop Header
│   ├── TCP Header
│   ├── UDP Header
│   │   └── DHCPv6 Header
│   ├── ICMPv6 Header
│   │   ├── Router Solicitation
│   │   ├── Router Advertisement
│   │   ├── Neighbor Solicitation
│   │   └── Unknown ICMPv6 Type
│   └── Unknown Next Header
├── ARP Header
│   ├── IPv4 ARP Header
│   ├── IPv6 ARP Header
│   └── Unknown Protocol Type
├── VLAN Header
│   ├── Double VLAN Header
│   │   ├── IPv4 Header
│   │   ├── IPv6 Header
│   │   ├── ARP Header
│   │   └── Unknown EtherType
│   ├── IPv4 Header
│   ├── IPv6 Header
│   ├── ARP Header
│   └── Unknown EtherType
├── Double VLAN Header
│   ├── IPv4 Header
│   ├── IPv6 Header
│   ├── ARP Header
│   └── Unknown EtherType
└── Unknown EtherType
```

### Prepare the Environment

```
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip3 install -r requirements.txt
deactivate
```

### Build Instructions

Assuming LLVM build files are in /cheriot-tools/bin.

```
. .venv/bin/activate
xmake config --sdk=/cheriot-tools
xmake
xmake run
deactivate
```