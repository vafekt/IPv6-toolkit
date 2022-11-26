#!/usr/bin/python
import sys
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrRouting, IPv6ExtHdrHopByHop, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandString

# Ask user to insert value
if len(sys.argv) == 3:
    sip = sys.argv[1]
    dip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address.")
    sys.exit(1)

# Generate packets
layer3 = IPv6(src=sip, dst=dip)
data = Raw(RandString(size=100))

# Erroneous header field encountered as Fragment flag at the last packet is set to Yes
packet1 = layer3/IPv6ExtHdrFragment(nh=6, offset=100, id=2, m=1)/\
         TCP(sport=36125, dport=80, flags="S")/Raw(load=("A"*150))

# Erroneous header field encountered as multiple headers with wrong order exist
packet2 = layer3/IPv6ExtHdrFragment(nh=44)/\
            IPv6ExtHdrRouting(nh=43)/IPv6ExtHdrFragment(nh=0)/\
            IPv6ExtHdrHopByHop()/ICMPv6EchoRequest()/data
send([packet1, packet2], verbose=False)
print("Sending two error packets to receive Parameter Problem response")
