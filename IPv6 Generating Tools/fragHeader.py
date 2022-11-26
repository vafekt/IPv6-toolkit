#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, fragment6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandString

# Ask user to insert value
if len(sys.argv) == 5:
    sip = sys.argv[1]
    dip = sys.argv[2]
    size_data = int(sys.argv[3])
    size_lim = int(sys.argv[4])
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address")
    sys.exit(1)

# Generate packet
data = Raw(RandString(size=size_data))
layer3 = IPv6(src=sip, dst=dip)
packet1 = fragment6(layer3 / IPv6ExtHdrFragment()
                    / ICMPv6EchoRequest() / data, size_lim)
send(packet1, verbose=False)
print("Sending packet with fragmentation to address: " + dip)
