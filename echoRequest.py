#!/usr/bin/python
import sys

from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 3:
    sip = sys.argv[1]
    dip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address")
    sys.exit(1)

# Generate packet
packet1 = IPv6(src=sip, dst=dip)/ICMPv6EchoRequest()
send(packet1, verbose=False)
print("Sending Echo Request message to address: " + dip)
