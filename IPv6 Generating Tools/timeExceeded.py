#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, IPerror6, ICMPv6EchoRequest
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 4:
    src_router = sys.argv[1]
    sip = sys.argv[2]
    dip = sys.argv[3]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address")
    sys.exit(1)

# Generate packet
layer3 = IPv6(src=src_router, dst=sip)
timeExceeded = ICMPv6TimeExceeded()/IPerror6(src=sip, dst=dip)/\
               ICMPv6EchoRequest()
packet1 = layer3/timeExceeded
send(packet1, verbose=False)
print("Sending Time Exceeded message to the host:" + dip)
