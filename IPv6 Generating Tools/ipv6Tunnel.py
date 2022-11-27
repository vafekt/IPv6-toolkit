#!/usr/bin/python
import sys
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 3:
    sip = sys.argv[1]
    dip = sys.argv[2]
else:
    print("Please insert:\n 1. Source IPv6\n 2. Destination IPv6")
    sys.exit(1)

# Classic 6to4 method
layer3 = IPv6(src=sip, dst=dip)
requestPacket = layer3/ICMPv6EchoRequest()/("VUT FEKT 2022")
packet1 = IP(src="192.168.10.1", dst="192.168.20.100")/requestPacket
send(packet1, verbose=False)
packet1.show2()
print("Sending packet with tunneling method 6to4")
