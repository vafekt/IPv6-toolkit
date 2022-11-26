#! usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting, \
    ICMPv6EchoRequest
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 4:
    sip = sys.argv[1]
    dst = sys.argv[2]
    hop = sys.argv[3]
else:
    print("Please insert:\n 1. Source IPv6 address\n 2. Destination IPv6 address"
          "\n 3. Intermediate hops")
    sys.exit(1)

hop = hop.split(",")

# Generate packet
layer3 = IPv6(src=sip, dst=dst)
RH0 = IPv6ExtHdrRouting(addresses=hop)
packet1 = layer3/RH0/ICMPv6EchoRequest(data="VUT FEKT")
send(packet1, verbose=False)
print("Sending RH0 message from source: " + sip)

