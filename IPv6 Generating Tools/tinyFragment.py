#!/usr/bin/python
import random
import sys
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, in6_chksum, IPv6ExtHdrFragment
from scapy.packet import Raw
from scapy.sendrecv import send

# Set the parameters
sip = "2001:db8:abcd:1:20c:29ff:fe17:9c15"
dip = "2001:db8:abcd:3:801c:42ff:feb5:f675"
# Generate random fragmentation ID
frag_ID = random.randrange(1, 4294967296, 1)

payload1 = Raw("AABBCCDD"*(1-1))
payload2 = Raw("BBDDAACC"*1)
payload = str(Raw("AABBCCDD"*(1+1-1)))

icmpv6_packet = ICMPv6EchoRequest(data=payload)
ipv6_packet1 = IPv6(src=sip, dst=dip, plen=(1+1)*8)
# csum=in6_chksum(58, ipv6_packet1/icmpv6_packet, bytes(icmpv6_packet))
csum = 14341

print(8*(1+1))
ipv6_packet1 = IPv6(src=sip, dst=dip, plen=8*(1+1))
icmpv6_packet = ICMPv6EchoRequest(cksum=csum, data=payload1)

frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=frag_ID, nh=58)
frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=frag_ID, nh=58)
packet1 = ipv6_packet1/frag1/icmpv6_packet
packet2 = ipv6_packet1/frag2/payload2
send(packet1, verbose=False)
send(packet2, verbose=False)
