#!/usr/bin/python
import sys
from collections import Counter

from scapy.arch import get_if_addr6
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, Pad1, HBHOptUnknown
from scapy.sendrecv import send, sniff


def reconnaisance(interface):
    # Parameters
    sip = get_if_addr6(interface)
    data = "A" * 8
    layer3 = IPv6(src=sip, dst="ff02::1")

    # Ping with standard PING packet
    packet1 = layer3 / ICMPv6EchoRequest() / data

    # Ping with Parameter Problem packet
    Extension = IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128)] +
                                          [Pad1()] + [Pad1()] + [Pad1()])
    packet2 = layer3 / Extension / ICMPv6EchoRequest() / data
    send(packet1, verbose=False, iface=interface)
    send(packet2, verbose=False, iface=interface)

    # Create a Packet Counter
    packet_counts = Counter()

    # Define our Custom Action function
    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
        packet_counts.update([key])
        return f"Discover the #{sum(packet_counts.values())} host with IPv6 address: " \
               f"{packet[0][1].src} and MAC address: {packet[0].src}"

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6 dst %s" % sip
    sniff(filter=build_filter, prn=custom_action, timeout=15)

    ## Print out packet count per A <--> Z address pair
    # print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
