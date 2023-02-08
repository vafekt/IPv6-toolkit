#!/usr/bin/python
from scapy.layers.inet6 import getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6


def echoRequest(interface, smac, sip, dip):
    if smac == "":
        smac = getmacbyip6(sip)
        # Generate packet when missing MAC address
        packet1 = Ether(src=smac) / IPv6(src=sip, dst=dip) / ICMPv6EchoRequest()
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending Echo Request message to address: " + dip)
    else:
        # Generate packet when having MAC address
        packet1 = Ether(src=smac) / IPv6(src=sip, dst=dip) / ICMPv6EchoRequest()
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending Echo Request message to address: " + dip)
