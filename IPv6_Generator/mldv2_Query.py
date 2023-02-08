#!/usr/bin/python
from scapy.layers.inet6 import getmacbyip6, IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def mldv2_Query(interface, smac, sip, dip, mulip, num_sources):
    if smac == "":
        smac = getmacbyip6(sip)
        # Generate packet when missing MAC address
        layer3 = IPv6(src=sip, dst=dip, hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        if num_sources == 0: # General Query and MAS Query
            MLD = ICMPv6MLQuery2(type=130, mladdr=mulip, sources_number=0)
            packet1 = Ether(src=smac)/layer3/HBH/MLD
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            if mulip == "::":
                print("Sending MLDv2 General Query message to address: ", dip)
            else:
                print("Sending MLDv2 Multicast Address Specific Query message to address: ", dip)
        if num_sources > 0: # Multicast Address and Source Specific Query
            sources = []
            for i in range(num_sources):
                element = input("- Insert your " + str(i+1) + " source: ")
                sources.append(element)
            MLD = ICMPv6MLQuery2(type=130, mladdr=mulip, sources_number=num_sources, sources=sources)
            packet1 = Ether(src=smac) / layer3 / HBH / MLD
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending MLDv2 Multicast Address and Source Specific Query message to address: ", dip)
    else:
        # Generate packet when missing MAC address
        layer3 = IPv6(src=sip, dst=dip, hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        if num_sources == 0:  # General Query and MAS Query
            MLD = ICMPv6MLQuery2(type=130, mladdr=mulip, sources_number=0)
            packet1 = Ether(src=smac) / layer3 / HBH / MLD
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            if mulip == "::":
                print("Sending MLDv2 General Query message to address: ", dip)
            else:
                print("Sending MLDv2 Multicast Address Specific Query message to address: ", dip)
        if num_sources > 0:  # Multicast Address and Source Specific Query
            sources = []
            for i in range(num_sources):
                element = input("- Insert your " + str(i+1) + " source: ")
                sources.append(element)
            MLD = ICMPv6MLQuery2(type=130, mladdr=mulip, sources_number=num_sources, sources=sources)
            packet1 = Ether(src=smac) / layer3 / HBH / MLD
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending MLDv2 Multicast Address and Source Specific Query message to address: ", dip)
