#! usr/bin/python
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting, ICMPv6EchoRequest, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def routingHeader(interface, smac, sip, dip, num_hops):
    if smac == "":
        smac = getmacbyip6(sip)
        if num_hops == 0:
            # Generate RHO packet
            layer3 = IPv6(src=sip, dst=dip)
            RH0 = IPv6ExtHdrRouting()
            packet1 = Ether(src=smac)/layer3/RH0/ICMPv6EchoRequest(data="VUT FEKT")
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending Routing Header message to address: ", dip)
        if num_hops > 0:
            hops = []
            for i in range(num_hops):
                if i == num_hops-1:
                    element = input("- Insert the last hop (final destination): ")
                    hops.append(element)
                    break
                element = input("- Insert the " + str(i+1) + " intermediate hop: ")
                hops.append(element)
            # Generate RHO packet
            layer3 = IPv6(src=sip, dst=dip)
            RH0 = IPv6ExtHdrRouting(addresses=hops)
            packet1 = Ether(src=smac) / layer3 / RH0 / ICMPv6EchoRequest(data="VUT FEKT")
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending Routing Header message to address: ", dip)
    else:
        if num_hops == 0:
            # Generate RHO packet
            layer3 = IPv6(src=sip, dst=dip)
            RH0 = IPv6ExtHdrRouting()
            packet1 = Ether(src=smac)/layer3/RH0/ICMPv6EchoRequest(data="VUT FEKT")
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending Routing Header message to address: ", dip)
        if num_hops > 0:
            hops = []
            for i in range(num_hops):
                if i == num_hops - 1:
                    element = input("- Insert the last hop (final destination): ")
                    hops.append(element)
                    break
                element = input("- Insert the " + str(i + 1) + " intermediate hop: ")
                hops.append(element)
            # Generate RHO packet
            layer3 = IPv6(src=sip, dst=dip)
            RH0 = IPv6ExtHdrRouting(addresses=hops)
            packet1 = Ether(src=smac) / layer3 / RH0 / ICMPv6EchoRequest(data="VUT FEKT")
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
            print("Sending Routing Header message to address: ", dip)

