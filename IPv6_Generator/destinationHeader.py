#!/usr/bin/python
import random

from scapy.layers.inet import TCP
from scapy.layers.inet6 import getmacbyip6, IPv6, IPv6ExtHdrDestOpt, Pad1, PadN
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.volatile import RandString


def destinationHeader(interface, smac, sip, dip, sport, dport):
    if smac == "":
        smac = getmacbyip6(sip)
    if sport == "":
        sport = random.randint(10000, 65535)
    sport = int(sport)
    option = int(input("- Insert one of the following options, insert the number (1, 2):\n "
                       "1: Sending SYN packet containing Destination Option with empty padding\n "
                       "2: Sending SYN packet containing 3x Destination Option headers\n "
                       "3: Sending SYN packet containing 100x Destination Option headers\n "
                       "4: Sending SYN packet containing Destination Option with hidden data in padding\n "
                       "Choose one of 4 options: "))
    layer3 = IPv6(src=sip, dst=dip)
    layer4 = TCP(sport=sport, dport=dport, ack=0, flags='S')

    if option == 1:
        # Generate Destination Option Header with ignore option
        desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        packet1 = Ether(src=smac)/layer3/desOption/layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending TCP SYN packet to address: ", dip)
    if option == 2:
        # Generate 3 Destination Option Headers
        desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        for i in range(2):
            desOption = desOption/IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        packet1 = Ether(src=smac) / layer3 / desOption / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending TCP SYN packet to address: ", dip)
    if option == 3:
        # Generate 100 Destination Option Headers
        desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        for i in range(99):
            desOption = desOption/IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
        packet1 = Ether(src=smac) / layer3 / desOption / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending TCP SYN packet to address: ", dip)
    if option == 4:
        # Covert channel
        data = Raw(RandString(size=100))
        desOption = IPv6ExtHdrDestOpt(options=[PadN(optdata=data)] + [PadN(optdata=data)] + [PadN(optdata=data)] + [PadN(optdata=data)] + [PadN(optdata=data)])
        packet1 = Ether(src=smac) / layer3 / desOption / layer4 / data
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending TCP SYN packet to address: ", dip)

