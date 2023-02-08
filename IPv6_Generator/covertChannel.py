#!/usr/bin/python
import random
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, PadN, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def covertChannel(interface, smac, sip, dip, sport, dport):
    if smac == "":
        smac = getmacbyip6(sip)
    if sport == "":
        sport = random.randint(10000, 65535)
    sport = int(sport)
    # Generate packet
    data1 = "https://github.com/secdev/scapy/blob/master/scapy/layers/inet6.py"
    data2 = "https://www.youtube.com/watch?v=hVy8lp2JzPE"
    data3 = "https://samsclass.info/ipv6/proj/fw6a.htm"
    data4 = "file:///E:/STUDIUM/PRVN%C3%8D%20LETN%C3%8D%20SEMESTR"
    data5 = "https://www.google.com/search?client=firefox-b-d&q=slaac+scapy"
    layer3 = IPv6(src=sip, dst=dip)
    Extension = IPv6ExtHdrDestOpt(options=[PadN(optdata=data1)] +
                                          [PadN(optdata=data2)] +
                                          [PadN(optdata=data3)] +
                                          [PadN(optdata=data4)])

    packet1 = Ether(src=smac) / layer3 / Extension / TCP(sport=sport, dport=dport) / data5
    if interface == "":
        sendp(packet1, verbose=False)
    else:
        sendp(packet1, verbose=False, iface=interface)
    print("Sending packet with covert message inside the extension headers to address: " + dip)
