#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2, ICMPv6MLReport2, \
    ICMPv6MLDMultAddrRec
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 5:
    opt = sys.argv[1]
    sip = sys.argv[2]
    mul_add = sys.argv[3]
    src_add = sys.argv[4]

else:
    print("Please insert:\n 1. Types of MLD messages(query, add, delete)"
          "\n 2. Source IPv6 address\n 3. Multicast address\n"
          " 4. Source that hosts want to get data from")
    sys.exit(1)

# Generate MLD packets
if opt == "query":
    layer3 = IPv6(src=sip, dst=mul_add, hlim=1)
    HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
    MLD = ICMPv6MLQuery2(type=130, mladdr="::", sources_number=0)
    packet1 = layer3/HBH/MLD
    send(packet1, verbose=False)
    print("Sending Query MLDv2 message")
elif opt == "add":
    if src_add == "0":
        layer3 = IPv6(src=sip, dst="ff02::16", hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        MLD = ICMPv6MLReport2(type=143, records_number=1,
                              records=[ICMPv6MLDMultAddrRec(rtype=3, dst=mul_add)])
        packet1 = layer3 / HBH / MLD
        send(packet1, verbose=False)
        print("Sending Include MLDv2 message")
    else:
        layer3 = IPv6(src=sip, dst="ff02::16", hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        MLD = ICMPv6MLReport2(type=143, records_number=1,
                              records=[ICMPv6MLDMultAddrRec(rtype=3, dst=mul_add, sources=[src_add])])
        packet1 = layer3 / HBH / MLD
        send(packet1, verbose=False)
        print("Sending Include MLDv2 message")
elif opt == "delete":
    if src_add == "0":
        layer3 = IPv6(src=sip, dst="ff02::16", hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        MLD = ICMPv6MLReport2(type=143, records_number=1,
                              records=[ICMPv6MLDMultAddrRec(rtype=4, dst=mul_add)])
        packet1 = layer3 / HBH / MLD
        send(packet1, verbose=False)
        print("Sending Exclude MLDv2 message")
    else:
        layer3 = IPv6(src=sip, dst="ff02::16", hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        MLD = ICMPv6MLReport2(type=143, records_number=1,
                              records=[ICMPv6MLDMultAddrRec(rtype=4, dst=mul_add, sources=[src_add])])
        packet1 = layer3 / HBH / MLD
        send(packet1, verbose=False)
        print("Sending Exclude MLDv2 message")
