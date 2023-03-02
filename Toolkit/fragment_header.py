#!/usr/bin/python
import argparse
import sys
import time

import netifaces
import netifaces as ni
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, Pad1, PadN, IPv6ExtHdrFragment, ICMPv6EchoRequest, in6_chksum, \
    fragment6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.volatile import RandShort, RandString
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port


def main():
    parser = argparse.ArgumentParser(description="Sending SYN or ICMPv6 message(s) with Fragment Header to a target for"
                                                 " checking firewall bypass with options:\n"
                                                 "|> 1x atomic fragment (insert -c 1).\n"
                                                 "|> 3x atomic fragment with same id (insert -c 2).\n"
                                                 "|> 3x atomic fragment with different id (insert -c 3).\n"
                                                 "|> 100x atomic fragment with same id (insert -c 4).\n"
                                                 "|> 100x atomic fragment with different id (insert -c 5).\n"
                                                 "|> 2x Destination Header + 2x Fragment Header (insert -c 6).\n"
                                                 "|> tiny fragments PING (insert -c 7).\n"
                                                 "|> overlapping fragments PING (insert -c 8)."
                                                 , formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination")
    parser.add_argument("-sport", dest="source_port", action="store", type=int,
                        help="the port of sender (set to random port if skipping)")
    parser.add_argument("-dport", dest="dest_port", action="store", type=int,
                        help="the port of destination (set to random port if skipping)")
    parser.add_argument('-c', dest="choice", choices=[1, 2, 3, 4, 5, 6, 7, 8], action="store", type=int,
                        help="the option of message you want to send (sending all types if skipping)")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    # Validate the network interface
    if not args.interface:
        print("---> Network interface is required!!!")
        parser.print_help()
        sys.exit(1)
    interface_list = netifaces.interfaces()
    while True:
        if args.interface in interface_list:
            break
        else:
            print("---> The given interface is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source IPv6 address
    if args.source_ip is None:
        args.source_ip = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        print("---> No destination IPv6 address is inserted. Try again!!!")
        sys.exit(1)
    if args.destination_ip is not None:
        if not is_valid_ipv6(args.destination_ip):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the source port
    if args.source_port is None:
        args.source_port = RandShort()
    if args.source_port is not None:
        if not is_valid_port(args.source_port):
            print("---> The given source port is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination port
    if args.dest_port is None:
        args.dest_port = RandShort()
    if args.dest_port is not None:
        if not is_valid_port(args.dest_port):
            print("---> The given destination port is invalid. Try again!!!")
            sys.exit(1)

    # Validate the option
    if args.choice is None:
        args.choice = "all"

    # Generate packet
    layer2 = Ether(src=args.source_mac)
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip, hlim=255)
    layer4 = TCP(sport=args.source_port, dport=args.dest_port, ack=0, flags='S')
    return args.interface, layer2, layer3, layer4, args.source_ip, args.destination_ip, args.choice


def choice1(interface, layer2, layer3, layer4, dip):
    fragHdr = IPv6ExtHdrFragment(id=RandShort())
    packet1 = layer2 / layer3 / fragHdr / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending atomic fragment message to the destination: ", dip)


def choice2(interface, layer2, layer3, layer4, dip):
    id = RandShort()
    fragHdr = IPv6ExtHdrFragment(id=id)
    for i in range(2):
        fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
    packet1 = layer2 / layer3 / fragHdr / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending 3x atomic fragment message (same id) to the destination: ", dip)


def choice3(interface, layer2, layer3, layer4, dip):
    id = RandShort()
    fragHdr = IPv6ExtHdrFragment(id=id)
    for i in range(2):
        id = id + 1
        fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
    packet1 = layer2 / layer3 / fragHdr / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending 3x atomic fragment message (different id) to the destination: ", dip)


def choice4(interface, layer2, layer3, layer4, dip):
    id = RandShort()
    fragHdr = IPv6ExtHdrFragment(id=id)
    for i in range(99):
        fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
    packet1 = layer2 / layer3 / fragHdr / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending 100x atomic fragment message (same id) to the destination: ", dip)


def choice5(interface, layer2, layer3, layer4, dip):
    id = RandShort()
    fragHdr = IPv6ExtHdrFragment(id=id)
    for i in range(99):
        id = id + 1
        fragHdr = fragHdr / IPv6ExtHdrFragment(id=id)
    packet1 = layer2 / layer3 / fragHdr / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending 100x atomic fragment message (different id) to destination: ", dip)


def choice6(interface, layer2, layer3, layer4, dip):
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    id = RandShort()
    data = Raw(RandString(size=2))
    options = [PadN(optdata=data)]
    for i in range(100):
        options = options + [PadN(optdata=data)]
    desOption = IPv6ExtHdrDestOpt(options=options) / IPv6ExtHdrDestOpt(options=options)
    fragHdr = IPv6ExtHdrFragment(id=id) / IPv6ExtHdrFragment(id=id + 1)
    packet1 = layer2 / layer3 / desOption / fragHdr / layer4 / Raw(RandString(size=2000))
    sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
    print("Sending message with 2x Destination Options + 2x Fragment Headers to the destination: ", dip)


def choice7(interface, layer2, layer3, layer4, sip, dip):
    payload = "ABCDEFGH"
    layer3 = IPv6(src=sip, dst=dip, plen=16)  # 16 bytes contains 8 bytes of ICMPv6 Header and 8 bytes of Payload
    icmpv6 = ICMPv6EchoRequest()
    csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / payload))
    frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
    frag2 = IPv6ExtHdrFragment(offset=1, m=0, id=12345,
                               nh=58)  # Avoiding overlapping by setting offset = 1 (8 bytes distance)
    icmpv6 = ICMPv6EchoRequest(cksum=csum)
    packet1 = layer2 / layer3 / frag1 / icmpv6
    packet2 = layer2 / layer3 / frag2 / payload

    sendp(packet1, verbose=False, iface=interface)
    sendp(packet2, verbose=False, iface=interface)
    print("Sending ICMPv6 Echo Request message with tiny fragments to the destination: ", dip)


def choice8(interface, layer2, layer3, layer4, sip, dip):
    payload1 = 'V' * 1272
    payload2 = 'A' * 1280
    layer3 = IPv6(src=sip, dst=dip,
                  plen=1288)  # (1280 bytes Payload 2 + 8 bytes Fragment Header) or (1272 + 8 Frag + 8 ICMPv6)
    icmpv6 = ICMPv6EchoRequest(data=payload1)
    csum = in6_chksum(58, layer3 / icmpv6, bytes(icmpv6 / payload2))
    icmpv6 = ICMPv6EchoRequest(cksum=csum, data=payload1)  # 8 bytes header + 1272 bytes data
    frag1 = IPv6ExtHdrFragment(offset=0, m=1, id=12345, nh=58)
    frag2 = IPv6ExtHdrFragment(offset=2, m=0, id=12345,
                               nh=58)  # Offset has to be 160 = 1280*8, but 2 offset causes overlapping
    packet1 = layer2 / layer3 / frag1 / icmpv6
    packet2 = layer2 / layer3 / frag2 / payload2

    sendp(packet1, verbose=False, iface=interface)
    sendp(packet2, verbose=False, iface=interface)
    print("Sending ICMPv6 Echo Request message with overlapping to the destination: ", dip)


if __name__ == "__main__":
    iface, l2, l3, l4, sip, dip, choice = main()
    try:
        if choice == 1:
            choice1(iface, l2, l3, l4, dip)
        if choice == 2:
            choice2(iface, l2, l3, l4, dip)
        if choice == 3:
            choice3(iface, l2, l3, l4, dip)
        if choice == 4:
            choice4(iface, l2, l3, l4, dip)
        if choice == 5:
            choice5(iface, l2, l3, l4, dip)
        if choice == 6:
            choice6(iface, l2, l3, l4, dip)
        if choice == 7:
            choice7(iface, l2, l3, l4, sip, dip)
        if choice == 8:
            choice8(iface, l2, l3, l4, sip, dip)
        if choice == "all":
            choice1(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice2(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice3(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice4(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice5(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice6(iface, l2, l3, l4, dip)
            time.sleep(2)
            choice7(iface, l2, l3, l4, sip, dip)
            time.sleep(2)
            choice8(iface, l2, l3, l4, sip, dip)
    except KeyboardInterrupt:
        sys.exit(0)




