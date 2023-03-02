#!/usr/bin/python
import argparse
import sys
import time
import netifaces
import netifaces as ni
import psutil
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, Pad1, PadN, IPv6ExtHdrFragment, fragment6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.volatile import RandShort, RandString
from validate_parameters import is_valid_ipv6
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_port


def main():
    parser = argparse.ArgumentParser(description="Sending SYN message(s) with Destination Header to a target for "
                                                 "checking firewall bypass with options:\n"
                                                 "|> 1x Destination Option with empty padding (insert -c 1).\n"
                                                 "|> 1x Destination Option with hidden data in padding (insert -c 2).\n"
                                                 "|> 3x Destination Option headers (insert -c 3).\n"
                                                 "|> 100x Destination Option headers (insert -c 4).\n"
                                                 "|> 150x Destination Option headers (insert -c 5).\n"
                                                 "|> 200x Destination Option headers (insert -c 6).\n"
                                                 "|> 4x Destination headers + 3x Fragment headers (insert -c 7).\n"
                                                    , formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-sport", dest="source_port", action="store", type=int,
                        help="the port of sender (set to random port if skipping)")
    parser.add_argument("-dport", dest="dest_port", action="store", type=int,
                        help="the port of destination (set to random port if skipping)")
    parser.add_argument('-c', dest="choice", choices=[1, 2, 3, 4, 5, 6, 7], action="store", type=int,
                        help="the option of message to send (sending all types if skipping)")
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
    return args.interface, layer2, layer3, layer4, args.destination_ip, args.choice


def choice1(interface, layer2, layer3, layer4, destination_ip):
    # Generate Destination Option Header with ignore option
    desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    packet1 = layer2 / layer3 / desOption / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending SYN packet: Destination Option Header with ignore option to: ", destination_ip)


def choice2(interface, layer2, layer3, layer4, destination_ip):
    # Generate Destination header with hidden data
    data = Raw(RandString(size=100))
    desOption = IPv6ExtHdrDestOpt(
        options=[PadN(optdata=data)] + [PadN(optdata=data)] + [PadN(optdata=data)] + [PadN(optdata=data)] + [
            PadN(optdata=data)])
    packet1 = layer2 / layer3 / desOption / layer4 / data
    sendp(packet1, verbose=False, iface=interface)
    print("Sending SYN packet: Destination Option Header with hidden data to: ", destination_ip)


def choice3(interface, layer2, layer3, layer4, destination_ip):
    # Generate 3 Destination Option Headers
    desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    for i in range(2):
        desOption = desOption / IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    packet1 = layer2 / layer3 / desOption / layer4
    sendp(packet1, verbose=False, iface=interface)
    print("Sending SYN packet: 3x Destination Option Headers to: ", destination_ip)


def choice4(interface, layer2, layer3, layer4, destination_ip):
    # Generate 100 Destination Option Headers
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    for i in range(99):
        desOption = desOption / IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    packet1 = layer2 / layer3 / desOption / layer4
    sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
    print("Sending SYN packet: 100x Destination Option Headers to: ", destination_ip)


def choice5(interface, layer2, layer3, layer4, destination_ip):
    # Generate 150 Destination Option Headers
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    for i in range(149):
        desOption = desOption / IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    packet1 = layer2 / layer3 / desOption / layer4
    sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
    print("Sending SYN packet: 150x Destination Option Headers to: ", destination_ip)


def choice6(interface, layer2, layer3, layer4, destination_ip):
    # Generate 200 Destination Option Headers
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    desOption = IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    for i in range(199):
        desOption = desOption / IPv6ExtHdrDestOpt(options=[Pad1()] + [Pad1()] + [Pad1()] + [Pad1()] + [Pad1()])
    packet1 = layer2 / layer3 / desOption / layer4
    sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
    print("Sending SYN packet: 200x Destination Option Headers to: ", destination_ip)


def choice7(interface, layer2, layer3, layer4, destination_ip):
    # Generate 4x Destination + 3x Fragmentation
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu
    id = RandShort()
    data = Raw(RandString(size=20))
    options = [PadN(optdata=data)]
    for i in range(2):
        options = options + [PadN(optdata=data)]
    desOption = IPv6ExtHdrDestOpt(options=options) / IPv6ExtHdrDestOpt(options=options) / IPv6ExtHdrDestOpt(options=options) / IPv6ExtHdrDestOpt(options=options)
    fragHdr = IPv6ExtHdrFragment(id=id) / IPv6ExtHdrFragment(id=id + 1) / IPv6ExtHdrFragment(id=id + 2)
    packet1 = layer2 / layer3 / desOption / fragHdr / layer4 / Raw(RandString(size=32))
    sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
    print("Sending SYN packet: 4x Destination Options + 3x Fragment Headers to: ", destination_ip)


if __name__ == "__main__":
    iface, l2, l3, l4, dip, choice = main()
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
            choice7(iface, l2, l3, l4, dip)
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
            choice7(iface, l2, l3, l4, dip)
    except KeyboardInterrupt:
        sys.exit(0)

