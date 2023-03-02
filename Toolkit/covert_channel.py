#!/usr/bin/python3
import random
import sys
from argparse import ArgumentParser
from math import floor

import netifaces
import netifaces as ni
import psutil
from Cryptodome.Cipher import DES, AES
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, HBHOptUnknown, IPv6ExtHdrDestOpt
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.volatile import RandString, RandShort

from validate_parameters import validate_file, is_valid_ipv6, is_valid_mac


def main():
    parser = ArgumentParser(description="Sending a file through Covert channel to a specified target, with option to "
                                        "encrypt (DES-CBC or AES-CBC algorithm) the file.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-i", dest="filename", required=True, type=validate_file,
                        help="input file to send", metavar="FILE")
    parser.add_argument('-k', dest="key", choices=['AES', 'DES'], action="store", help="choose one of two options to "
                                                                                       "encrypt (AES or DES)")
    args = parser.parse_args()

    # Get the content of file
    with open(args.filename, 'rb') as f:
        content = f.read()
        f.close()

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
        args.destination_ip = "ff02::1"
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

    # Validate the encryption
    if args.key == "AES":
        aes = AES.new('This is a key123'.encode("utf8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))
        extra = len(content) % 16
        if extra > 0:
            char = " ".encode("utf-8")
            content = content + (char * (16 - extra))
        content = aes.encrypt(content)
    if args.key == "DES":
        des = DES.new('This key'.encode("utf8"), AES.MODE_CBC, 'This iv '.encode("utf8"))
        extra = len(content) % 8
        if extra > 0:
            char = " ".encode("utf-8")
            content = content + (char * (8 - extra))
        content = des.encrypt(content)

    # Validate the length of content
    stats = psutil.net_if_stats()
    mtu = stats.get(args.interface).mtu
    if len(content) == 0:
        print("---> The file has empty content. Try again!!!")
        sys.exit(1)
    if len(content) <= (mtu-100):
        num_full_packets = 1
    if len(content) > (mtu-100):
        num_full_packets = floor(len(content) / (mtu-100))
    content_parts = [content[i:i + (mtu-100)] for i in range(0, len(content), (mtu-100))]

    # Generate the 1300B packets
    layer2 = Ether(src=args.source_mac)
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip, hlim=128)

    factor_main = int(len(content_parts[0]) / 255)
    data_left_main = len(content_parts[-1]) - factor_main * 255
    for i in range(num_full_packets):
        option1 = HBHOptUnknown(otype=16, optlen=4, optdata=RandString(4))
        num_set = str(i + 1)
        num_set = num_set.ljust(4, '0')
        option2 = HBHOptUnknown(otype=17, optlen=4, optdata=num_set)
        option = [option1, option2]
        index = 0
        for j in range(factor_main):
            option3 = HBHOptUnknown(otype=18 + j, optdata=content_parts[i][index:index + 255])
            index = index + 255
            option.append(option3)
        if data_left_main > 0:
            option3 = HBHOptUnknown(otype=31, optdata=content_parts[i][index:])
            option.append(option3)
        DestOpt = IPv6ExtHdrDestOpt(options=option)
        packet1 = layer2 / layer3 / DestOpt / ICMPv6EchoRequest(id=RandShort(), seq=i + 1)
        sendp(packet1, verbose=False, iface=args.interface)
        print("Sending the Covert Channel message number #" + str(i + 1) + " to the destination: " + args.destination_ip)

    # Generate the last packet
    if num_full_packets > 1:
        factor = int(len(content_parts[-1]) / 255)
        data_left = len(content_parts[-1]) - factor * 255
        option1 = HBHOptUnknown(otype=16, optlen=4, optdata=RandString(4))
        num_set = str(num_full_packets + 1)
        num_set = num_set.ljust(4, '0')
        option2 = HBHOptUnknown(otype=17, optlen=4, optdata=num_set)
        option = [option1, option2]
        index = 0
        if factor == 0:
            option3 = HBHOptUnknown(otype=31, optdata=content_parts[-1])
            option.append(option3)
        else:
            for j in range(factor):
                option3 = HBHOptUnknown(otype=18 + j, optdata=content_parts[-1][index:index + 255])
                index = index + 255
                option.append(option3)
        if data_left > 0:
            option3 = HBHOptUnknown(otype=31, optdata=content_parts[-1][index:])
            option.append(option3)
        DestOpt_Last = IPv6ExtHdrDestOpt(options=option)
        packet1 = layer2 / layer3 / DestOpt_Last / ICMPv6EchoRequest(id=RandShort(), seq=num_full_packets + 1)
        sendp(packet1, verbose=False, iface=args.interface)
        print("Sending the Covert Channel message number #" + str(num_full_packets + 1) + " to the destination: " + args.destination_ip)


if __name__ == "__main__":
    main()
