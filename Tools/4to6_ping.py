#!/usr/bin/env python3
import argparse
import logging
import multiprocessing
import random
import sys
import threading

import netifaces as ni
import netifaces
import psutil
from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy import all
from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.inet import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast, sndrcvflood, srpflood, sniff
from scapy.supersocket import SuperSocket
from scapy.volatile import RandString, RandShort
from validate_parameters import generate_random_ipv4, is_valid_ipv4, is_valid_ipv6, validate_file, is_valid_port, convert_paramProblem, \
    convert_destUnrechable, convert_timeExceeded
from validate_parameters import is_valid_mac
from validate_parameters import is_valid_num
from validate_parameters import payload


def parameter():
    parser = argparse.ArgumentParser(description="|> Sending 4to6 Ping from given source to given destination (including both IPv4 and IPv6 nodes), with option to flood.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender.")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of IPv6 sender (resolved from the interface if skipping).")
    parser.add_argument("-dmac", dest="destination_mac", action="store",
                        help="the MAC address of IPv6 receiver (resolved from the interface if skipping).")
    parser.add_argument("-sip4", dest="source_ip4", action="store", help="the IPv4 address of sender (0.0.0.0 if skipping).")
    parser.add_argument("-dip4", dest="destination_ip4", action="store", help="the IPv4 address of destination (255.255.255.255 if skipping).")
    parser.add_argument("-sip6", dest="source_ip6", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping).")
    parser.add_argument("-dip6", dest="destination_ip6", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping).")
    parser.add_argument("-hlim", dest="hop_lim", action="store", type=int,
                        help="the hop limit of IPv6 Ping message (255 if skipping).")
    parser.add_argument("-tun_lim", dest="tunnel_encap_lim", action="store", type=int, help="the Tunnel Encapsulation Limit (1 if skipping).")
    parser.add_argument("-n", dest="num_packets", action="store", default=1, type=int,
                        help="the number of packets to send (1 if skipping).")
    parser.add_argument("-l", dest="data_length", type=int, action="store",
                        help="the size of data in bytes (32 if skipping).")
    parser.add_argument("-i", dest="filename", action="store", type=validate_file,
                        help="input file to send (not influenced by parameter -l if being set).", metavar="FILE")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the targets with option: sending Request messages using only the defined "
                             "source addresses (constant), or sending Request messages with many random source "
                             "addresses (random).")
    args = parser.parse_args()

    # Set the flag error
    flag = False

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

    # Validate the source IPv4 address
    if args.source_ip4 is None:
        args.source_ip4 = "0.0.0.0"
    if args.source_ip4 is not None:
        if not is_valid_ipv4(args.source_ip4):
            print("---> The given source IPv4 address is invalid. Try again!!!")
            flag = True

    # Validate the destination IPv4 address
    if args.destination_ip4 is None:
        args.destination_ip4 = "255.255.255.255"
    if args.destination_ip4 is not None:
        if not is_valid_ipv4(args.destination_ip4):
            print("---> The given destination IPv4 address is invalid. Try again!!!")
            flag = True

    # Validate the source IPv6 address
    if args.source_ip6 is None:
        args.source_ip6 = ni.ifaddresses(args.interface)[ni.AF_INET6][0]['addr']
        args.source_ip6 = args.source_ip6.replace("%", '')
        args.source_ip6 = args.source_ip6.replace(args.interface, '')
    if args.source_ip6 is not None:
        if not is_valid_ipv6(args.source_ip6):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            flag = True

    # Validate the destination IPv6 address
    if args.destination_ip6 is None:
        args.destination_ip6 = "ff02::1"
    if args.destination_ip6 is not None:
        if not is_valid_ipv6(args.destination_ip6):
            print("---> The given destination IPv6 address is invalid. Try again!!!")
            flag = True

    # Validate the source MAC address
    if args.source_mac is None:
        args.source_mac = get_if_hwaddr(args.interface)
    if args.source_mac is not None:
        if not is_valid_mac(args.source_mac):
            print("---> The given source MAC address is invalid. Try again!!!")
            flag = True

    # Validate the destination MAC address
    if args.destination_mac is not None:
        if not is_valid_mac(args.destination_mac):
            print("---> The given destination MAC address is invalid. Try again!!!")
            flag = True

    # Validate the tunnel encapsulation limit
    if args.tunnel_encap_lim is None:
        args.tunnel_encap_lim = 1
    if args.tunnel_encap_lim is not None:
        if args.tunnel_encap_lim < 0 or args.tunnel_encap_lim > 255:
            print("---> The given number of tunnel encapsulation limit is invalid. Try again!!!")
            flag = True

    # Validate the hop limit
    if args.hop_lim is None:
        args.hop_lim = 255
    if args.hop_lim is not None:
        if args.hop_lim < 0 or args.hop_lim > 255:
            print("---> The given number of hop limit is invalid. Try again!!!")
            flag = True

    # Validate the number of packets
    if args.num_packets is None:
        args.num_packets = 1
    if args.num_packets is not None:
        if not is_valid_num(args.num_packets):
            print("---> The given number of packets is invalid. Try again!!!")
            flag = True

    # Validate the size of Payload data
    if args.data_length is None:
        args.data_length = 32
    if args.data_length is not None:
        if not is_valid_port(args.data_length):
            print("---> The given size of data is invalid. Try again!!!")
            flag = True
    if args.data_length is not None and args.filename is not None:
        print("---> Sending the data following the file, not related to the data length!!!")

    # Get the content of file
    if args.filename is not None:
        with open(args.filename, 'rb') as f:
            content = f.read()
            f.close()

    data = ''
    if args.filename is None:
        data = payload(args.data_length)
    if args.filename is not None:
        data = content

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Exiting program if error
    if flag:
        sys.exit(1)

    return args.interface, args.source_mac, args.destination_mac, args.source_ip4, args.destination_ip4, args.source_ip6, args.destination_ip6, args.tunnel_encap_lim, args.hop_lim, args.num_packets, data, args.flood


def generate(interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood):
    # Generate the packet
    id = RandShort()
    stats = psutil.net_if_stats()
    mtu = stats.get(interface).mtu

    if destination_mac is None:
        layer2 = Ether(src=source_mac)
    if destination_mac is not None:
        layer2 = Ether(src=source_mac, dst=destination_mac)

    if flood is None:  # Normal situation
        print("Sending 4to6 Ping to the destination: " + destination_ip4)
        for i in range(num_packets):
            if tunnel_encap_lim == 0:
                optdata = '\x00'
            else:
                optdata = tunnel_encap_lim.to_bytes(1, byteorder='big')            
            layer3_IPv6 = IPv6(src=source_ip6, dst=destination_ip6, hlim=hop_lim) / IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optdata=optdata)]+ [PadN(otype=1, optdata='\x00')])
            layer3_IPv4 = IP(src=source_ip4, dst=destination_ip4, id=12345+i, ttl=127) / ICMP(id=id, seq=53+i)/Raw(load=data)
            packet1 = layer2 / layer3_IPv6 / layer3_IPv4
            if len(data) > mtu:  # Fragmentation exists
                sendp(fragment6(packet1, mtu), verbose=False, iface=interface)
            else:
                sendp(packet1, verbose=False, iface=interface)

    if flood is not None:  # Flooding the target
        pkt_list = []
        print("Flooding the destination: " + destination_ip4 + " with PING messages (press Ctrl+C to stop the "
                                                              "attack).....")
        if flood == "constant":
            for i in range(150):
                if tunnel_encap_lim == 0:
                    optdata = '\x00'
                else:
                    optdata = tunnel_encap_lim.to_bytes(1, byteorder='big') 
                layer3_IPv6 = IPv6(src=source_ip6, dst=destination_ip6, hlim=hop_lim) / IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optdata=optdata)]+ [PadN(otype=1, optdata='\x00')])
                layer3_IPv4 = IP(src=source_ip4, dst=destination_ip4, id=12345+i, ttl=127) / ICMP(id=id, seq=53+i)/Raw(load=data)
                packet1 = layer2 / layer3_IPv6 / layer3_IPv4
                if len(data) > mtu:  # Fragmentation exists
                    packet1 = fragment6(packet1, mtu)
                pkt_list.append(packet1)
        if flood == "random":
            for i in range(70):
                if tunnel_encap_lim == 0:
                    optdata = '\x00'
                else:
                    optdata = tunnel_encap_lim.to_bytes(1, byteorder='big')
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                M = 16 ** 4
                source_ip6 = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for j in range(6)))
                source_ip4 = generate_random_ipv4() 
                layer3_IPv6 = IPv6(src=source_ip6, dst=destination_ip6, hlim=hop_lim) / IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optdata=optdata)]+ [PadN(otype=1, optdata='\x00')])
                layer3_IPv4 = IP(src=source_ip4, dst=destination_ip4, id=12345+i, ttl=127) / ICMP(id=id, seq=53+i)/Raw(load=data)
                packet1 = Ether(src=random_mac) / layer3_IPv6 / layer3_IPv4
                if len(data) > mtu:  # Fragmentation exists
                    packet1 = fragment6(packet1, mtu)
                pkt_list.append(packet1)

        def send_packets(packet, iface):
            try:
                sendpfast(packet, mbps=60000, pps=30000, loop=5000000, iface=iface)
            except KeyboardInterrupt:
                pass

        threads = []
        for i in range(4):
            thread = threading.Thread(target=send_packets, args=(pkt_list, interface))
            threads.append(thread)
            thread.start()

        # wait for all threads to complete
        for thread in threads:
            thread.join()


def sniffing(interface, source_ip6, destination_ip6):
    # Define our Custom Action function
    ip_list = []

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if ICMPv6ND_NA not in packet or ICMPv6ND_NS not in packet:
            if ICMPv6EchoReply or IPv6ExtHdrFragment in packet:
                print("===> Received Echo Reply from: " + packet[0][1].src + "\n                     with MAC: " + packet[0].src)
                try:
                    print("     with IPv4 source: " + packet[0][2].src + " and IPv4 destination: " + packet[0][2].dst)
                except:
                    pass
                ip_list.append(packet[0][1].src)
            if ICMPv6ParamProblem in packet:
                print("===> Received Parameter Problem from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                try:
                    print("     with IPv4 source: " + packet[0][2].src + " and IPv4 destination: " + packet[0][2].dst)
                except:
                    pass
                print("     with error: " + convert_paramProblem(packet[ICMPv6ParamProblem].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6DestUnreach in packet:
                print("===> Received Destination Unreachable from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                try:
                    print("     with IPv4 source: " + packet[0][2].src + " and IPv4 destination: " + packet[0][2].dst)
                except:
                    pass
                print("     with error: " + convert_destUnrechable(packet[ICMPv6DestUnreach].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6TimeExceeded in packet:
                print("===> Received Time Exceeded from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                try:
                    print("     with IPv4 source: " + packet[0][2].src + " and IPv4 destination: " + packet[0][2].dst)
                except:
                    pass
                print("     with error: " + convert_timeExceeded(packet[ICMPv6TimeExceeded].code))
                ip_list.append(packet[0][1].src)
            if ICMPv6PacketTooBig in packet:
                print("===> Received Packet Too Big from: " + packet[0][1].src + " with MAC: " + packet[0].src)
                try:
                    print("     with IPv4 source: " + packet[0][2].src + " and IPv4 destination: " + packet[0][2].dst)
                except:
                    pass
                print("     with informed MTU: " + str(packet[ICMPv6PacketTooBig].mtu))
                ip_list.append(packet[0][1].src)
            else:
                pass

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "ip6 dst %s" % source_ip6

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2)
        if len(ip_list) < 1:
            print("===> No response found.")
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_ip6, destination_ip6])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood = parameter()
    if flood is None:
        try:
            execute_functions(interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, destination_mac, source_ip4, destination_ip4, source_ip6, destination_ip6, tunnel_encap_lim, hop_lim, num_packets, data, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
