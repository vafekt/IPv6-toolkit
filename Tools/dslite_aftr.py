#!/usr/bin/python3

import argparse
import subprocess
import sys
import netifaces

from validate_parameters import add_ipv6_address, get_ipv4_addresses, get_ipv6_addresses, is_valid_ipv4_network, \
    is_valid_ipv6, random_ipv6_addr, is_valid_num


def parameter():
    parser = argparse.ArgumentParser(
        description="|> Setting the current device as AFTR in Dual Stack lite network. It only works with 1 B4. It keeps running and will delete configuration after Keyboard Interrupt.")
    parser.add_argument("-is", dest="if_server", action="store",
                        help="the network interface corresponding to the server network. Error if skipping.")
    parser.add_argument("-it", dest="if_tunnel", action="store",
                        help="the network interface B4 connecting to AFTR (Tunnel). Error if skipping.")
    parser.add_argument("-aftr", dest="aftr_ip", action="store",
                        help="the IPv6 of AFTR. It will resolve from the interface assigned to softwire tunnel if skipping.")
    parser.add_argument("-b4", dest="b4_ip", action="store", help="the IPv6 of B4.")
    parser.add_argument("-net", dest="net_client", action="store",
                        help="the client network in IPv4 for adding manual route to server network. For example: -net 10.0.0.0/24")
    parser.add_argument("-tn", dest="tunnel_name", action="store", help="the name of DS-Lite tunnel. By default it is named ipip6 if skipping.")
    parser.add_argument("-mtu", dest="mtu", action="store",
                        help="the MTU of softwire interface. Set to 1452 if skipping.")
    args = parser.parse_args()

    # Validate the input
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    flag = False

    # Validate the network interface of client
    interface_list = netifaces.interfaces()
    if args.if_server:
        if args.if_server not in interface_list:
            print("---> Network interface corresponding to the server network is inactive or invalid!!!")
            flag = True
        if args.if_server in interface_list:
            if get_ipv4_addresses(args.if_server) is None:
                print("---> No IPv4 address on the interface connecting to server network!!!")

    if not args.if_server:
        print("---> Network interface corresponding to the server network is required!!!")
        flag = True

    # Validate the network interface of tunnel (softwire)
    if args.if_tunnel:
        if args.if_tunnel not in interface_list:
            print("---> Network interface for setting the tunnel is inactive or invalid!!!")
            flag = True
        if args.if_tunnel in interface_list:
            if get_ipv6_addresses(args.if_tunnel) is None:
                print("---> No IPv6 address on the network interface!!!")

    if not args.if_tunnel:
        print("---> Network interface for setting the tunnel is required!!!")
        flag = True

    # Validate the inserted AFTR IPv6 address
    if args.aftr_ip:
        if not is_valid_ipv6(args.aftr_ip):
            print("---> Inserted IPv6 address of AFTR is invalid!!!")
            flag = True
        elif args.if_tunnel in interface_list and args.aftr_ip not in get_ipv6_addresses(args.if_tunnel):
            print("---> Inserted IPv6 address of AFTR does not exist on the interface. So it will be automatically created!!!")
            add_ipv6_address(args.if_tunnel, args.aftr_ip)

    if not args.aftr_ip and args.if_tunnel in interface_list:
        if get_ipv6_addresses(args.if_tunnel) is None:
            print("---> Lacking inserted IPv6 address of AFTR. But no IPv6 address found on the softwire interface. So a random IPv6 address is created!!!")
            args.aftr_ip = random_ipv6_addr("2001:dead::/64")
            add_ipv6_address(args.if_tunnel, args.aftr_ip)
        else:
            args.aftr_ip = sorted(get_ipv6_addresses(args.if_tunnel))[0]
            print(f"IPv6 address of AFTR: {args.aftr_ip} is automatically assigned.")

    # Validate the inserted B4 IPv6 address
    if args.b4_ip:
        if not is_valid_ipv6(args.b4_ip):
            print("---> Inserted IPv6 address of B4 is invalid!!!")
            flag = True

    if not args.b4_ip:
        print("---> IPv6 address of B4 is required!!!")
        flag = True

    # Validate the client network
    if args.net_client:
        if not is_valid_ipv4_network(args.net_client):
            print("---> Inserted IPv4 network of client is invalid!!!")
            flag = True

    if not args.net_client:
        print("---> No manual route is added. This only works if the device allows dynamic routing protocols!!!")
        flag = True

    # Validate the tunnel name
    if not args.tunnel_name:
        args.tunnel_name = "ipip6"

    # Validate the MTU
    if args.mtu:
        if not is_valid_num(args.mtu):
            print("---> Inserted MTU of tunnel is invalid!!!")
            flag = True

    if not args.mtu:
        args.mtu = 1452

    if flag:
        sys.exit(1)

    return args.if_server, args.if_tunnel, args.aftr_ip, args.b4_ip, args.net_client, args.tunnel_name, args.mtu


def check_and_enable_interface(interface):
    try:
        # Check if the interface is up
        result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True, check=True)

        if "state UP" in result.stdout:
            print(f"The interface {interface} is currently up.")
        else:
            # Bring the interface up
            subprocess.run(["sudo", "ip", "link", "set", "dev", interface, "up"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True)
            print(f"The interface {interface} has been brought up.")

        # Show the current status
        subprocess.run(["ip", "link", "show", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)


def enable_traffic_forwarding():
    try:
        # Enable IPv4 traffic forwarding
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True)

        # Enable IPv6 traffic forwarding for all interfaces
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)

        print("Traffic forwarding enabled.")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)


def add_ipv6_tunnel(local_ip, remote_ip, interface, name, mtu):
    try:
        # Add IPv6 tunnel link
        subprocess.run(
            ["ip", "link", "add", "name", name, "mtu", str(mtu), "type", "ip6tnl", "local", local_ip, "remote",
             remote_ip, "mode", "any", "dev", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True)

        print(f"IPv6 tunnel link added successfully.")

    except subprocess.CalledProcessError as e:
        print(f"There might be other links which have same configuration as the given link!!!")
        sys.exit(1)


def del_ipv6_tunnel(local_ip, remote_ip, interface, name, mtu):
    try:
        # Add IPv6 tunnel link
        subprocess.run(
            ["ip", "link", "delete", "name", name, "mtu", str(mtu), "type", "ip6tnl", "local", local_ip, "remote",
             remote_ip, "mode", "any", "dev", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True)

        print(f"IPv6 tunnel link deleted successfully.")

    except subprocess.CalledProcessError as e:
        print(f"There might be some conflict on the given link!!!")
        sys.exit(1)


def add_route(network, interface):
    try:
        # Add route
        subprocess.run(["ip", "route", "add", network, "dev", interface], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)

        print(f"Route {network} added successfully for interface {interface}.")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)


def del_route(network, interface):
    try:
        # Add route
        subprocess.run(["ip", "route", "del", network, "dev", interface], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)

        print(f"Route {network} deleted successfully for interface {interface}.")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)


def check_interface_if_exists(interface_name):
    try:
        result = subprocess.run(["ip", "link", "show", interface_name], check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        return True

    except subprocess.CalledProcessError as e:
        return False


def delete_interface_if_exists(interface_name):
    try:
        # print(f"Interface {interface_name} exists. So it is deleted and new interface is generated.")
        subprocess.run(["ip", "link", "delete", interface_name], check=True)

    except subprocess.CalledProcessError as e:
        pass


def add_iptables_rules(interface):

    # iptables rules for TCP and UDP source port rewriting
    # tcp_rule = f"iptables -t nat -A POSTROUTING -o {interface} -p tcp --sport 1024:65535 -j SNAT --to-source :1024-49151"
    # udp_rule = f"iptables -t nat -A POSTROUTING -o {interface} -p udp --sport 1024:65535 -j SNAT --to-source :1024-49151"
    other_rule = f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE"

    # subprocess.run(tcp_rule, shell=True, check=True)
    # subprocess.run(udp_rule, shell=True, check=True)
    subprocess.run(other_rule, shell=True, check=True)


def del_iptables_rules(interface):

    # iptables rules for TCP and UDP source port rewriting
    # tcp_rule = f"iptables -t nat -D POSTROUTING -o {interface} -p tcp --sport 1024:65535 -j SNAT --to-source :1024-49151"
    # udp_rule = f"iptables -t nat -D POSTROUTING -o {interface} -p udp --sport 1024:65535 -j SNAT --to-source :1024-49151"
    other_rule = f"iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE"

    # subprocess.run(tcp_rule, shell=True, check=True)
    # subprocess.run(udp_rule, shell=True, check=True)
    subprocess.run(other_rule, shell=True, check=True)


# Launching the program

try:
    if_server, if_tunnel, aftr_ip, b4_ip, net_client, tunnel_name, mtu = parameter()

    # Turning all interfaces on
    check_and_enable_interface(if_server)
    check_and_enable_interface(if_tunnel)

    # Checking the existence of tunnel link, adding the link
    if check_interface_if_exists(tunnel_name):
        delete_interface_if_exists(tunnel_name)
    add_ipv6_tunnel(aftr_ip, b4_ip, if_tunnel, tunnel_name, mtu)

    # Turning the interface on
    check_and_enable_interface(tunnel_name)

    # Adding static route to the server
    if net_client:
        add_route(net_client, tunnel_name)

    # Enabling forwarding traffic in IPv4 and IPv6
    enable_traffic_forwarding()

    # Adding NAT rules for translation
    add_iptables_rules(if_server)

    print("The AFTR is configured. Configuration is restored after Keyboard Interrupt....")
    print("..............................................................................")

    while True:
        pass

except KeyboardInterrupt:
     
    # Deleting NAT rules
    del_iptables_rules(if_server)

    # Deleting the route
    if net_client:
        del_route(net_client, tunnel_name)

    # Deleting the tunnel
    if check_interface_if_exists(tunnel_name):
        del_ipv6_tunnel(aftr_ip, b4_ip, if_tunnel, tunnel_name, mtu)

    # Information
    print("Restoring configuration completed.")
    sys.exit(0)
    
    
