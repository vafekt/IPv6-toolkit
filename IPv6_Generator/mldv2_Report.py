#! usr/bin/python
from scapy.layers.inet6 import getmacbyip6, IPv6, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLDMultAddrRec, ICMPv6MLReport2
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp


def mldv2_Report(interface, smac, sip, dip, num_records):
    if smac == "":
        smac = getmacbyip6(sip)
        layer3 = IPv6(src=sip, dst=dip, hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        num_mode = int(input("- Insert the Multicast Address Record types: MODE_IS_INCLUDE (insert 1), "
                             "MODE_IS_EXCLUDE (insert 2), CHANGE_TO_INCLUDE_MODE (insert 3), CHANGE_TO_EXCLUDE_MODE ("
                             "insert 4), ALLOW_NEW_SOURCES (insert 5), BLOCK_OLD_RESOURCES (insert 6): "))
        if num_mode == 1: # MODE_IS_INCLUDE
            if num_records == 0:
                print("MODE_IS_INCLUDE is never sent with an empty record and empty source list.")
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i+1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record (it has to be "
                                                    "non-zero in MODE_IS_INCLUDE): "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j+1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=1, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 2: # MODE_IS_EXCLUDE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=2, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 3: # CHANGE_TO_INCLUDE_MODE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=3, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 4: # CHANGE_TO_EXCLUDE_MODE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=4, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 5: # ALLOW_NEW_SOURCES
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=5, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 6: # BLOCK_OLD_SOURCES
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac)/layer3/HBH/MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=6, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
    else:
        layer3 = IPv6(src=sip, dst=dip, hlim=1)
        HBH = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))
        num_mode = int(input("- Insert the Multicast Address Record types: MODE_IS_INCLUDE (insert 1), "
                             "MODE_IS_EXCLUDE (insert 2), CHANGE_TO_INCLUDE_MODE (insert 3), CHANGE_TO_EXCLUDE_MODE ("
                             "insert 4), ALLOW_NEW_SOURCES (insert 5), BLOCK_OLD_RESOURCES (insert 6): "))
        if num_mode == 1:  # MODE_IS_INCLUDE
            if num_records == 0:
                print("MODE_IS_INCLUDE is never sent with an empty record and empty source list.")
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record (it has to be "
                                                    "non-zero in MODE_IS_INCLUDE): "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=1, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 2:  # MODE_IS_EXCLUDE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=2, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 3:  # CHANGE_TO_INCLUDE_MODE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=3, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 4:  # CHANGE_TO_EXCLUDE_MODE
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=4, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 5:  # ALLOW_NEW_SOURCES
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=5, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
        if num_mode == 6:  # BLOCK_OLD_SOURCES
            if num_records == 0:
                MLD = ICMPv6MLReport2(type=143, records_number=0)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)
            if num_records > 0:
                muladd_records = []
                for i in range(num_records):
                    mulip = input("- Insert the multicast address of the " + str(i + 1) + " record: ")
                    num_records_sources = int(input("- Insert the number of sources in a record: "))
                    sources = []
                    if num_records_sources > 0:
                        for j in range(num_records_sources):
                            element = input("- Insert the " + str(j + 1) + " source: ")
                            sources.append(element)
                    MAR = ICMPv6MLDMultAddrRec(rtype=6, dst=mulip, sources=sources)
                    muladd_records.append(MAR)
                MLD = ICMPv6MLReport2(type=143, records_number=num_records, records=muladd_records)
                packet1 = Ether(src=smac) / layer3 / HBH / MLD
                if interface == "":
                    sendp(packet1, verbose=False)
                else:
                    sendp(packet1, verbose=False, iface=interface)
                print("Sending MLDv2 Report message to address: ", dip)




