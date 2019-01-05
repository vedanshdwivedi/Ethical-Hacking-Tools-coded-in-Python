#!/usr/bin/env python

import scapy.all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Enter the target IP or the range of IP eg 10.0.2.1 or 10.0.2.1/24")
    (options, arguments) = parser.parse_args()
    if not options.target :
        parser.error("[-] Please enter the target IP/IPs, Use --help for more details.")
    else :
        return options

def print_result(results_list):
    print("   IP\t\t\tMAC Address\n---------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)