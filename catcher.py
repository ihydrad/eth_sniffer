import socket
import struct
import subprocess
import threading
import argparse
from ipaddress import ip_address
from time import sleep
import sys

ETH_P_ALL = 3
ETH_P_IP = 0x800
ETH_P_ARP = 0x806
active = True

def get_ip(text):
    hex_data = text.hex()
    return f"{int(hex_data[:2], 16)}.{int(hex_data[2:4], 16)}.{int(hex_data[4:6], 16)}.{int(hex_data[6:8], 16)}"

def ethernet_parser(raw_data):
    eth_frame = {}
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    eth_frame["dst"] = dest.hex()
    eth_frame["src"] = src.hex()
    eth_frame["proto"] = prototype #socket.htons(prototype)
    eth_frame["data"] = raw_data[14:]
    return eth_frame

def ipv4_parser(raw_data):
    ip_pocket = {}
    version_header_length = raw_data[0]
    ip_pocket["version"] = version_header_length >> 4
    ip_pocket["header_length"] = (version_header_length & 15) * 4
    ip_pocket["ttl"], ip_pocket["proto"], ip_pocket["src"], ip_pocket["dst"] = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    ip_pocket["src"], ip_pocket["dst"] = get_ip(ip_pocket["src"]), get_ip(ip_pocket["dst"])
    ip_pocket["data"] = raw_data[ip_pocket["header_length"]:]
    return ip_pocket

def arp_parser(raw_data):
    pass

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        if addr[0] == 'lo':
            continue
        frame = ethernet_parser(raw_data)
        if frame["proto"] == ETH_P_ARP:
            print(f'{frame["src"]} -> {frame["dst"]} [{hex(frame["proto"])}]        {addr[0]}') 
        # if frame["proto"] == 8:
        #     ipv4 = ipv4_parser(frame["data"])
        #     print(f'{ipv4["src"]} -> {ipv4["dst"]} [{ipv4["proto"]}]')
        #     #print(f'Version:{ipv4["version"]}, Header Length:{ipv4["header_length"]}, TTL:{ipv4["ttl"]}\n')
            
def catch_frame(addr):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    while active:
        raw_data, iface = s.recvfrom(65535)
        if iface[0] == 'lo':
            continue
        frame = ethernet_parser(raw_data)        
        if frame["proto"] == ETH_P_IP:
            ipv4 = ipv4_parser(frame["data"])
            if ipv4["dst"] == addr:
                return print(f"Pocket with dst addr {addr} catched on {iface[0]}") 
        if frame["proto"] == ETH_P_ARP:
            arp = arp_parser(frame["data"])
            if arp["dst"] == addr:
                return print(f"Pocket with dst addr {addr} catched on {iface[0]}") 

def generate(addr, method):
    if method == "icmp":
        subprocess.call(f"ping -c 1 {addr} > /dev/null", shell=True)
    else:
        raise NotImplementedError

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", help="destination")
    parser.add_argument("-m", dest="method", help="destination", default="icmp")
    args = parser.parse_args()
    try:
        ip_address(args.addr)
    except ValueError:
        print("Input correct ip-address!")
        sys.exit(1)
    catcher = threading.Thread(target=catch_frame, args=(args.addr,))
    catcher.start()
    try:
        generate(args.addr, args.method)
        sleep(3)
    except NotImplementedError:
        active = False
        print("Not Implemented")
    