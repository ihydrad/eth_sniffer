import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

def get_ip(text):
    hex_data = text.hex()
    return f"{int(hex_data[:2], 16)}.{int(hex_data[2:4], 16)}.{int(hex_data[4:6], 16)}.{int(hex_data[6:8], 16)}"


def ipv4_parser(raw_data):
    ip_pocket = {}
    version_header_length = raw_data[0]
    ip_pocket["version"] = version_header_length >> 4
    ip_pocket["header_length"] = (version_header_length & 15) * 4
    ip_pocket["ttl"], ip_pocket["proto"], ip_pocket["src"], ip_pocket["dst"] = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    ip_pocket["src"], ip_pocket["dst"] = get_ip(ip_pocket["src"]), get_ip(ip_pocket["dst"])
    ip_pocket["data"] = raw_data[ip_pocket["header_length"]:]
    return ip_pocket

def ethernet_parser(raw_data):
    eth_frame = {}
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    eth_frame["dst"] = dest.hex()
    eth_frame["src"] = src.hex()
    eth_frame["proto"] = socket.htons(prototype)
    eth_frame["data"] = raw_data[14:]
    return eth_frame


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        if addr[0] == 'lo':
            continue
        frame = ethernet_parser(raw_data)
        print(f'{frame["src"]} -> {frame["dst"]} [{frame["proto"]}]        {addr[0]}') 
        if frame["proto"] == 8:
            ipv4 = ipv4_parser(frame["data"])
            print(f'{ipv4["src"]} -> {ipv4["dst"]} [{ipv4["proto"]}]')
            #print(f'Version:{ipv4["version"]}, Header Length:{ipv4["header_length"]}, TTL:{ipv4["ttl"]}\n')
            

if __name__ == "__main__":
    main()