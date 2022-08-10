import socket
import struct
import scapy.all as scapy
import textwrap
import processBD as bd
from scapy.compat import bytes_hex
from scapy.layers import http
from scapy.layers.dot11 import Dot11
from scapy.layers.tls.record import TLS
from scapy.main import load_layer

num = 0

def process_sniffer(package):
    serviceBD = bd.ServiceBD
    if package.haslayer(scapy.Ether):
        #распакуем ethernet frame
        dest_mac, src_mac, eth_type,data = unpack_ethernet_frame(package[scapy.Ether].build())
        print("\nEthernet Frame:\n")
        serviceBD.insert_ethernet_frame(tuple(dest_mac, src_mac, eth_type))
        if eth_type == 8:
            version, len_head, ttl, proto, src, target, data = ipv4_package(data)
            serviceBD.insert_ipv4((version, len_head, ttl, proto, src, target, data))
            if proto == 1:
                type_icmp, code, checksum = icmp_package(data)
                serviceBD.insert_icmp((type_icmp, code, checksum,data))
            #TCP
            if proto == 6:
                source_port, dest_port, sequence, acknowledgement, fl_ack, fl_fin, fl_syn, fl_psh, fl_urg, fl_rst, data = tcp_package(data)
                serviceBD.insert_tcp(source_port, dest_port, sequence, acknowledgement, fl_ack, fl_fin, fl_syn, fl_psh, fl_urg, fl_rst, data)
            #UDP
            if proto == 17:
                source_port, dest_port, size, data = udp_package(data)
                serviceBD.insert_udp(source_port, dest_port, size, data)
            #other
            else:
                serviceBD.insert_other(data)

def unpack_ethernet_frame(ether_frame):
    dest_mac, src_mac, eth_type = struct.unpack('! 6s 6s H',ether_frame[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_type), ether_frame[14:]

def get_mac_addr(addr):
    num_mac_addr = map('{:02x}'.format, addr)
    mac_addr = ':'.join(num_mac_addr).upper()
    return mac_addr

def ipv4_package(data):
    len_version = data[0]
    version = len_version >> 4
    len_head = (len_version & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version, len_head, ttl, proto, ipv4(src), ipv4(target), data[len_head:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_package(data):
    type_icmp, code, checksum = struct.unpack('! B B H',data[:4])
    return type_icmp, code, checksum

def tcp_package(data):
    source_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    fl_urg = (offset_reserved_flags & 32) >> 5
    fl_ack = (offset_reserved_flags & 16) >> 4
    fl_psh = (offset_reserved_flags & 8) >> 3
    fl_rst = (offset_reserved_flags & 4) >> 2
    fl_syn = (offset_reserved_flags & 2) >> 1
    fl_fin = offset_reserved_flags & 1
    return source_port, dest_port, sequence, acknowledgement, fl_ack, fl_fin, fl_syn, fl_psh, fl_urg, fl_rst, data[offset:]

def udp_package(data):
    source_port, dest_port, size = struct.unpack('! H H 2x H',data[:8])
    return source_port, dest_port, size, data[8:]

def form_multiline(prefix, string, size = 80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])
