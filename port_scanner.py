import socket 
import struct

def calc_checksum( msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1] 
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s 
    return s & 0xffff


def build_packet(src_ip,dest_ip,port):

    # IP info
    ver = 4
    ihl = 5
    dscp = 0
    total_length = 20
    identification = 23432
    ip_flags = 0
    fragment_offset = 0
    ttl = 32
    protocol = 6
    header_checksum = 0
    src_ip = src_ip
    dest_ip = dest_ip
    src_addr = socket.inet_aton(src_ip)
    dest_addr = socket.inet_aton(dest_ip)

    # TCP info
    src_port = 8080
    dest_port = port   
    seq_num = 0
    ack_num = 0
    flags = 2
    window_size = 3200
    checksum = 0
    urg_pointer = 0

    
    ip_header = struct.pack("!BBHHHBBH4s4s", (ver << 4) + ihl , dscp, total_length, identification, (ip_flags << 13) + fragment_offset, ttl, protocol, header_checksum, src_addr, dest_addr)
    final_ip_header = struct.pack("!BBHHHBBH4s4s", (ver << 4) + ihl, dscp, total_length,identification, (ip_flags << 13) + fragment_offset, ttl, protocol, calc_checksum(ip_header), src_addr, dest_addr)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port, seq_num, ack_num, 5 << 4, flags, window_size, checksum,urg_pointer)
    pseudo_header = struct.pack("!4s4sBBH", src_addr, dest_addr, checksum, protocol, len(tcp_header))
    pseudo_header_emerged = pseudo_header + tcp_header
    final_tcp_header = struct.pack("!HHIIBBHHH", src_port, dest_port,seq_num,ack_num, 5 << 4, flags, window_size, calc_checksum(pseudo_header_emerged), urg_pointer)
    packet = final_ip_header + final_tcp_header

    return packet



def send_packet(src_address, dst_address, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.settimeout(1.25)
    packet = build_packet(src_address, dst_address, port)
    s.sendto(packet, (dst_address, 0))
    try:
        data = s.recv(4096)
    except:
        data = "filtered"
    s.close()
    return data

src_address = input("Enter your source address: ")
dst_address = input("Enter your destination address: ")

for port in range(1000):
    result = send_packet(src_address, dst_address, port)
    if result == "filtered":
        continue
    tcph = struct.unpack('!HHIIBBHHH',result[20:40])
    flags = tcph[5]
    if flags == 18:
        print("Port "+str(port)+ " is open")

 
