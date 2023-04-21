import socket
import struct
import sys
from helpers import *
import time
import os

input_file_name = sys.argv[1]
if not os.path.exists(input_file_name):
    print("The file to be transferred does not exist")
    sys.exit(1)
SERVER_IP = sys.argv[2]
SERVER_PORT = int(sys.argv[3])
TCP_WINDOW_SIZE = int(sys.argv[4])
if TCP_WINDOW_SIZE != 1024:
    print("TCP_WINDOW_SIZE has to be 1024")
    sys.exit(1) 
CLIENT_PORT = int(sys.argv[5])

TCP_SYN = 0b00000010  # SYN flag
TCP_ACK = 0b00010000  # ACK flag
TCP_FIN = 0b00000001  # FIN flag
TCP_TIMEOUT = 0.2  # TCP timeout
# TCP Header: src_port, dst_port, seq_num, ack_num, data_offset, flags, packet_size, checksum, urgent_ptr
TCP_HEADER_FORMAT = '!HHLLBBHHH'
estimated_rtt = 0

with open(input_file_name, 'rb') as f:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', CLIENT_PORT))
    except socket.error as err:
        print(f"Socket creation failed with error {err}")

    # Get the local address and port of the socket
    local_addr, local_port = sock.getsockname()

    # Connect to the server using a 3-way handshake
    seq_num = 0
    while True:
        # Send SYN packet
        tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, 0, 0, TCP_SYN, TCP_WINDOW_SIZE, 0, 0)
        packet = tcp_header + b'SYN'
        checksum = calculate_checksum(packet)
        tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, 0, 0, TCP_SYN, TCP_WINDOW_SIZE, checksum, 0)
        packet = tcp_header + b'SYN'
        send_time = time.time()
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        print('Sent SYN packet')

        # Receive SYN-ACK packet
        sock.settimeout(TCP_TIMEOUT)
        try:
            packet_recv, server_addr = sock.recvfrom(1024)
            tcp_header = packet_recv[:20]
            flags = tcp_header[13]
            if flags == (TCP_SYN | TCP_ACK):
                receive_time = time.time()
                estimated_rtt = receive_time - send_time
                TCP_TIMEOUT = update_timeout(estimated_rtt, receive_time - send_time)
                print('Received SYN-ACK packet')
                seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
                seq_num += 1
                ack_num = seq_num_recv + 1
                break
            else:
                print('Received unexpected packet')
        except socket.timeout:
            print('Timeout waiting for SYN-ACK packet')
        finally:
            sock.settimeout(None)

    # Send ACK packet
    tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, TCP_ACK, TCP_WINDOW_SIZE, 0, 0)
    packet = tcp_header + b''
    sock.sendto(packet, (SERVER_IP, SERVER_PORT))
    print('Sent ACK packet')

    # Send file
    data_size = TCP_WINDOW_SIZE - 20 
    data = f.read(data_size)
    while data:
        # Send data packet
        tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, 0, TCP_WINDOW_SIZE, 0, 0)
        packet = tcp_header + data
        checksum = calculate_checksum(packet)
        tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, 0, TCP_WINDOW_SIZE, checksum, 0)
        packet = tcp_header + data
        send_time = time.time()
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        print(f'Sent data packet')
        # Wait for ACK packet
        sock.settimeout(TCP_TIMEOUT)
        try:
            packet_recv, server_addr = sock.recvfrom(1024)
            tcp_header = packet_recv[:20]
            flags = tcp_header[13]
            if flags == TCP_ACK:
                receive_time = time.time()
                estimated_rtt = receive_time - send_time
                TCP_TIMEOUT = update_timeout(estimated_rtt, receive_time - send_time)
                print('Received ACK packet')
                seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
                seq_num += 1
                ack_num = seq_num_recv + 1
                data = f.read(data_size)
            else:
                print('Received unexpected packet')
        except socket.timeout:
            print('Timeout waiting for ACK packet')
        finally:
            sock.settimeout(None)
        

# Close the connection using a 3-way handshake
while True:
    # Send FIN packet
    tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, TCP_FIN, TCP_WINDOW_SIZE, 0, 0)
    packet = tcp_header + b''
    checksum = calculate_checksum(packet)
    tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, TCP_FIN, TCP_WINDOW_SIZE, checksum, 0)
    packet = tcp_header + b''
    sock.sendto(packet, (SERVER_IP, SERVER_PORT))
    print('Sent FIN packet')

    # Receive ACK packet
    sock.settimeout(TCP_TIMEOUT)
    try:
        packet_recv, server_addr = sock.recvfrom(1024)
        tcp_header = packet_recv[:20]
        flags = tcp_header[13]
        if flags == (TCP_FIN | TCP_ACK):
            print('Received FIN-ACK packet')
            seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
            seq_num += 1
            ack_num = seq_num_recv + 1
            break
        else:
            print('Received unexpected packet')
    except socket.timeout:
        print('Timeout waiting for ACK packet')
    finally:
        sock.settimeout(None)

# Receive the server's FIN packet
while True:
    # Receive FIN packet
    sock.settimeout(TCP_TIMEOUT)
    try:
        packet_recv, server_addr = sock.recvfrom(1024)
        tcp_header = packet_recv[:20]
        flags = tcp_header[13]
        if flags == TCP_FIN:
            print('Received FIN packet')
            seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
            seq_num += 1
            ack_num = seq_num_recv + 1
            break
        else:
            print('Received unexpected packet')
    except socket.timeout:
        print('Timeout waiting for FIN packet')
    finally:
        sock.settimeout(None)

# Send FIN-ACK packet
tcp_header = struct.pack(TCP_HEADER_FORMAT, local_port, SERVER_PORT, seq_num, ack_num, 0, TCP_FIN | TCP_ACK, TCP_WINDOW_SIZE, 0, 0)
packet = tcp_header + b''
sock.sendto(packet, (SERVER_IP, SERVER_PORT))
print('Sent FIN-ACK packet')

sock.close()


