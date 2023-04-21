import socket
import struct
import sys
from helpers import *

output_file_name = sys.argv[1]
ip_address_for_acks = sys.argv[3]
port_for_acks = int(sys.argv[4])
SERVER_PORT = int(sys.argv[2])

TCP_SYN = 0b00000010  # SYN flag 
TCP_ACK = 0b00010000  # ACK flag 
TCP_FIN = 0b00000001  # FIN flag
TCP_WINDOW_SIZE = 1024  # TCP packet size
# TCP Header: src_port, dst_port, seq_num, ack_num, data_offset, flags, packet_size, checksum, urgent_ptr
TCP_HEADER_FORMAT = '!HHLLBBHHH'  

# Create socket and bind to port
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', SERVER_PORT))
except socket.error as err:
    print(f"Socket creation failed with error {err}")
print("Listening for incoming UDP packets on port", SERVER_PORT)


seq_num = 0
while True:
    packet_recv, addr = sock.recvfrom(1024)  
    if check_checksum(packet_recv):
        tcp_header = packet_recv[:20]
        flags = tcp_header[13]
        # Receive SYN packet
        if flags == TCP_SYN:
            seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
            print("Received SYN, seq num reveived is " + str(seq_num_recv))
            ack_num = seq_num_recv + 1
            # Send SYN-ACK packet
            tcp_header = struct.pack(TCP_HEADER_FORMAT, SERVER_PORT, addr[1], seq_num, ack_num, 0, TCP_SYN | TCP_ACK, TCP_WINDOW_SIZE, 0, 0)
            packet = tcp_header + b'SYN-ACK'
            sock.sendto(packet, (ip_address_for_acks, port_for_acks))
            print('Sent SYN-ACK packet')

            # Receive data packets
            with open(output_file_name, 'wb') as file:
                while True:
                    packet_recv, addr = sock.recvfrom(1024)
                    if check_checksum(packet_recv):
                        tcp_header = packet_recv[:20]
                        flags = tcp_header[13]
                        if flags == TCP_ACK:
                            print('ACK received. Connection established')
                        else:
                            data = packet_recv[20:]
                            seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
                            if seq_num_recv == ack_num:
                                ack_num = seq_num_recv + 1
                                seq_num += 1
                                print("Received data packet with seq num " + str(seq_num_recv))
                                tcp_header = struct.pack(TCP_HEADER_FORMAT, SERVER_PORT, addr[1], seq_num, ack_num, 0, TCP_ACK, TCP_WINDOW_SIZE, 0, 0)
                                packet = tcp_header + b''
                                sock.sendto(packet, (ip_address_for_acks, port_for_acks))
                                file.write(data)
                                if len(data) < 1004:
                                    break
                                print(f'Received {len(packet_recv)-20} bytes of data and sent ACK packet with ack num ' + str(ack_num))
                            else:
                                print("Received duplicated packets. Dropping the packet")
                    else:
                        print("Checksum for data packet incorrect. Dropping the packet")


                # Close the connection using a 3-way handshake
                while True:
                    packet_recv, addr = sock.recvfrom(1024)
                    if check_checksum(packet_recv):
                        tcp_header = packet_recv[:20]
                        flags = tcp_header[13]
                        if flags == TCP_FIN:
                            print('Received FIN packet')
                            seq_num_recv = struct.unpack('!L', tcp_header[4:8])[0]
                            ack_num = seq_num_recv + 1
                            seq_num += 1
                            # Send ACK packet
                            tcp_header = struct.pack(TCP_HEADER_FORMAT, SERVER_PORT, addr[1], seq_num, ack_num, 0, TCP_FIN | TCP_ACK, TCP_WINDOW_SIZE, 0, 0)
                            packet = tcp_header + b''
                            sock.sendto(packet, (ip_address_for_acks, port_for_acks))
                            print('Sent FIN-ACK packet')

                            # Send FIN packet
                            tcp_header = struct.pack(TCP_HEADER_FORMAT, SERVER_PORT, addr[1], seq_num, ack_num, 0, TCP_FIN, TCP_WINDOW_SIZE, 0, 0)
                            packet = tcp_header + b''
                            sock.sendto(packet, (ip_address_for_acks, port_for_acks))
                            print('Sent FIN packet')

                            # Close the socket
                            sock.close()
                            print('Connection closed. Terminating the program')
                            sys.exit()
                    else:
                        print("Checksum for FIN packet received incorrect")
    else:
        print("Checksum for SYN packet received incorrect")