import struct

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum


def check_checksum(packet):
    tcp_header = packet[:20]
    tcp_header_without_checksum = tcp_header[:16] + b'\x00\x00' + tcp_header[18:]
    data = packet[20:]
    tcp_data = tcp_header_without_checksum + data
    checksum = calculate_checksum(tcp_data)
    expected_checksum = struct.unpack('!H', tcp_header[16:18])[0]
    if checksum == expected_checksum:
        print("Checksum Correct")
        return True
    else:
        return False
    

def update_timeout(estimated_rtt, sample_rtt):
    estimated_rtt = estimated_rtt * 0.875 + sample_rtt * 0.125
    dev_rtt = 0.75 * sample_rtt + 0.25 * abs(sample_rtt - estimated_rtt)
    new_timeout = estimated_rtt + 4 * dev_rtt
    print("TIMEOUT value updated to ", new_timeout)
    return new_timeout
