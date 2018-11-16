"""Python Pinger"""
#!/usr/bin/env python3
# encoding: UTF-8

import binascii
import os
import select
import struct
import sys
import time
import socket
import random
from statistics import mean, stdev

ECHO_REQUEST_TYPE = 8
ECHO_REPLY_TYPE = 0
ECHO_REQUEST_CODE = 0
ECHO_REPLY_CODE = 0
REGISTRARS = ["afrinic.net", "apnic.net", "arin.net", "lacnic.net", "ripe.net"]
# REGISTRARS = ["example.com"]


def print_raw_bytes(pkt: bytes) -> None:
    """Printing the packet bytes"""
    for i in range(len(pkt)):
        sys.stdout.write("{:02x} ".format(pkt[i]))
        if (i + 1) % 16 == 0:
            sys.stdout.write("\n")
        elif (i + 1) % 8 == 0:
            sys.stdout.write("  ")
    sys.stdout.write("\n")


def checksum(pkt: bytes) -> int:
    """Calculate checksum"""
    csum = 0
    count = 0
    count_to = (len(pkt) // 2) * 2

    while count < count_to:
        this_val = (pkt[count + 1]) * 256 + (pkt[count])
        csum = csum + this_val
        csum = csum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(pkt):
        csum = csum + (pkt[len(pkt) - 1])
        csum = csum & 0xFFFFFFFF

    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = csum + (csum >> 16)
    result = ~csum
    result = result & 0xFFFF
    result = result >> 8 | (result << 8 & 0xFF00)

    return result



def parse_address_a(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv4 addressd'''
    IPstring = ""
    for i in range(addr_len):
        if i == (addr_len)-1:
            IPstring+=str(addr_bytes[i])
        else:
            IPstring += str(addr_bytes[i]) + "."
    #print(IPstring)
    return IPstring

def parse_reply(
    my_socket: socket.socket, req_id: int, timeout: int, addr_dst: str
) -> tuple:
    """Receive an Echo reply"""
    #print("HERE1")
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if what_ready[0] == []:  # Timeout
            raise TimeoutError("Request timed out after 1 sec")
        time_rcvd = time.time()
        rtt = (time_rcvd - started_select) * 1000
        pkt_rcvd, addr = my_socket.recvfrom(1024)
        if addr[0] != addr_dst:
            raise ValueError(f"Wrong sender: {addr[0]}")
        # Extract ICMP header from the IP packet and parse it
        plen = len(pkt_rcvd)
        ICMP_Header = pkt_rcvd[20:36]
        ICMP_Header_NoChecksum = list(ICMP_Header)
        ICMP_Header_NoChecksum[2] = 0
        ICMP_Header_NoChecksum[3] = 0
        ICMP_Header_NoChecksum = bytes(ICMP_Header_NoChecksum)
        cksum_new = hex(checksum(ICMP_Header_NoChecksum))[2:]
        cksum_rec = ICMP_Header[2:4].hex()
        msg_typ = ICMP_Header[0:1].hex()
        msg_code = ICMP_Header[1:2].hex()

        zero_hex = hex(0) + '0'

        if msg_typ != zero_hex[2:]:
            raise ValueError("Wrong message type")
        if msg_code != zero_hex[2:]:
            raise ValueError("Wrong code type")
        if cksum_rec != cksum_new:
            raise ValueError("Incorrect checksum")

        destination = parse_address_a(len(pkt_rcvd[12:16]), pkt_rcvd[12:16])
        ttl = int(pkt_rcvd[8:9].hex(),16)
        seq_num = int(ICMP_Header[6:8].hex(),16)//256
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            raise TimeoutError("Request timed out after 1 sec")
        return (destination, plen, round(rtt,2), ttl, seq_num)


def format_request(req_id: int, seq_num: int) -> bytes:
    """Format an Echo request"""
    my_checksum = 0
    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    if sys.platform == "darwin":
        my_checksum = socket.htons(my_checksum) & 0xFFFF #what does htons do?
    else:
        my_checksum = socket.htons(my_checksum) 

    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    packet = header + data
    return packet


def send_request(addr_dst: str, seq_num: int, timeout: int = 1) -> tuple:
    """Send an Echo Request"""
    result = None
    proto = socket.getprotobyname("icmp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    my_id = os.getpid() & 0xFFFF

    packet = format_request(my_id, seq_num)
    my_socket.sendto(packet, (addr_dst, 1))

    try:
        result = parse_reply(my_socket, my_id, timeout, addr_dst)
    except ValueError as ve:
        print(f"Packet error: {ve}")
    finally:
        my_socket.close()
    return result


def ping(host: str, pkts: int, timeout: int = 1) -> None:
    """Main loop"""

    #convert host to IP here and then pass it to everything else?
    received = 0
    ip = socket.gethostbyname(host)
    timelist = []
    print("\n--- Ping {} ({}) using Python ---\n".format(host,ip))
    for i in range(1,pkts+1):
        try:
            req = send_request(ip,i)
            print("{} bytes from {}: icmp_seq={} TTL={} time={} ms".format(req[1], req[0], req[4], req[3], req[2]))
            received += 1
            timelist.append(req[2])

        except TimeoutError:
            print("No response: Request timed out after 1 sec")
        except:
            pass

    print("\n--- {} ping statistics ---".format(host))
    print("{} packets transmitted, {} received, {}% packet loss".format(pkts, received, ((pkts-received)/pkts)*100))
    if timelist != []:
        print("rtt min/avg/max/mdev = {}/{}/{}/{} ms".format(min(timelist), round(mean(timelist),2), max(timelist), round(stdev(timelist),2)))
        
    return


if __name__ == "__main__":
    for rir in REGISTRARS:
        ping(rir, 5)

