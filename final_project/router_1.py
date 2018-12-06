"""Router implementation using UDP sockets"""
#!/usr/bin/env python3
# encoding: UTF-8


import os
import random
import select
from socket import socket, AF_INET, SOCK_STREAM
import struct
import sys
import datetime

HOST_ID = os.path.splitext(__file__)[0].split("_")[-1]
THIS_NODE = f"127.0.0.{HOST_ID}"
PORT = 4300
NEIGHBORS = set()
ROUTING_TABLE = {}
TIMEOUT = 5
MESSAGES = [
    "Cosmic Cuttlefish",
    "Bionic Beaver",
    "Xenial Xerus",
    "Trusty Tahr",
    "Precise Pangolin"
]

def read_file(filename: str) -> None:
    """Read config file"""

    lines = [line.rstrip('\n') for line in open(filename,"r")]
    #print(lines)
    index = 0
    for i in range(len(lines)):
        if lines[i] == THIS_NODE:
            index = i
    i = index+1
    while i<len(lines) and lines[i] != "":
        addr, cost = lines[i].split(" ")
        NEIGHBORS.add(addr)
        ROUTING_TABLE[addr] = [cost, addr]
        i+=1
    





def format_update():
    """Format update message"""
    raise NotImplementedError


def parse_update(msg, neigh_addr):
    """Update routing table"""
    raise NotImplementedError


def send_update(node):
    """Send update"""


    raise NotImplementedError


def format_hello(msg_txt, src_node, dst_node):
    """Format hello message"""
    raise NotImplementedError


def parse_hello(msg):
    """Send the message to an appropriate next hop"""
    raise NotImplementedError


def send_hello(msg_txt, src_node, dst_node):
    """Send a message"""
    raise NotImplementedError


def print_status():
    """Print status"""
    print("\tHOST\t\tCOST\tVIA")
    for item in ROUTING_TABLE:
        print(f"\t{THIS_NODE}\t{ROUTING_TABLE[item][0]}\t{ROUTING_TABLE[item][1]}")


def main(args: list):
    """Router main loop"""
    start_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{start_time} | Router {THIS_NODE} here")
    udp_socket = socket(AF_INET, SOCK_STREAM)
    print(f"{start_time} | Binding to {THIS_NODE}:{PORT}")
    udp_socket.bind((THIS_NODE,PORT))
    #udp_socket.connect() #send it a tuple of STRING_OF_IP_ADDRESS to connect to and PORT you want to connect to on that IP address. tuple of node and port. Port + int(destination node.split()) destination node is a string of address
    print(f"{start_time} | Listening to {THIS_NODE}:{PORT}")
    #udp_socket.listen(1)
    read_file(args[1])
    print_status()

    #send to neighbors what you know


if __name__ == "__main__":
    main(sys.argv)
