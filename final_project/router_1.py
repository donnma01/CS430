"""Router implementation using UDP sockets"""
#!/usr/bin/env python3
# encoding: UTF-8


import os
import random
import select
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
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

def val_to_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    reducedvalue = value
    returnlst = []
    for i in range(n_bytes):
        newvalue = reducedvalue & 0xFF
        returnlst.insert(0,newvalue)
        reducedvalue = reducedvalue >> 8
    return returnlst

def read_file(filename: str) -> None:
    """Read config file"""

    lines = [line.rstrip('\n') for line in open(filename,"r")]
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
    update = bytearray(b'\x00')
    for item in ROUTING_TABLE:
        node = item.split(".")
        byte1 = val_to_bytes(int(node[0]),1)
        byte2 = val_to_bytes(int(node[1]),1)
        byte3 = val_to_bytes(int(node[2]),1)
        byte4 = val_to_bytes(int(node[3]),1)
        cost = val_to_bytes(int(ROUTING_TABLE[item][0]),1)
        update.extend(byte1)
        update.extend(byte2)
        update.extend(byte3)
        update.extend(byte4)
        update.extend(cost)
    return update


def parse_update(msg, neigh_addr): #msg is bytes
    """Update routing table"""
    update = False
    for i in range(1,len(msg),5):
        addr = f'{msg[i]}.{msg[i+1]}.{msg[i+2]}.{msg[i+3]}'
        cost = int(msg[i+4])

        if not (addr == THIS_NODE):
            if addr in NEIGHBORS:
                cost_to_neighbor = int(ROUTING_TABLE[neigh_addr][0])
                total_cost = cost_to_neighbor + cost
                if total_cost < int(ROUTING_TABLE[addr][0]):
                    update = True
                    ROUTING_TABLE[addr] = [str(total_cost),neigh_addr]
            if addr not in NEIGHBORS:
                cost_to_neighbor = int(ROUTING_TABLE[neigh_addr][0])
                total_cost = cost_to_neighbor + cost
                if addr not in ROUTING_TABLE:
                    update = True
                    ROUTING_TABLE[addr] = [str(int(ROUTING_TABLE[neigh_addr][0]) +  cost), neigh_addr]
                if addr in ROUTING_TABLE:
                    if total_cost < int(ROUTING_TABLE[addr][0]):
                        update = True
                        ROUTING_TABLE[addr] = [str(int(ROUTING_TABLE[neigh_addr][0]) +  cost), neigh_addr]

    return update


def send_update(node):
    """Send update"""

    client_socket = socket(AF_INET, SOCK_DGRAM) #all will listen on port 4300
    client_socket.bind((THIS_NODE,4300))
    packet = format_update()
    CLIENT_PORT = 4300 + int(node[-1])
    client_socket.sendto(packet,(node,CLIENT_PORT)) #COULD BE WRONG
    client_socket.close()



def format_hello(msg_txt, src_node, dst_node):
    """Format hello message"""

    hello = bytearray(b'\x01')
    src = src_node.split(".")
    dst = dst_node.split(".")
    sbyte1 = val_to_bytes(int(src[0]),1)
    sbyte2 = val_to_bytes(int(src[1]),1)
    sbyte3 = val_to_bytes(int(src[2]),1)
    sbyte4 = val_to_bytes(int(src[3]),1)

    hello.extend(sbyte1)
    hello.extend(sbyte2)
    hello.extend(sbyte3)
    hello.extend(sbyte4)


    dbyte1 = val_to_bytes(int(dst[0]),1)
    dbyte2 = val_to_bytes(int(dst[1]),1)
    dbyte3 = val_to_bytes(int(dst[2]),1)
    dbyte4 = val_to_bytes(int(dst[3]),1)

    hello.extend(dbyte1)
    hello.extend(dbyte2)
    hello.extend(dbyte3)
    hello.extend(dbyte4)


    hello.extend(bytearray(msg_txt,'utf-8'))

    return hello


def parse_hello(msg):
    """Send the message to an appropriate next hop"""

    src_addr = f'{msg[1]}.{msg[2]}.{msg[3]}.{msg[4]}'
    dst_addr = f'{msg[5]}.{msg[6]}.{msg[7]}.{msg[8]}'
    txt = msg[9:].decode()

    if THIS_NODE == dst_addr:
        print('{}| Received {} from {}'.format(datetime.datetime.now().strftime("%H:%M:%S"),txt,src_addr))
    else:
        send_hello(txt, src_addr, dst_addr)


def send_hello(msg_txt, src_node, dst_node):
    """Send a message"""

    hop = ROUTING_TABLE[dst_node][1]
    client_socket = socket(AF_INET, SOCK_DGRAM) #all will listen on port 4300
    client_socket.bind((THIS_NODE,4300))
    CLIENT_PORT = 4300 + int(hop[-1])
    packet = format_hello(msg_txt, src_node, dst_node)
    client_socket.sendto(packet,(hop,CLIENT_PORT))
    client_socket.close()

def print_status():
    """Print status"""
    print("\tHOST\t\tCOST\tVIA")
    for item in ROUTING_TABLE:
        print("\t{}\t{}\t{}".format(item,ROUTING_TABLE[item][0],ROUTING_TABLE[item][1]))


def main(args: list):
    """Router main loop"""
    start_time = datetime.datetime.now().strftime("%H:%M:%S")
    print("{} | Router {} here".format(start_time,THIS_NODE))
    server_socket = socket(AF_INET, SOCK_DGRAM)
    newport = str(4300 + int(THIS_NODE[-1]))
    print("{} | Binding to {}:{}".format(start_time,THIS_NODE,newport))
    server_socket.bind((THIS_NODE,4300 + int(THIS_NODE[-1]))) #port = specific port
    print("{} | Listening to {}:{}".format(start_time,THIS_NODE,newport))
    read_file(args[1])
    print_status()

    for item in NEIGHBORS:
        send_update(item)


    inputs = [server_socket]


    heard_from = {}
    for item in NEIGHBORS:
        heard_from[item] = False

    while len(inputs)>0:
        readable, writable, error = select.select(inputs, [], [], TIMEOUT)
        for sock in readable:
            data, addr = sock.recvfrom(1024)
            heard_from[addr] = True
            if data != None or data != '':
                if data[0] == 0:
                    update = parse_update(data, addr[0])
                    if update:
                        print("{} | Table updated with information from {}".format(datetime.datetime.now().strftime("%H:%M:%S"),addr))
                        print_status()
                        for item in NEIGHBORS:
                            send_update(item)
                if data[0] == 1:
                    parse_hello(data)

        for item in heard_from:
            if heard_from[item] == False:
                send_update(item)

        hello = random.randint(0,100000)
        if hello < 10:
            print("sending hello")
            send_hello(random.choice(MESSAGES), THIS_NODE, random.choice(list(ROUTING_TABLE.keys())))
        resend = random.randint(0,100000)
        if resend < 10:
            print("sending update")
            for ip in NEIGHBORS:
                send_update(ip)

if __name__ == "__main__":
    main(sys.argv)
