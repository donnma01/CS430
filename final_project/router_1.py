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
    update = bytearray(b'\x00')
    for item in NEIGHBORS:
        neighbor = item.split(".")
        byte1 = val_to_bytes(int(neighbor[0]),1)
        #print(byte1)
        #print(type(bytes(byte1[0])))
        byte2 = val_to_bytes(int(neighbor[1]),1)
        byte3 = val_to_bytes(int(neighbor[2]),1)
        byte4 = val_to_bytes(int(neighbor[3]),1)
        #print(neighbor[3])
        cost = val_to_bytes(int(ROUTING_TABLE[item][0]),1)
        #print(cost)
        update.extend(byte1)
        update.extend(byte2)
        update.extend(byte3)
        update.extend(byte4)
        update.extend(cost)
        #print(update)
    print(update)
    return update


def parse_update(msg, neigh_addr): #msg is bytes
    """Update routing table"""
    update = False
    for i in range(1,len(msg),5):
        addr = f'{msg[i]}.{msg[i+1]}.{msg[i+2]}.{msg[i+3]}'
        cost = msg[i+4]

        print(addr,cost)
        if not (addr == THIS_NODE):
            if addr in NEIGHBORS:
                cost_to_neighbor = cost + int(ROUTING_TABLE[neigh_addr][0])
                if cost_to_neighbor < int(ROUTING_TABLE[addr][0]):
                    update = True
                    ROUTING_TABLE[addr] = [str(cost_to_neighbor),neigh_addr]
            if addr not in NEIGHBORS:
                if addr not in ROUTING_TABLE:
                    update = True
                    ROUTING_TABLE[addr] = [str(ROUTING_TABLE[neigh_addr][0] +  cost), neigh_addr]
                else:
                    if (int(ROUTING_TABLE[neigh_addr][0]) + cost) < ROUTING_TABLE[addr][0]:
                        update = True
                        ROUTING_TABLE[addr] = [ROUTING_TABLE[neigh_addr][0] +  cost, neigh_addr]

    return update



def send_update(node):
    """Send update"""






    raise NotImplementedError


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

    print(hello)

    #hello.extend(text)



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
        print(f"\t{item}\t{ROUTING_TABLE[item][0]}\t{ROUTING_TABLE[item][1]}")


def main(args: list):
    """Router main loop"""
    start_time = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{start_time} | Router {THIS_NODE} here")
    udp_socket = socket(AF_INET, SOCK_DGRAM)
    print(f"{start_time} | Binding to {THIS_NODE}:{PORT}")
    udp_socket.bind((THIS_NODE,PORT))
    #udp_socket.listen(4)
    print(f"{start_time} | Listening to {THIS_NODE}:{PORT}")
    read_file(args[1])
    print_status()
    #neighbors = select(NEIGHBORS.keys(),NEIGHBORS.keys(),NEIGHBORS.keys())

    format_update()

    #format_hello(MESSAGES[random.randint(0,len(MESSAGES))],THIS_NODE,'127.0.0.2')
    sample_msg = bytearray(b'\x00\x7f\x00\x00\x03\x01\x7f\x00\x00\x01\x01')
    parse_update(sample_msg, '127.0.0.2')
    print_status()





    #send to neighbors what you know

    # inputs = [udp_socket]
    # outputs = []
    # messages = []

    # while True:
    #     receive, send, error = select.select(inputs, outputs, inputs)
    #     for sock in receive:
    #         pass 
    #     for sock in send:
    #         pass
    #     for sock in error:
    #         pass


#CLIENT

    # listener = []
    # for item in NEIGHBORS:
    #     client_sckt = socket(AF_INET,SOCK_DGRAM)
    #     client_sckt.connect((ROUTING))


# def send_request(q_message: bytearray, q_server: str) -> bytes:
#     '''Contact the server'''
#     client_sckt = socket(AF_INET, SOCK_DGRAM)
#     client_sckt.connect((HOST,PORT))
#     client_sckt.sendto(q_message, (HOST, PORT))
#     (q_response, _) = client_sckt.recvfrom(2048)
#     client_sckt.close()

#SERVER
# def run(filename: str) -> None:
#     '''Main server loop'''
#     server_sckt = socket(AF_INET, SOCK_DGRAM)
#     server_sckt.bind((HOST, PORT))
#     origin, zone = read_zone_file(filename)
#     print("Listening on %s:%d" % (HOST, PORT))

#     while True:
#         (request_msg, client_addr) = server_sckt.recvfrom(512)
#         try:
#             trans_id, domain, qry_type, qry = parse_request(origin, request_msg)
#             msg_resp = format_response(zone, trans_id, domain, qry_type, qry)
#             server_sckt.sendto(msg_resp, client_addr)
#         except ValueError as ve:
#             print('Ignoring the request: {}'.format(ve))
#     server_sckt.close()

if __name__ == "__main__":
    main(sys.argv)
