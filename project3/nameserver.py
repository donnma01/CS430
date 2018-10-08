'''
DNS Name Server
'''
#!/usr/bin/env python3

import sys
from random import randint, choice
from socket import socket, SOCK_DGRAM, AF_INET


HOST = "localhost"
PORT = 43054

DNS_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
}

TTL_SEC = {
    '1s': 1,
    '1m': 60,
    '1h': 60*60,
    '1d': 60*60*24,
    '1w': 60*60*24*7,
    '1y': 60*60*24*365
    }


def val_to_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    reducedvalue = value
    returnlst = []
    for i in range(n_bytes):
        newvalue = reducedvalue & 0xFF
        returnlst.insert(0,newvalue)
        reducedvalue = reducedvalue >> 8
    return returnlst


def bytes_to_val(bytes_lst: list) -> int:
    '''Merge n bytes into a value'''
    val = 0
    shift = 0
    unshifted = []
    for i in range(len(bytes_lst)-1,-1,-1):
        unshifted.append(bytes_lst[i]<<shift)
        shift+=8
    for i in range(len(unshifted)):
        val += unshifted[i]
    return val


def get_left_bits(bytes_lst: list, n_bits: int) -> int:
    '''Extract left n bits of a two-byte sequence'''
    val = bytes_to_val(bytes_lst)
    #print(val)
    return val >> 16-n_bits


def get_right_bits(bytes_lst: list, n_bits) -> int:
    '''Extract right n bits of a two-byte sequence'''
    val = bytes_to_val(bytes_lst)
    return val & (2**n_bits)-1


def read_zone_file(filename: str) -> tuple:
    '''Read the zone file and build a dictionary'''
    zone = dict()
    with open(filename) as zone_file:
        origin = zone_file.readline().split()[1].rstrip('.')
        ottl = zone_file.readline().split()[1].rstrip('.')
        zoneline = zone_file.readline()
        domain = ""

        while zoneline != "":
            bzoneline = zoneline.split()
            if len(bzoneline) == 5:
                domain = bzoneline[0]
                ttl = bzoneline[1]
                clas = bzoneline[2]
                typ = bzoneline[3]
                addr = bzoneline[4]
                zone[domain] = [(ttl, clas, typ, addr)]
            if len(bzoneline) == 4 and bzoneline[0].startswith("1"):
                ttl = bzoneline[0]
                clas = bzoneline[1]
                typ = bzoneline[2]
                addr = bzoneline[3]
                zone[domain].append((ttl,clas,typ,addr))
            if len(bzoneline) == 4 and not(bzoneline[0].startswith("1")):
                domain = bzoneline[0]
                clas = bzoneline[1]
                typ = bzoneline[2]
                addr = bzoneline[3]
                zone[domain] = [(ottl,clas,typ,addr)]
            if len(bzoneline) == 3:
                clas = bzoneline[0]
                typ = bzoneline[1]
                addr = bzoneline[2]
                zone[domain].append((ottl,clas,typ,addr))
            zoneline = zone_file.readline()
    
    return (origin, zone)


def parse_request(origin: str, msg_req: bytes) -> tuple:
    '''Parse the request'''
    transid = bytes_to_val(msg_req[0:2])
    print(msg_req[0:2])
    print(transid)
    domain = []
    overindex = 12
    enddomain = False
    novidx = 0
    print(msg_req)



    while not enddomain:
        place = overindex
        if place == 12:
            dn = []
            while msg_req[place]!=0:
                for j in range(1,msg_req[place]+1):
                    domain_chr = chr(bytes_to_val([msg_req[place+j]]))
                    dn.append(domain_chr)
                place+=msg_req[place]+1
                if msg_req[place+1] != 0:
                    dn.append(".")
                if msg_req[place+1] == 0:
                    novidx = place+1 #watch out for this.
                    enddomain = True
            domain.append("".join(dn))
    querytype = bytes_to_val(msg_req[novidx:novidx+2]) #watch out for this.
    query = msg_req[overindex:(novidx+5)]

    if querytype not in DNS_TYPES:
        raise ValueError("Unknown query type")
    if query[len(query)-2:len(query)] != bytearray(b'\x00\x01'):
        raise ValueError("Unknown class")
    if origin != domain[0].replace(domain[0].split(".")[0]+".",''):
        raise ValueError("Unknown zone")

    request = (transid,domain[0].replace(origin,'').strip("."),querytype,query)
    print(request)
    return request


def format_response(zone: dict, trans_id: int, qry_name: str, qry_type: int, qry: bytearray) -> bytearray:
    '''Format the response'''
    response = bytearray()
    transid = val_to_bytes(trans_id,2)
    print(transid)
    response.append(transid[0])
    response.append(transid[1])
    print(response)
    response.extend(bytearray(b'\x81\x00\x00\x01'))
    #number of answers depends on what you find from the zone
    thezone = zone[qry_name]
    print(thezone)
    records = []
    for record in thezone:
        if record[2] == DNS_TYPES[qry_type]:
            records.append(record)
    print(records)
    answerRRs = val_to_bytes(len(records),2)
    response.append(answerRRs[0])
    response.append(answerRRs[1])
    response.extend(bytearray(b'\x00\x00\x00\x00'))
    response.extend(qry)
    for answer in records:
        response.extend(bytearray(b'\xc0\x0c'))
        qrytpe = val_to_bytes(qry_type,2)
        response.append(qrytpe[0])
        response.append(qrytpe[1])
        response.extend(bytearray(b'\x00\x01'))
        ttl = val_to_bytes(TTL_SEC[answer[0]],4)
        response.append(ttl[0])
        response.append(ttl[1])
        response.append(ttl[2])
        response.append(ttl[3])
        if answer[2] == 'A':
            dlen = len(answer[3].split("."))
            dlenans = val_to_bytes(dlen,2)
            response.append(dlenans[0])
            response.append(dlenans[1])
            daddr = answer[3].split(".")
            response.append(int(daddr[0]))
            response.append(int(daddr[1]))
            response.append(int(daddr[2]))
            response.append(int(daddr[3]))

        if answer[2] == 'AAAA':
            dlen = len(answer[3].split(":"))
            dlenans = val_to_bytes(dlen,2)
            response.append(0)
            response.append(16)
            daddr = answer[3].split(":")
            for item in daddr:
                while len(item) < 4:
                    item = "0" + item
                lh = int("0x"+item[0:2],16)
                rh = int("0x"+item[2:],16)
                response.append(lh)
                response.append(rh)


    print(response)
    return response


def run(filename: str) -> None:
    '''Main server loop'''
    server_sckt = socket(AF_INET, SOCK_DGRAM)
    server_sckt.bind((HOST, PORT))
    origin, zone = read_zone_file(filename)
    print("Listening on %s:%d" % (HOST, PORT))

    while True:
        (request_msg, client_addr) = server_sckt.recvfrom(512)
        try:
            trans_id, domain, qry_type, qry = parse_request(origin, request_msg)
            msg_resp = format_response(zone, trans_id, domain, qry_type, qry)
            server_sckt.sendto(msg_resp, client_addr)
        except ValueError as ve:
            print('Ignoring the request: {}'.format(ve))
    server_sckt.close()


def main(*argv):
    '''Main function'''
    if len(argv[0]) != 2:
        print('Proper use: python3 nameserver.py <zone_file>')
        exit()
    run(argv[0][1])


if __name__ == '__main__':
    main(sys.argv)
