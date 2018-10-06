#!/usr/bin/env python3

import sys
from random import randint, choice, seed
from socket import socket, SOCK_DGRAM, AF_INET


PORT = 53

DNS_TYPES = {
    'A': 1,
    'AAAA': 28,
    'CNAME': 5,
    'MX': 15,
    'NS': 2,
    'PTR': 12,
    'TXT': 16
}

PUBLIC_DNS_SERVER = [
    '1.0.0.1',  # Cloudflare
    '1.1.1.1',  # Cloudflare
    '8.8.4.4',  # Google
    '8.8.8.8',  # Google
    '8.26.56.26',  # Comodo
    '8.20.247.20',  # Comodo
    '9.9.9.9',  # Quad9
    '64.6.64.6',  # Verisign
    '208.67.222.222',  # OpenDNS
    '208.67.220.220'  # OpenDNS
]


def val_to_2_bytes(value: int) -> list:
    '''Split a value into 2 bytes'''
    '''Return a list of 2 integers'''
    val_left = value >> 8
    val_right = value & 0xFF
    return[val_left,val_right]

def val_to_n_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    #use loop, extract bits, put into list each time
    #push left 7 times for loop range(n_bytes)
    reducedvalue = value
    returnlst = []
    for i in range(n_bytes):
        newvalue = reducedvalue & 0xFF
        returnlst.insert(0,newvalue)
        reducedvalue = reducedvalue >> 8
    return returnlst

def bytes_to_val(bytes_lst: list) -> int:
    '''Merge 2 bytes into a value'''
    val = 0
    shift = 0
    unshifted = []
    for i in range(len(bytes_lst)-1,-1,-1):
        unshifted.append(bytes_lst[i]<<shift)
        shift+=8
    for i in range(len(unshifted)):
        val += unshifted[i]
    return val

def get_2_bits(bytes_lst: list) -> int:
    '''Extract first two bits of a two-byte sequence'''
    return bytes_lst[0]>>6

def get_offset(bytes_lst: list) -> int:
    '''Extract size of the offset from a two-byte sequence'''
    return((bytes_lst[0] & 0x3f) << 8) + bytes_lst[1]

def parse_cli_query(filename, q_type, q_domain, q_server=None) -> tuple:
    '''Parse command-line query'''
    #print("IN PARSE_CLI_QUERY")
    if q_server == None:
        if q_type == "MX":
            raise ValueError("Unknown query type")
        else:
            return DNS_TYPES[q_type],q_domain.split("."),PUBLIC_DNS_SERVER[randint(0,9)]
    else:
        if q_server not in PUBLIC_DNS_SERVER:
            raise Exception("SERVER TYPE NOT VALID")
        if q_type == "MX":
            raise ValueError("QUERY TYPE NOT VALID")
        else:
            return DNS_TYPES[q_type],q_domain.split("."),q_server

def format_query(q_type: int, q_domain: list) -> bytearray:
    '''Format DNS query'''
    #print("QUERY TYPE", q_type)
    randomnum = randint(0,65535)
    twobytes = val_to_2_bytes(randomnum)
    #print(twobytes)
    thearray = bytearray()
    
    thearray.append(twobytes[0])
    thearray.append(twobytes[1])
    
    #print('{:04x}'.format(bytearray(twobytes)))
    thearray.append(1)
    thearray.append(0)
    thearray.append(0)
    thearray.append(1)
    thearray.append(0)
    thearray.append(0)
    thearray.append(0)
    thearray.append(0)
    thearray.append(0)
    thearray.append(0)
    for domain in q_domain:
        #print(domain)
        #print(len(domain))
        thearray.append(len(domain))
        thearray.extend(bytearray(domain,'utf-8'))
    thearray.append(0)
    thearray.append(0)
    thearray.append(q_type)
    thearray.append(0)
    thearray.append(1)

    return thearray

def send_request(q_message: bytearray, q_server: str) -> bytes:
    '''Contact the server'''
    client_sckt = socket(AF_INET, SOCK_DGRAM)
    client_sckt.sendto(q_message, (q_server, PORT))
    (q_response, _) = client_sckt.recvfrom(2048)
    client_sckt.close()
    
    return q_response

def parse_response(resp_bytes: bytes):
    '''Parse server response'''
    #print("HEADER:")
    header = resp_bytes[0:12]

    num_answers = bytes_to_val(resp_bytes[6:8])
    #print(num_answers)
    domain_ttl_addr = []
    answers = []
    overindex = 12
    enddomain = False

    while(not enddomain):
        place = overindex
        if place == 12:
            while resp_bytes[place]!=0:
                place+=resp_bytes[place] +1
                if resp_bytes[place+1] == 0:
                    enddomain = True
                    overindex = place
    #print("HERE117")
    #print(domain_ttl_addr)
    #print(overindex)
    overindex+=5
    #print(get_2_bits(resp_bytes[overindex:overindex+1])==3)
    return parse_answers(resp_bytes,overindex,num_answers)


def parse_answers(resp_bytes: bytes, offset: int, rr_ans: int) -> list:
    '''Parse DNS server answers'''
    cplace = offset
    oldcplace = offset

    answers = []
    for i in range(rr_ans):
        #cooc = resp_bytes[cplace:cplace+2]
        #print("C00C", cooc)
        domain_name = []
        if get_2_bits(resp_bytes[cplace:cplace+1])==3:
            #print("HERE555")
            #keep track of where the reference was
            oldcplace = cplace
            cplace = get_offset(resp_bytes[cplace:cplace+2])
            #print(cplace)
            dn = []
            while resp_bytes[cplace] != 0:
                for j in range(1,resp_bytes[cplace]+1):
                    domain_chr = chr(bytes_to_val([resp_bytes[cplace+j]]))
                    dn.append(domain_chr)
                cplace += resp_bytes[cplace]+1
                if resp_bytes[cplace+1] != 0:
                    dn.append(".")
            domain_name.append("".join(dn))
            #print(domain_name)
            cplace = oldcplace
            cplace+=2
        else:
            dn = []
            while resp_bytes[cplace] != 0:
                for j in range(1,resp_bytes[cplace]+1):
                    domain_chr = chr(bytes_to_val([resp_bytes[cplace+j]]))
                    dn.append(domain_chr)
                cplace += resp_bytes[cplace]+1
                if resp_bytes[cplace+1] != 0:
                    dn.append(".")   
            domain_name.append("".join(dn))
            #print(domain_name)
            cplace+=2 #skip 0
        tpe = bytes_to_val(resp_bytes[cplace:cplace+2])
        #print("tpe", tpe)
        cplace+=2
        cs = bytes_to_val(resp_bytes[cplace:cplace+2])
        #print("cplace", cs)
        cplace+=2
        ttl = bytes_to_val(resp_bytes[cplace:cplace+4])
        #print("ttl", ttl)
        cplace+=4
        addlen = bytes_to_val(resp_bytes[cplace:cplace+2])
        #print("addlen", addlen)
        cplace+=2        
        #print(tpe ==1)
        if tpe == 1:
            addr = resp_bytes[cplace:cplace+4]
            #print("over there")
            address = parse_address_a(addlen,addr)
            #print(address)
            cplace+=4
        if tpe == 28:
            addr = resp_bytes[cplace:cplace+16]
            #print("RACHEL")
            #print(addlen)
            #print(addr)
            address = parse_address_aaaa(addlen,addr)
            cplace+= 16
        
        answers.append((domain_name[0],ttl,address))
    #print(answers)
    return answers


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


def parse_address_aaaa(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv6 address'''
    '''
    for i in range(addr_len):
        print(str(hex(addr_bytes[i])))
    '''
    addrlst = addr_bytes.hex()
    theaddr = []
    for i in range(0,32,4):
        twobytes = addrlst[i:i+4]
        #if twobytes == '0000':
            #theaddr.append('0')
        while twobytes.startswith('0') and len(twobytes)!=1:
            twobytes = twobytes[1:]
        theaddr.append(twobytes)
        
        
    addans = ':'.join(theaddr)
    return addans

    
def resolve(query: str) -> None:
    '''Resolve the query'''
    #print(bytes_to_val([42]))
    #print(bytes_to_val([6, 145, 94]) == 430430)
    #print(val_to_2_bytes(43043) == [168, 35])
    #print(val_to_n_bytes(430430, 3) == [6, 145, 94])
    #print(get_2_bits([200, 100]) == 3)
    #print(get_offset([200, 100]) == 2148)
    q_type, q_domain, q_server = parse_cli_query(*query[0])
    #print(q_type,q_domain,q_server)
    query_bytes = format_query(q_type, q_domain)
    #print(query_bytes)
    response_bytes = send_request(query_bytes, q_server)
    answers = parse_response(response_bytes)
    print('DNS server used: {}'.format(q_server))
    for a in answers:
        print('Domain: {}'.format(a[0]))
        print('TTL: {}'.format(a[1]))
        print('Address: {}'.format(a[2]))

def main(*query):
    '''Main function'''
    if len(query[0]) < 3 or len(query[0]) > 4:
        print('Proper use: python3 resolver.py <type> <domain> <server>')
        exit()
    resolve(query)


if __name__ == '__main__':
    main(sys.argv)