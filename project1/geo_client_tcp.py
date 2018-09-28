'''
GEO TCP Client
'''
#!/usr/bin/env python3

import socket
import sys

HOST = 'localhost'
PORT = 4300


def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print('Connected to {}:{}'.format(HOST, PORT))
        ucountry = input("Enter a country or BYE to quit\n")
        while not(ucountry == "BYE"):
            s.sendall(ucountry.encode())
            capital = s.recv(1024).decode()
            if capital == "NA":
                print("-There is no such country")
            else:
                print('+{}'.format(capital))
            ucountry = input("Enter another country to try again or BYE to quit\n")
        s.close()
        print('Connection closed')

def main():
    '''Main function'''
    client()


if __name__ == "__main__":
    main()
