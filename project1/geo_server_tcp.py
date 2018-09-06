'''
GEO TCP Server
'''
#!/usr/bin/env python3

#from socket import socket, AF_INET, SOCK_STREAM
import socket

FILE_NAME = 'geo_world.txt'
HOST = 'localhost'
PORT = 4300


def read_file(filename: str) -> dict:
    '''Read world territories and their capitals from the provided file'''
    worldfile = open(FILE_NAME,"r")
    world = dict()
    for line in worldfile:
        linelst = line.split("-")
        world[linelst[0]] = linelst[1].strip()
    return world


def server(world: dict) -> None:
    '''Main server loop'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print('Listening on port {}'.format(PORT))
        conn, addr = s.accept()
        with conn:
            print('Accepted connection from {}'.format(addr))
            while True:
                data = conn.recv(1024)
                if not data:
                    print('Connection closed')
                    break
                country = str(data.decode())
                print("User query: {}".format(country))
                if country in world:
                    conn.sendall(world[country].encode())
                else:
                    conn.sendall("NA".encode())


def main():
    '''Main function'''
    world = read_file(FILE_NAME)
    #print(world)
    server(world)


if __name__ == "__main__":
    main()
