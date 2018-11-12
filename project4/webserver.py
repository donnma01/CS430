"""Python Web server implementation"""
from socket import socket, AF_INET, SOCK_STREAM
from datetime import datetime
import sys

server = socket(AF_INET, SOCK_STREAM)

ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def readFile(filename):
    fl = open(filename, "r")
    s = ""
    for line in fl:
        s += line
    fl.close()
    return s



def server():
    '''Main server loop'''
    with socket(AF_INET,SOCK_STREAM) as s:
        s.bind((ADDRESS, PORT))
        while True:
            s.listen(1)
            logfile = open("webserver.log", "a")
            print('Listening on port {}'.format(PORT))

            #read alice file and send it out
            conn, addr = s.accept()
            with conn:
                print("Connected: {}".format(addr[0]))
                data = conn.recv(1024)
                if len(data) < 1:
                    header = "HTTP/1.1 404 Not Found\r\n\r\n"
                else:
                    request = str(data.decode())
                    time = datetime.now()
                    requestlst = request.strip("\r").split("\n")
                    reqdictlst = requestlst[1:]
                    reqdict = {}
                    for element in reqdictlst:
                        el_list = element.split(":",1)
                        if el_list[0] != "\r" and el_list[0] != "":
                            reqdict[el_list[0]] = el_list[1][1:].strip("\r")
                    rq = requestlst[0]
                    rq = rq[4:len(rq)-10]
                    ip = reqdict["Host"][:len(reqdict["Host"])-5]
                    browser = reqdict["User-Agent"]
                    returnitem =  "{} | {} | {} | {}\n".format(time,rq,ip,browser)
                    logfile.write(returnitem)
                    logfile.close()
                    if requestlst[0][:3] != "GET":
                        header = "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
                    elif requestlst[0][4:len(requestlst[0])-10] != "/alice30.txt":
                        header = "HTTP/1.1 404 Not Found\r\n\r\n"
                    else:
                        alice = readFile("alice30.txt")
                        header = "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\nDate: {}\r\nLast-Modified: Wed Aug 29 11:00:00 2018\r\nServer: CS430-MASON\r\n\r\n{}".format(len(alice),datetime.now(),alice)
                    #print(header)
                conn.sendall(header.encode())
                conn.close()


def main():
    """Main loop"""
    server()


if __name__ == "__main__":
    main()
