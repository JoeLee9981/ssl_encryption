'''
Created on Apr 10, 2014

@author: khazidea99
'''

from socket import *
import sys
import select


def start_server(addr, port):
    server = socket(AF_INET, SOCK_STREAM)
    print("Socket: ", server.fileno())
    server.bind((addr, port))
    print("Socket Bound: ", server.getsockname())
    print("---------------------------------------------")
    server.listen(100)
    input = [server]
    
    while 1:
        
        #select sockets for input or output
        inputready,outputready,exceptready = select.select(input, [], [])

        for s in inputready:
            if s == server:
                    #new connection from server was found
                    print('Handle server socket')
                    connectionSocket, addr = server.accept()
                    print("Accepted connection from:", connectionSocket.getpeername())
                    input.append(connectionSocket)
            else:
                    message = ""
                    data = ""
                    while len(data) != 0:
                        data = s.recv(1024)
                        message += data
                    s.close()
                    input.remove(s)
                    print("---RECEIVED:")
                    print(message)
                    print("---SOCKET CLOSED")


if __name__ == '__main__':
    pass