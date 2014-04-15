'''
Created on Apr 10, 2014

@author: khazidea99
'''

from socket import *
import sys
import select
from encrypter import *


def main():
    start_server('localhost', 12333)

class bob(object):
    
    def __init__(self, addr, port, debug):
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.server = socket(AF_INET, SOCK_STREAM)
        self._get_keys()

    def start_server(self):
        print("Socket: ", self.server.fileno())
        self.server.bind((self.addr, self.port))
        print("Socket Bound: ", self.server.getsockname())
        print("---------------------------------------------")
        self.server.listen(100)
        input = [self.server]
        
        while 1:
            
            #select sockets for input or output
            inputready,outputready,exceptready = select.select(input, [], [])
    
            for s in inputready:
                if s == self.server:
                        #new connection from server was found
                        print('Handle server socket')
                        connectionSocket, addr = self.server.accept()
                        print("Accepted connection from:", connectionSocket.getpeername())
                        input.append(connectionSocket)
                else:
                        message = ''
                        while 1:
                            message += s.recv(1024)
                            if '\r\n' in message:
                                break
                        
                        print "---RECEIVED:"
                        print message
                        self.send_pub(s)
                        s.close()
                        input.remove(s)
                        
                        print "---SOCKET CLOSED"
    
    def send_pub(self, sock):
        h = hash(self.kb_pub.exportKey())
        sig = sign(h, self.kc_priv)
        #print sig
        to_send = self.kb_pub.exportKey() + sig
        sock.send(to_send)
        sock.send('\r\n')
 
    def _get_keys(self):
        self.kb_pub = load_key('bob.pub')
        self.kb_priv = load_key('bob.priv')
        self.kc_pub = load_key('cert.pub')
        self.kc_priv = load_key('cert.priv')
        self.ka_pub = load_key('alice.pub')
                        
def main(argv):
    debug = False
    if len(argv) > 0:
        if argv[0] == '-iv':
            debug = True
        else:
            print 'Unexpected argument, should be -iv'
            exit()
    s = bob('localhost', 12333, debug)
    s.start_server()


if __name__ == '__main__':
    main(sys.argv[1:])