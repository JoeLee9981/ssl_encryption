'''
Created on Apr 10, 2014

@author: khazidea99
'''
from socket import *
from encrypter import *
import sys

class alice(object):
    
    def __init__(self, addr, port, debug):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.get_keys()
    
    def start_client(self):
        self.socket.connect((self.addr, self.port))
        self.send_hello()
        self.socket.send('\r\n')
        print("FROM SERVER: ")
        
        message = ''
        while 1:
            message += self.socket.recv(1024)
            if '\r\n' in message:
                break
        print message
        
        print("Close socket")
        self.socket.close()
        
    def send_hello(self):
        self.socket.send('hello\r\n')
        
    def send_message(self):
        message = open('message.txt').read()
        print '***Sending***'
        print message
        self.socket.send(message)      
    
    def get_keys(self):
        self.alice_pub = load_key('alice.pub')
        self.alice_priv = load_key('alice.priv')
        self.cert_pub = load_key('cert.pub')
        if self.debug_enabled:
            print self.alice_pub.exportKey().encode('hex')
            print self.alice_priv.exportKey().encode('hex')
            print self.cert_pub.exportKey().encode('hex')
        
def main(argv):
    debug = False
    if len(argv) > 0:
        if argv[0] == '-iv':
            debug = True
        else:
            print 'Unexpected argument, should be -iv'
            exit()
    c = alice('localhost', 12333, debug)
    c.start_client()

if __name__ == '__main__':
    main(sys.argv[1:])