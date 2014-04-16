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
        print "\n***STARTING SERVER***"
        print "Socket: ", self.server.fileno()
        self.server.bind((self.addr, self.port))
        print("Socket Bound: ", self.server.getsockname())
        print "---------------------------------------------\n"
        self.server.listen(100)
        input = [self.server]
        
        while 1:
            
            #select sockets for input or output
            inputready,outputready,exceptready = select.select(input, [], [])
    
            for s in inputready:
                if s == self.server:
                        #new connection from server was found
                        print 'Handle server socket'
                        connectionSocket, addr = self.server.accept()
                        print "Accepted connection from:", connectionSocket.getpeername()
                        input.append(connectionSocket)
                        print ''
                else:
                        message = ''
                        while 1:
                            message += s.recv(1024)
                            if '\r\n' in message:
                                break
                            
                        try: 
                            print "***HELLO RECEIVED - BEGINNING HANDSHAKE***\n"
                            print message
                            print ''
                            self.send_pub(s)
                            message = ''
                            while 1:
                                data = s.recv(1024)
                                if len(data) == 0:
                                    break
                                message += data
                            print "***ENCRYPTED MESSAGE RECEIVED***\n"
                            self.decode_message(s, message)
                            s.close()
                            print "Closing socket\n"
                            input.remove(s)
                            print "We are done - waiting for next connection\n"
                        except Exception as ex:
                            print "------ FAILED ------"
                            print ex.args
                            print "Closing socket\n"
                            s.close()
                            input.remove(s)
                        
    def decode_message(self, sock, message):
        #strip off \r\n
        message = message[:-2]
        #strip off encoded symmetric key
        enc_symm = message[:128]
        #strip the IV
        iv = message[128:136]
        #strip remainder of the message
        message = message[136:]
        #decode symm key
        self.symm_key = decrypt_RSA(self.kb_priv, enc_symm)
        if self.debug_enabled:
            print "***DECRYPTING SYMMETRIC KEY***\n"
            print "Encoded key:", enc_symm.encode('hex'), '\n'
            print "IV:", iv.encode('hex'), '\n'
            print "Decoded key:", self.symm_key.encode('hex'), '\n'
            print "Encoded message:"
            print message.encode('hex'), '\n'
        #decode message
        try:
            self.decoder = get_3des_decrypter(self.symm_key, iv)
            message = self.decoder.decrypt(message)
        except:
            raise Exception("An error occurred during decryption - Keys may be corrupted")
        #strip signed hash
        sig = message[:128]
        #strip message
        message = message[128:]
        #verify signature
        if verify_sign(message, sig, self.ka_pub):
            print message
        else:
            sock.close()
            raise Exception("Message signature failed using Alice's public key, closing connnection")
        
    def send_pub(self, sock):
        if self.debug_enabled:
            print "Sending public key\n"
        h = hash(self.kb_pub.exportKey())
        sig = sign(h, self.kc_priv)
        if self.debug_enabled:
            print "Signed hash of the public key:"
            print sig.encode('hex'), '\n'
        to_send = self.kb_pub.exportKey() + sig
        sock.send(to_send)
        sock.send('\r\n')
        if self.debug_enabled:
            print "Key and signature sent on socket:"
            print to_send, '\n'
 
    def _get_keys(self):
        self.kb_pub = load_key('bob.pub')
        self.kb_priv = load_key('bob.priv')
        self.kc_pub = load_key('cert.pub')
        self.kc_priv = load_key('cert.priv')
        self.ka_pub = load_key('alice.pub')
        if self.debug_enabled:
            print "***KEYS LOADED FROM FILE***"
            print "---------Bob's public key:---------"
            print self.kb_pub.exportKey()
            print "---------Bob's private key:---------"
            print self.kb_priv.exportKey()
            print "---------Certificate Authority's public key:---------"
            print self.kc_pub.exportKey()
            print "---------Certificate Authority's private key:---------"
            print self.kc_priv.exportKey()
            print "---------Alice's public key:---------"
            print self.ka_pub.exportKey()
            print ''

def extract_ip(arg):
    if ':' in arg:
        split = arg.split(':')
        if len(split) > 2:
            print "Invalid IP / port combination - use format: (XXX.XXX.XXX.XXX:Port)"
            exit()
        else:
            return split[0], int(split[1])
    else:
        return arg, 12333

def parse_opt(argv):
    debug = False
    ip = None
    port = None
    for i in range(len(argv)):
        if argv[i - 1].upper() == "-IP":
            continue
        if argv[i].upper() == "-IV":
            debug = True
            continue
        if argv[i].upper() == "-IP":
            ip, port = extract_ip(argv[i+1])
            continue
        print "Invalid Argument was entered, should be -IP ip:port(or ip alone), or -IV"
        exit()
    return debug, ip, port
                       
def main(argv):
    debug = False
    ip = None
    port = None
    if len(argv) > 0:
        debug, ip, port = parse_opt(argv)
    if ip == None:    
        ip = 'localhost'
        port = 12333
    try:
        s = bob(ip, port, debug)
        s.start_server()
    except:
        print "An error occurred connecting the server - shutting down"
    s.close()

if __name__ == '__main__':
    main(sys.argv[1:])