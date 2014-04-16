'''
Created on Apr 10, 2014

@author: khazidea99
'''
from socket import *
from encrypter import *
from Crypto.PublicKey import RSA
import sys

class alice(object):
    
    def __init__(self, addr, port, debug, key_files=None):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.get_keys(key_files)
    
    def start_client(self):
        self.socket.connect((self.addr, self.port))
        self.ssl_handshake()
        self.send_message()
        print("Close socket")
        self.socket.close()
    
    def ssl_handshake(self):
        self.socket.send('hello\r\n')
        key_str = ''
        #obtain the key from the socket
        while 1:
            key_str += self.socket.recv(1024)
            if '\r\n' in key_str:
                break
        #import the string version into the RSA key
        self.kb_pub = RSA.importKey(key_str[:-130])
        #strip the signed hash from the end
        sig = key_str[-130:-2]
        #validate the signature
        if not verify_sign(self.kb_pub.exportKey(), sig, self.cert_pub):
            print "Certificate failed authentication, ending session"
            s.close()
            exit()
        else:
            print "Certificate validated successfully! Public key obtained"
        
    def send_message(self):
        #obtain the initialization vector
        #self.iv = get_iv()
        self.iv = '01234567'
        print "iv", self.iv, "END"
        self.symm_key = create_sym_key(24)

        #encrypt the key using kb_pub
        h = hash(self.symm_key)
        enc_key = encrypt_RSA(self.kb_pub, self.symm_key, h)

        message = open('message.txt').read()
        #Hash the message
        h = hash(message)
        #sign the hash using Alice's private key
        sig = sign(h, self.alice_priv)
        #encode the signed hash and message
        enc_msg = encrypt_3DES(self.symm_key, self.iv, sig + message)
        print '***Sending***'
        print enc_msg
        self.socket.send(enc_key + self.iv + enc_msg + '\r\n')    
    
    def get_keys(self, key_files):
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