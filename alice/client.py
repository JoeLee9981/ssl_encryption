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
        print ''
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.get_keys(key_files)
    
    def start_client(self):
        self.socket.connect((self.addr, self.port))
        print "***STARTING SSL HANDSHAKE***\n"
        try:
            self.ssl_handshake()
            
            if self.debug_enabled:
                print "***GENERATING SYMMETRIC KEY***\n"
            self.send_message()
            print "Closing socket"
            self.socket.close()
            print "And now we are done with transmission - Have a nice day"
        except Exception as ex:
            print "Unknown Exception has occurred"
            print ex.args
    
    def ssl_handshake(self):
        if self.debug_enabled:
            print "Sending 'hello' and request for public key\n"
        self.socket.send('hello\r\n')
        key_str = ''
        
        #obtain the key from the socket
        if self.debug_enabled:
            print "Waiting for public key\n"
        while 1:
            key_str += self.socket.recv(1024)
            if '\r\n' in key_str:
                break
        if self.debug_enabled:
            print "Received encoded data:"
            print key_str.encode('hex')
        #import the string version into the RSA key
        self.kb_pub = RSA.importKey(key_str[:-130])
        #strip the signed hash from the end
        sig = key_str[-130:-2]
        if self.debug_enabled:
            print "\tPublic Key from Bob"
            print self.kb_pub.exportKey()
            print "\tSignature:"
            print sig.encode('hex'), '\n'
        #validate the signature
        if not verify_sign(self.kb_pub.exportKey(), sig, self.cert_pub):
            print "Certificate failed authentication, ending session"
            self.socket.close()
            exit()
        else:
            print "***Certificate validated successfully! Public key obtained - ENDING HANDSHAKE***\n"
        
    def send_message(self):
        #obtain the initialization vector
        self.iv = get_iv()
        self.symm_key = create_sym_key(24)
        if self.debug_enabled:
            print "Symmetric Key: ", self.symm_key.encode('hex'), '\n'
            print "IV:", self.iv.encode('hex'), '\n'
        #encrypt the key using kb_pub
        h = hash(self.symm_key)
        enc_key = encrypt_RSA(self.kb_pub, self.symm_key, h)
        if self.debug_enabled:
            print "Hash Digest of Symm Key:", h.digest().encode('hex'), '\n'
            print "Encrypted Key:", enc_key.encode('hex'), '\n'
        message = open('message.txt').read()
        
        #Hash and sign the message using Alice's priv key
        h = hash(message)
        sig = sign(h, self.alice_priv)
        if self.debug_enabled:
            print "Signed hash of message:", sig.encode('hex'), '\n'
        #encode the signed hash and message
        self.decoder = get_3des_decrypter(self.symm_key, self.iv)
        enc_msg = self.decoder.encrypt(sig + message)
        #send to the socket
        self.socket.send(enc_key + self.iv + enc_msg + '\r\n')
        if self.debug_enabled:
            print "Encrypted message sent:", (enc_key + self.iv + enc_msg).encode('hex'), '\n'
        print "***DONE SENDING****"
    
    def get_keys(self, key_files):
        self.alice_pub = load_key('alice.pub')
        self.alice_priv = load_key('alice.priv')
        self.cert_pub = load_key('cert.pub')
        if self.debug_enabled:
            print "***KEYS LOADED FROM FILE***\n"
            print "---------Alice's public key:---------"
            print self.alice_pub.exportKey()
            print "---------Alice's private key:---------"
            print self.alice_priv.exportKey()
            print "---------Certificate Authority public key:---------"
            print self.cert_pub.exportKey()
            print ''
        
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