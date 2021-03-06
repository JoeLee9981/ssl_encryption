'''
PA3 - SSL Encryption
CS4480
Due: 4/26/2014
@author: Joseph Lee
'''

from socket import *
from encrypter import *
from Crypto.PublicKey import RSA
import sys

'''
class Alice is to server as a client for the SSL encryption communication.
Will connect to localhost by default, so specify ip using the -ip option
Use the -v option to display all print statements
'''
class alice(object):
    
    '''
    Constructor
    '''
    def __init__(self, addr, port, debug, key_files=None):
        print ''
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.get_keys(key_files)
    
    '''
    Launch the client, connect to provided IP (or default localhost)
    '''
    def start_client(self):
        self.socket.connect((self.addr, self.port))
        print "***STARTING SSL HANDSHAKE***\n"
        try:
            #Perform the SSL handshake
            self.ssl_handshake()
            if self.debug_enabled:
                print "***GENERATING SYMMETRIC KEY***\n"
            #Send encoded message with the symmetric key
            self.send_message()
            print "Closing socket"
            self.socket.close()
            print "And now we are done with transmission - Have a nice day"
        except Exception as ex:
            #Problem has occurred
            print "Unknown Exception has occurred"
            print ex.args
    
    '''
    Perform the SSL handshake, obtain and decrypt Bob's public key
    '''
    def ssl_handshake(self):
        if self.debug_enabled:
            print "Sending 'hello' and request for public key\n"
        self.socket.send('hello\r\n')
        key_str = ''
        
        #obtain the key from the socket
        if self.debug_enabled:
            print "Waiting for Bob's public key\n"
        while 1:
            key_str += self.socket.recv(1024)
            if '\r\n' in key_str:
                break
        if self.debug_enabled:
            print "Received encoded data from Bob:"
            print key_str.encode('hex')
        #import the string version into the RSA key
        self.kb_pub = RSA.importKey(key_str[:-130])
        #strip the signed hash from the end
        sig = key_str[-130:-2]
        if self.debug_enabled:
            print "\tPublic Key from Bob"
            print self.kb_pub.exportKey()
            print "\tSigned Hash from Bob:"
            print sig.encode('hex'), '\n'
        #validate the signature
        if not verify_sign(self.kb_pub.exportKey(), sig, self.cert_pub):
            print "Certificate failed authentication, ending session"
            self.socket.close()
            exit()
        else:
            print "***Certificate validated successfully! Public key obtained - ENDING HANDSHAKE***\n"
    
    '''
    Generates the symmetric key, encrypts the data and sends it to Bob
    '''
    def send_message(self):
        #obtain the initialization vector
        self.iv = get_iv()
        #generate the symmteric key
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
    
    '''
    Load all keys known in the beginning by Alice
    '''
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

'''
Used by parse options to obtained the provided IP
'''
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

'''
Parse command line arguments provided as options
'''
def parse_opt(argv):
    debug = False
    ip = None
    port = None
    for i in range(len(argv)):
        if argv[i - 1].upper() == "-IP":
            continue
        if argv[i].upper() == "-V":
            debug = True
            continue
        if argv[i].upper() == "-IP":
            ip, port = extract_ip(argv[i+1])
            continue
        print "Invalid Argument was entered, should be -IP ip:port(or ip alone), or -V"
        exit()
    return debug, ip, port

'''
Main method, parse options and launch client to communiate with server
'''      
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
        #connect and start client
        c = alice(ip, port, debug)
        c.start_client()
    except:
        #error occurred with client connection / communication
        print "An error occurred connecting to the server - shutting down"

if __name__ == '__main__':
    main(sys.argv[1:])