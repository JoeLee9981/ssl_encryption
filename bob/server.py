'''
PA3 - SSL Encryption
CS4480
Due: 4/26/2014
@author: Joseph Lee
'''

from socket import *
import sys
import select
from encrypter import *


'''
Class Bob is to function as a server that performs an SSL handshake using
RSA, 3DES and SHA1.
Bob will bind to the default IP of the machine, or specify the IP in the 
command line.
Use option -v to enable printing of all data
'''
class bob(object):
    '''
    Constructor
    '''
    def __init__(self, addr, port, debug):
        self.addr = addr
        self.port = port
        self.debug_enabled = debug
        self.server = socket(AF_INET, SOCK_STREAM)
        self._get_keys()

    '''
    Start the server and begin waiting for a TCP connection
    '''
    def start_server(self):
        print "\n***STARTING SERVER***"
        print "Socket: ", self.server.fileno()
        self.server.bind((self.addr, self.port))
        print("Socket Bound: ", self.server.getsockname())
        print "---------------------------------------------\n"
        self.server.listen(100)
        input = [self.server]
        
        #Loop through sockets
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
                        #message received from client socket
                        message = ''
                        while 1:
                            message += s.recv(1024)
                            if '\r\n' in message:
                                break
                            
                        try: 
                            print "***HELLO RECEIVED - BEGINNING HANDSHAKE***\n"
                            print '\tFrom Alice:', message
                            print ''
                            #Respond with the public key
                            self.send_pub(s)
                            print ''
                            print '***DONE SENDING BOBS KEY, NOW WAITING FOR MESSAGE***\n'
                            message = ''
                            #Wait for response from client
                            while 1:
                                data = s.recv(1024)
                                if len(data) == 0:
                                    break
                                message += data
                            print "***ENCRYPTED MESSAGE RECEIVED***\n"
                            #Decode encrypted message
                            self.decode_message(s, message)
                            s.close()
                            print "Closing socket\n"
                            input.remove(s)
                            print "We are done - waiting for next connection\n"
                        #Problem has occurred on server, close socke tand remove
                        except Exception as ex:
                            print "------ FAILED ------"
                            print ex.args
                            print "Closing socket\n"
                            s.close()
                            input.remove(s)
    
    '''
    Strips the encoded message and symetric key from the response from Alice's client
    '''            
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
            print "Encoded symmetric key:", enc_symm.encode('hex'), '\n'
            print "IV:", iv.encode('hex'), '\n'
            print "Decoded symmetric key:", self.symm_key.encode('hex'), '\n'
            print "Encoded message from Alice:"
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
            print '***Decrypted message received from Alice in its original form:\n'
            print message
        else:
            sock.close()
            raise Exception("Message signature failed using Alice's public key, closing connnection")
       
    '''
    Send the public key to Alice's client
    ''' 
    def send_pub(self, sock):
        if self.debug_enabled:
            print "Sending Bob's public key to Alice\n"
        #create and sign the hash
        h = hash(self.kb_pub.exportKey())
        sig = sign(h, self.kc_priv)
        if self.debug_enabled:
            print "Signed hash of Bob's public key: (signed using CA private)"
            print sig.encode('hex'), '\n'
        #append the signature to the public key
        to_send = self.kb_pub.exportKey() + sig
        #send the completed message to Alice
        sock.send(to_send)
        sock.send('\r\n')
        if self.debug_enabled:
            print "Bob's public Key and signature sent to Alice (in hex):"
            print to_send.encode('hex'), '\n'
    
    '''
    Load all keys known by Bob at the beginning
    '''
    def _get_keys(self):
        #kb is Bob's keys, both public and private
        self.kb_pub = load_key('bob.pub')
        self.kb_priv = load_key('bob.priv')
        #kc is the certificate authority keys, both public and private
        self.kc_pub = load_key('cert.pub')
        self.kc_priv = load_key('cert.priv')
        #ka is Alice's key, knows only the public
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

'''
Used by parse options to find the IP address specified with -ip
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
Parse options provided by command line argument
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
Main method, parse the options then run the server
'''                    
def main(argv):
    debug = False
    ip = None
    port = None
    if len(argv) > 0:
        debug, ip, port = parse_opt(argv)
    if ip == None:    
        ip = gethostbyname(gethostname())
        port = 12333
    try:
        #star the server
        s = bob(ip, port, debug)
        s.start_server()
    except:
        #problem occurred while connecting / communicating to server
        print "An error occurred connecting the server - shutting down"
    s.close()

if __name__ == '__main__':
    main(sys.argv[1:])