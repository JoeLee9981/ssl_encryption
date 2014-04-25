'''
PA3 - SSL Encryption
CS4480
Due: 4/26/2014
@author: Joseph Lee
'''

from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as pkcs1_signature
from Crypto.Cipher import PKCS1_v1_5 as pkcs1_cipher

'''
Create the initialization vector
'''
def get_iv():
    return Random.get_random_bytes(8)

'''
Load a key from specified file name
'''
def load_key(filename):
    key = RSA.importKey(open(filename).read())
    return key;

'''
Create a symmetric key  for 3DES n bytes long
'''
def create_sym_key(n):
    return Random.get_random_bytes(n)

'''
Encrypt a mesage into 3DES using a key and init vector
'''
def encrypt_3DES(key, iv, m):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)
    return des3.encrypt(m)

'''
Create a 3DES decrypter object
'''
def get_3des_decrypter(key, iv):
    return DES3.new(key, DES3.MODE_CFB, iv)

'''
Encrypt a message using RSA encryption and a public key
'''
def encrypt_RSA(pub_key, m, h):
    rsa_cipher = pkcs1_cipher.new(pub_key)
    c = rsa_cipher.encrypt(m + h.digest())
    return c

'''
Decrypt a message using RSA encrytpion and a private key
'''
def decrypt_RSA(priv_key, c):
    dig_size = SHA.digest_size
    sentinel = Random.new().read(24+dig_size)
    rsa_cipher = pkcs1_cipher.new(priv_key)
    #verify the digest
    m = rsa_cipher.decrypt(c, sentinel)
    digest = SHA.new(m[:-dig_size]).digest()
    #strip the digest portion and return
    if digest==m[-dig_size:]:
        return m[:-dig_size]
    else:
        return ""

'''
Sign an SHA1 hash using RSA encryption with a private key
'''
def sign(h, priv_key):
    signer = pkcs1_signature.new(priv_key)
    return signer.sign(h)

'''
Verify the signed SHA1 hash using RSA encryption with a public key
'''
def verify_sign(m, sig, pub_key):
    verifier = pkcs1_signature.new(pub_key)
    hash = SHA.new(m)
    return verifier.verify(hash, sig)
 
'''
Obtain the SHA1 hash of a message m
'''
def hash(m):
    hasher = SHA.new()
    hasher.update(m)
    return hasher