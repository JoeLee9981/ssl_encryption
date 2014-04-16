from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as pkcs1_signature
from Crypto.Cipher import PKCS1_v1_5 as pkcs1_cipher

def get_iv():
    return Random.get_random_bytes(8)

def load_key(filename):
    key = RSA.importKey(open(filename).read())
    return key;

def create_sym_key(n):
    return Random.get_random_bytes(n)

def encrypt_3DES(key, iv, m):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)
    return des3.encrypt(m)

def get_3des_decrypter(key, iv):
    return DES3.new(key, DES3.MODE_CFB, iv)


def encrypt_RSA(pub_key, m, h):
    rsa_cipher = pkcs1_cipher.new(pub_key)
    c = rsa_cipher.encrypt(m + h.digest())
    return c

def decrypt_RSA(priv_key, c):
    dig_size = SHA.digest_size
    sentinel = Random.new().read(24+dig_size)
    rsa_cipher = pkcs1_cipher.new(priv_key)
    
    m = rsa_cipher.decrypt(c, sentinel)
    digest = SHA.new(m[:-dig_size]).digest()
    
    if digest==m[-dig_size:]:
        return m[:-dig_size]
    else:
        return ""

def sign(h, priv_key):
    signer = pkcs1_signature.new(priv_key)
    return signer.sign(h)

def verify_sign(m, sig, pub_key):
    verifier = pkcs1_signature.new(pub_key)
    hash = SHA.new(m)
    return verifier.verify(hash, sig)
 
def hash(m):
    hasher = SHA.new()
    hasher.update(m)
    return hasher