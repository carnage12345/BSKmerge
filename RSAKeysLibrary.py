import rsa
import hashlib

from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


#  RSA key functions
# --------
# Jaworski
# --------
def generate_keys(letter):
    (publicKey, privateKey) = rsa.newkeys(1024)  # 1024 - 128 byte key
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
        f.write(publicKey.save_pkcs1('PEM'))
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
        f.write(privateKey.save_pkcs1('PEM'))
    print("Keys Generated")


def load_keys(letter):
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
        publicKey = rsa.PublicKey.load_pkcs1(f.read())
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
        privateKey = rsa.PrivateKey.load_pkcs1(f.read())

    return publicKey, privateKey


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def sign_sha1(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')


def verify_sha1(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
    except:
        return False


def encrypt_session_key_with_rsa(session_key, rsa_key):
    return rsa.encrypt(session_key, rsa_key)


def decrypt_session_key_with_rsa(session_key_encoded, rsa_kye):
    try:
        return rsa.decrypt(session_key_encoded, rsa_kye)
    except:
        return False


#  ---------
#  Żebrowski
#  ---------
class AESCipher:
    def __init__(self):
        password = input('Input user-friendly password : ')
        self.local_key = hashlib.md5(password.encode('utf8')).digest()
        self.cipher = 'nothing'

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


def load_encrypted_keys(letter):
    with open('Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.txt', 'r') as f:
        cipheredPublicKey = f.read()
    with open('Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.txt', 'r') as f:
        cipheredPrivateKey = f.read()

    return cipheredPublicKey, cipheredPrivateKey


def encryptRSAKeysAndSave(letter):
    cbc = AESCipher()
    publicKey, privateKey = load_keys(letter)
    cipheredPublicKey = cbc.encrypt(str(publicKey)).decode('utf-8')
    cipheredPrivateKey = cbc.encrypt(str(privateKey)).decode('utf-8')

    with open('Keys' + letter + '/PublicKeys/encryptedPublicKey' + letter + '.txt', 'w') as f:
        f.write(cipheredPublicKey)
    with open('Keys' + letter + '/PrivateKeys/encryptedPrivateKey' + letter + '.txt', 'w') as f:
        f.write(cipheredPrivateKey)


def decryptRSAKeysAndReturn(letter):
    cbc = AESCipher()
    cipheredPublicKey, cipheredPrivateKey = load_encrypted_keys(letter)
    publicKey = cbc.decrypt(cipheredPublicKey).decode('utf-8')
    privateKey = cbc.decrypt(cipheredPrivateKey).decode('utf-8')

    return publicKey, privateKey