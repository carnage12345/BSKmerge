import rsa
import hashlib

from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


#  RSA key functions

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


# def generate_keys(letter):
#     (publicKey, privateKey) = rsa.newkeys(1024)  # 1024 - 128 byte key
#     with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
#         f.write(publicKey.save_pkcs1('PEM'))
#     with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
#         f.write(privateKey.save_pkcs1('PEM'))
#
#     print("Keys Generated")
#
#
# def load_keys(letter):
#     with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
#         publicKey = rsa.PublicKey.load_pkcs1(f.read())
#     with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
#         privateKey = rsa.PrivateKey.load_pkcs1(f.read())
#
#     return publicKey, privateKey


class AESCipher:
    def __init__(self, letter):
        self.letter = letter
        self.publicKey = 'nothing',
        self.privateKey = 'nothing',
        self.userFriendlyPassword = 'nothing',
        self.local_key = 'nothing',
        self.cipher = 'nothing'


    def generate_rsa_keys(self):
        self.publicKey, self.privateKey = rsa.newkeys(1024)

    def change_password_and_local_key_and_encrypt_rsa_keys_and_save(self, password):
        self.userFriendlyPassword = password
        self.local_key = hashlib.md5(self.userFriendlyPassword.encode('utf8')).digest()

        publicKeyAsString = self.publicKey.save_pkcs1().decode('utf-8')
        privateKeyAsString = self.privateKey.save_pkcs1().decode('utf-8')

        encryptedPublicKey = self.encrypt_data(publicKeyAsString)
        encryptedPrivateKey = self.encrypt_data(privateKeyAsString)

        with open('Keys' + self.letter + '/PublicKeys/encryptedPublicKey' + self.letter + '.txt', 'wb') as f:
            f.write(encryptedPublicKey)
        with open('Keys' + self.letter + '/PrivateKeys/encryptedPrivateKey' + self.letter + '.txt', 'wb') as f:
            f.write(encryptedPrivateKey)

    def decrypt_rsa_keys_and_return(self):
        with open('Keys' + self.letter + '/PublicKeys/encryptedPublicKey' + self.letter + '.txt', 'rb') as f:
            encryptedPublicKey = f.read().decode('utf-8')
        with open('Keys' + self.letter + '/PrivateKeys/encryptedPrivateKey' + self.letter + '.txt', 'rb') as f:
            encryptedPrivateKey = f.read().decode('utf-8')

        decryptedPublicKey = rsa.PublicKey.load_pkcs1(self.decrypt_data(encryptedPublicKey))
        decryptedPrivateKey = rsa.PrivateKey.load_pkcs1(self.decrypt_data(encryptedPrivateKey))

        return decryptedPublicKey, decryptedPrivateKey

    def check_if_decryption_works(self):
        if (self.publicKey, self.privateKey) == self.decrypt_rsa_keys_and_return():
            return True
        else:
            return False

    def encrypt_data(self, data):
        iv = get_random_bytes(AES.block_size)
        print(iv.__sizeof__())
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size)))

    def decrypt_data(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.local_key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)

    def return_rsa_keys(self):
        return self.publicKey, self.privateKey