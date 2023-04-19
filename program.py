import codecs
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2



salt = get_random_bytes(16)
password = 'mysecretpassword'
key = PBKDF2(password, salt, dkLen=16)

ciphers = AES.new(key, AES.MODE_ECB)

def pad(s):
    padval = 16 - len(s)
    s = bytearray(s)
    return bytes(s + bytes([padval]) * padval)


class PaddingError:
    pass


def unpad(s):
    n = s[-1]
    if n == 0 or len(s) < n or not s.endswith(bytes([n]) * n):
        raise PaddingError
    return s[:-n]
    

def _encrypt(text):
    return ciphers.encrypt(text)



def _decrypt(text):
    deciphertext = ciphers.decrypt(text)
    return deciphertext




def ECBEncryption(plainText, type):
    cipher = bytearray()
    i = 0
    if type == "image":
        cipher = bytearray(plainText[0:54])
        i = 54
    if len(plainText[i:]) < 16:
        line = plainText[i:]
        cipher.extend((_encrypt(pad(line))))
        return cipher
    line = plainText[i:i+16]
    i += 16
    while True:
        cipher.extend(_encrypt(line))
        if len(plainText[i:]) < 16:
            line = plainText[i:]
            cipher.extend(_encrypt(pad(line)))
            return cipher
        line = plainText[i:i+16]
        i += 16

def ECBDecryption(cipher, type):
    decrypted = bytearray()
    i = 0
    if type == "image":
        decrypted = bytearray(cipher[0:54])
        i = 54

    if len(cipher[i:]) < 16:
        line = cipher[i:]
        decrypted.extend(unpad(_decrypt(line)))
        return decrypted
    line = cipher[i:i+16]
    i += 16
    while True:
        line = _decrypt(line)
        if len(cipher[i:]) == 0:
            decrypted.extend(unpad(line))
            return decrypted
        decrypted.extend(line)
        line = cipher[i:i+16]
        i += 16



def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def CBCEncryption(plaintext, iv, type):
    cipher = bytearray()
    i = 0
    if type == "image":
        cipher = bytearray(plaintext[0:54])
        i = 54
    elif type == "text":
        plaintext = plaintext.encode('utf-8')

    if len(plaintext[i:]) < 16:
        line = byte_xor(pad(plaintext[i:]), iv)
        cipher.extend(_encrypt(line))
        return cipher
    line = byte_xor(plaintext[i:i+16], iv)
    i += 16
    tempcipher = _encrypt(line)
    cipher.extend(tempcipher)
    prevline = tempcipher

    if len(plaintext[i:]) < 16:
        line = byte_xor(pad(plaintext[i:]), prevline)
        cipher.extend(_encrypt(line))
        return cipher
    line = plaintext[i:i+16]
    i += 16

    while True:
        line = byte_xor(line, prevline)
        tempcipher = _encrypt(line)
        cipher.extend(tempcipher)
        prevline = tempcipher
        if len(plaintext[i:]) < 16:
            line = byte_xor(pad(plaintext[i:]), prevline)
            cipher.extend(_encrypt(line))
            return cipher
        line = plaintext[i:i+16]
        i += 16


def CBCDecryption(cipher, iv, type):
    decrypted = bytearray()
    i = 0
    if type == "image":
        decrypted = bytearray(cipher[0:54])
        i = 54

    line = cipher[i:i+16]
    i += 16
    prevline = line
    decipher = _decrypt(line)
    if len(cipher[i:]) == 0:
        decrypted.extend(byte_xor(unpad(decipher), iv))
        if type == "text":
            return decrypted.decode('utf-8')
        return decrypted
    decrypted.extend(byte_xor(decipher, iv))
    line = cipher[i:i+16]
    i += 16

    while True:
        decipher = _decrypt(line)
        if len(cipher[i:]) == 0:
            decrypted.extend(unpad(byte_xor(decipher, prevline)))
            if type == "text":
                return decrypted.decode('latin-1')
            return decrypted
        decrypted.extend(byte_xor(decipher, prevline))
        prevline = line
        line = cipher[i:i+16]
        i += 16




def task1():

    file = open('unencryptedImages/mustang.bmp', 'rb')
    newfile1 = open('encryptedECB1.bmp', 'wb')
    newfile2 = open('encryptedCBC1.bmp', 'wb')

    cipheredText1 = ECBEncryption(file.read(), "image")
    file.close()
    file = open('unencryptedImages/mustang.bmp', 'rb')
    iv = get_random_bytes(16)
    cipheredText2 = CBCEncryption(file.read(), iv, "image")
    file.close()

    newfile1.write(cipheredText1)
    newfile2.write(cipheredText2)
    newfile1.close()
    newfile2.close()

    encryptedfile1 = open('encryptedECB1.bmp', 'rb')
    decrypted1 = open('newDecryptECB1.bmp', 'wb')

    unciphered1 = ECBDecryption(encryptedfile1.read(), "image")
    encryptedfile1.close()
    decrypted1.write(unciphered1)
    decrypted1.close()

    encryptedfile2 = open('encryptedCBC1.bmp', 'rb')
    unciphered2 = CBCDecryption(encryptedfile2.read(), iv, "image")
    encryptedfile2.close()
    decrypted2 = open('newDecryptCBC1.bmp', 'wb')
    decrypted2.write(unciphered2)
    decrypted2.close()


task1()


def submit(vector):
    ipt = input('Type in a string: ')
    ipt = ipt.replace(';', '%3B')
    ipt = ipt.replace('=', '%3D')
    plaintext = "userid=456;userdata="+ipt+";session-id=31337"
    ciphered = CBCEncryption(plaintext, vector, "text")
    print(plaintext)
    print(ciphered)
    return ciphered

def verify(cipher, vector):
    print(cipher)
    decrypted = CBCDecryption(cipher, vector, "text")
    print(decrypted)
    if decrypted.find(';admin=true;') != -1:
        return True
    return False

def task2():
    initVec = get_random_bytes(16)
    encryptedURL = submit(initVec)
    hexD = 0x00000000580000000000590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    flippedcipher = hex(int(encryptedURL.hex(), 16) ^ hexD)
    encryptedURL = bytearray(bytes.fromhex(flippedcipher[2:]))
    print(verify(encryptedURL, initVec))

task2()
