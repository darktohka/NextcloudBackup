from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import struct, os

PBKDF_SALT = b'\xdem\x96\xb9\xed\xcc\xa3\x9b\xca\xa2\xdc{\xf5\x00\xef\xfc}7\xa6\xf5;\xfb\xf1\x13F\xe6\xef\xb7\xfd\x82\x9f\x81'

def derive_key(contents, length=16):
    return PBKDF2(contents, PBKDF_SALT, dkLen=length)

def encrypt_file(key, input_filename, output_filename, chunk_size=64*1024):
    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)

    with open(input_filename, 'rb') as input:
        with open(output_filename, 'wb') as output:
            output.write(struct.pack('<Q', os.path.getsize(input_filename)))
            output.write(iv)

            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                output.write(aes.encrypt(chunk))

def decrypt_file(key, input_filename, output_filename, chunk_size=64*1024):
    with open(input_filename, 'rb') as input:
        original_size = struct.unpack('<Q', input.read(struct.calcsize('Q')))[0]
        iv = input.read(16)
        aes = AES.new(key, AES.MODE_CBC, iv)

        with open(output_filename, 'wb') as output:
            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(aes.decrypt(chunk))

            output.truncate(original_size)