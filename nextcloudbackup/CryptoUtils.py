from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from io import BytesIO
import struct, os

PBKDF_SALT = b'\xd7\x84\xcd\xcbl39\x98\xca\x92\x97fH\x86\x9e\xa1f\xef\xb9\xee\x8b\xab\xb3N\xd6\xf4\x17\xda\xba\xb6\xbe\xc1'
VERSION = 0

def derive_key(contents, length=16):
    return PBKDF2(contents, PBKDF_SALT, dkLen=length)

def read_struct(input, type):
    return struct.unpack(type, input.read(struct.calcsize(type)))[0]

def encrypt_chunk(aes, chunk):
    if len(chunk) % 16 != 0:
        chunk += b' ' * (16 - len(chunk) % 16)

    return aes.encrypt(chunk)

def encrypt_file(input_filename, output_filename, full_filename, timestamp, key, chunk_size=64*1024):
    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)

    with open(input_filename, 'rb') as input:
        with open(output_filename, 'wb') as output:
            header = b''
            header += struct.pack('<Q', timestamp)
            header += struct.pack('<H', len(full_filename))
            header += full_filename.encode()
            header += struct.pack('<Q', os.path.getsize(input_filename))
            header = encrypt_chunk(aes, header)

            output.write(struct.pack('<B', VERSION))
            output.write(struct.pack('<B', len(iv)))
            output.write(iv)
            output.write(struct.pack('<I', len(header)))
            output.write(header)

            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(encrypt_chunk(aes, chunk))

def decrypt_file(input_filename, output_filename, key, chunk_size=64*1024):
    with open(input_filename, 'rb') as input:
        version = read_struct(input, '<B')

        if version != VERSION:
            raise Exception('Cloud file {0} ({1}) has invalid version.'.format(input_filename, output_filename))

        iv_length = read_struct(input, '<B')
        header_length = read_struct(input, '<I')
        iv = input.read(iv_length)

        aes = AES.new(key, AES.MODE_CBC, iv)

        header = input.read(header_length)
        header = aes.decrypt(header)

        with BytesIO(header) as header:
            timestamp = read_struct(header, '<Q')
            filename_length = read_struct(header, '<H')
            filename = header.read(filename_length).decode()
            original_size = read_struct(header, '<Q')

        with open(output_filename, 'wb') as output:
            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(aes.decrypt(chunk))

            output.truncate(original_size)

        return (filename, timestamp)
