from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from io import BytesIO
from .CompressUtils import compress_file, decompress_file
import struct, os, zlib, hashlib

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

def combine_files(input_filenames, output_filename, base_folder, encrypted_folder, file_password, chunk_size=64*1024):
    output_basename = os.path.basename(output_filename)
    key = derive_key(file_password + output_basename, 32)
    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    file_headers = []
    combined_files = {}

    with open(output_filename, 'wb') as output:
        for filename, timestamp in input_filenames.items():
            timestamp = int(timestamp)
            drive_path = os.path.join(base_folder, filename)

            if not os.path.exists(drive_path):
                continue

            file_size = os.path.getsize(drive_path)
            version_hash = hashlib.sha256(filename.encode('utf-8')).hexdigest()
            compressed_path = os.path.join(encrypted_folder, version_hash + '-compressed')

            compress_file(drive_path, compressed_path)
            compressed_size = os.path.getsize(compressed_path)

            if compressed_size > file_size:
                # Looks like the compressed file actually takes up more space than the actual file.
                # Let's remove the compressed file and directly use the actual file.
                os.remove(compressed_path)
                compressed_path = drive_path
                compressed_size = 0

            start_position = output.tell()
            faes = AES.new(key, AES.MODE_CBC, iv)

            with open(compressed_path, 'rb') as input:
                while True:
                    chunk = input.read(chunk_size)

                    if len(chunk) == 0:
                        break

                    output.write(encrypt_chunk(faes, chunk))

            # Only remove compressed file if we are actually using compressed files.
            if compressed_size > 0:
                os.remove(compressed_path)

            end_position = output.tell()
            header = b''
            header += struct.pack('<Q', timestamp)
            header += struct.pack('<H', len(filename))
            header += filename.encode()
            header += struct.pack('<Q', file_size)
            header += struct.pack('<Q', compressed_size)
            header += struct.pack('<Q', start_position)
            header += struct.pack('<Q', end_position)
            file_headers.append(header)
            combined_files[filename] = timestamp

    header = encrypt_chunk(aes, b''.join(file_headers))
    output_header = BytesIO()
    output_header.write(struct.pack('<B', VERSION))
    output_header.write(struct.pack('<B', len(iv)))
    output_header.write(struct.pack('<H', len(file_headers)))
    output_header.write(struct.pack('<I', len(header)))
    output_header.write(iv)
    output_header.write(header)
    output_header.write(struct.pack('<I', output_header.tell() + struct.calcsize('<I')))
    return combined_files, output_header

def read_headers(input_filename, file_password, chunk_size=64*1024):
    key = derive_key(file_password + os.path.basename(input_filename), 32)
    files = {}

    with open(input_filename, 'rb') as input:
        version = read_struct(input, '<B')

        if version != VERSION:
            raise Exception('Cloud file {0} ({1}) has invalid version.'.format(input_filename, output_filename))

        iv_length = read_struct(input, '<B')
        file_count = read_struct(input, '<H')
        header_length = read_struct(input, '<I')
        iv = input.read(iv_length)

        aes = AES.new(key, AES.MODE_CBC, iv)
        header = input.read(header_length)
        header = aes.decrypt(header)

        file_seek = read_struct(input, '<I')

        with BytesIO(header) as header:
            for i in range(file_count):
                timestamp = read_struct(header, '<Q')
                filename_length = read_struct(header, '<H')
                filename = header.read(filename_length).decode()
                original_size = read_struct(header, '<Q')
                compressed_size = read_struct(header, '<Q')
                start_seek = read_struct(header, '<Q')
                end_seek = read_struct(header, '<Q')
                files[filename] = {'time': timestamp, 'size': original_size, 'compressed': compressed_size, 'start_seek': start_seek, 'end_seek': end_seek}

    return {'files': files, 'iv': iv, 'file_seek': file_seek}

def decrypt_files(input_filename, files, file_password, encrypted_folder, base_folder, headers=None, chunk_size=64*1024):
    if not headers:
        headers = read_headers(input_filename, file_password, chunk_size)

    key = derive_key(file_password + os.path.basename(input_filename), 32)
    all_files = headers['files']
    file_seek = headers['file_seek']
    iv = headers['iv']

    with open(input_filename, 'rb') as input:
        for filename in files:
            file = all_files[filename]
            file_length = file['end_seek'] - file['start_seek']
            start_seek = file_seek + file['start_seek']
            compressed = file['compressed'] > 0

            version_hash = hashlib.sha256(filename.encode('utf-8')).hexdigest()
            target_path = os.path.join(base_folder, filename)

            if compressed:
                # The file is compressed, we have to save the compressed version first
                compressed_path = os.path.join(encrypted_folder, version_hash + '-compressed')
            else:
                # The file is not compressed, decrypt directly to target
                compressed_path = target_path

            input.seek(start_seek)

            # Create the directory if necessary
            directory = os.path.dirname(compressed_path)

            if not os.path.exists(directory):
                os.makedirs(directory)

            with open(compressed_path, 'wb') as output:
                aes = AES.new(key, AES.MODE_CBC, iv)

                while True:
                    chunk = input.read(min(chunk_size, file_length))

                    if len(chunk) == 0:
                        break

                    output.write(aes.decrypt(chunk))
                    file_length -= chunk_size

                    if file_length <= 0:
                        break

                # Only truncate to compressed size if the file is actually compressed
                if compressed:
                    output.truncate(file['compressed'])
                else:
                    output.truncate(file['size'])

            if not compressed:
                # This file is not compressed, we can skip the compression part
                continue

            decompress_file(compressed_path, target_path)
            os.remove(compressed_path)

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
