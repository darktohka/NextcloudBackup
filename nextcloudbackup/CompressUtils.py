import fnmatch, zlib, io, os

def check_patterns(file, patterns):
    if not patterns:
        return False

    for pattern in patterns:
        if fnmatch.fnmatch(file, pattern):
            return True

    return False

def compress_file(input_filename, output_filename, chunk_size=64*1024):
    compressor = zlib.compressobj()

    with open(input_filename, 'rb') as input:
        with open(output_filename, 'wb') as output:
            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(compressor.compress(chunk))

            output.write(compressor.flush())

def decompress_file(input_filename, output_filename, chunk_size=64*1024): 
    directory = os.path.dirname(output_filename)

    if not os.path.exists(directory):
        os.makedirs(directory)

    compressor = zlib.decompressobj()

    with open(input_filename, 'rb') as input:
        with open(output_filename, 'wb') as output:
            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(compressor.decompress(chunk))

            output.write(compressor.flush())

def get_file_size(file):
    if isinstance(file, io.IOBase):
        return file.tell()
    else:
        return os.path.getsize(file)

def open_read_file(file):
    if isinstance(file, io.IOBase):
        file.seek(0)
        return file
    else:
        return open(file, 'rb')