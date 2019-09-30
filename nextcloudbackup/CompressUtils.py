import fnmatch
import zlib

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
    compressor = zlib.decompressobj()

    with open(input_filename, 'rb') as input:
        with open(output_filename, 'wb') as output:
            while True:
                chunk = input.read(chunk_size)

                if len(chunk) == 0:
                    break

                output.write(compressor.decompress(chunk))

            output.write(compressor.flush())
