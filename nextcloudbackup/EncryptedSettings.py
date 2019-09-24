from .CryptoUtils import derive_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import collections, json, os

class EncryptedSettings(collections.MutableMapping):

    def __init__(self, filename, key):
        self.filename = filename
        self.iv = derive_key(key, 16)
        self.key = derive_key(key, 32)
        self.store = {}
        self.read()

    def get_cipher(self):
        return AES.new(self.key, AES.MODE_CBC, iv=self.iv)

    def read(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'rb') as f:
                cipher = self.get_cipher()
                self.store = unpad(cipher.decrypt(f.read()), cipher.block_size)
                self.store = json.loads(self.store)
        else:
            self.write()

    def write(self):
        with open(self.filename, 'wb') as f:
            cipher = self.get_cipher()
            data = json.dumps(self.store)

            f.write(cipher.encrypt(pad(data.encode(), cipher.block_size)))

    def __setitem__(self, key, value):
        self.store[key] = value
        self.write()

    def __delitem__(self, key):
        del self.store[key]
        self.write()

    def __getitem__(self, key):
        return self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)
