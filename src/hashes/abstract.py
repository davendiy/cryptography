#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 13.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from abc import abstractmethod, ABC
from ..aes.AES import new, MODE_CBC


class Hash(ABC):

    block_size = 0
    word_size = 0
    digest_size = 0

    @abstractmethod
    def update(self, bytestream: bytes):
        pass

    @abstractmethod
    def padding(self):
        pass

    @abstractmethod
    def digest(self):
        pass

    @abstractmethod
    def hexdigest(self):
        pass


def create_AES_cipher(password, hash_algo, mode=MODE_CBC, IV=None):
    pass_hash = hash_algo(password).digest()[-128//8:]
    cipher = new(pass_hash, mode, IV)
    return cipher


class HMAC:

    def __init__(self, hash_algo, key, message=None):

        self.message = b''
        self.key = key
        self.hash_algo = hash_algo
        if message is not None:
            self.update(message)

    def update(self, message):
        self.message += message

    def _digest(self, data):
        return self.hash_algo(data).digest()

    def digest(self) -> bytes:
        key = self.key

        # Keys longer than blockSize are shortened by hashing them
        if len(key) > self.hash_algo.block_size // 8:
            key = self._digest(key)

        # Keys shorter than blockSize are padded to blockSize
        # by padding with zeros on the right
        key = key.ljust(self.hash_algo.block_size // 8, b'\x00')

        opad = bytes([_x ^ 0x5c for _x in key])
        ipad = bytes([_x ^ 0x36 for _x in key])

        return self._digest(opad + self._digest(ipad + self.message))

    def hexdigest(self):
        return self.digest().hex()

    def check(self, hmac):
        return self.digest() == hmac
