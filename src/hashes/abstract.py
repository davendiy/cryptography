#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 13.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

""" Module with hashes declaration and functions which don't depend on
implementation of specific hash function (currently it's only HMAC).
"""

from abc import abstractmethod, ABC
from ..aes.AES import new, MODE_CBC

BIT = 'bit'
BYTE = 'byte'


class Hash(ABC):
    """ Interface for implementation of single hash algorithm.
    Similar to Crypto.Hash
    """
    _block_size = 0
    _word_size = 0
    _digest_size = 0
    _input_limit = 0

    @classmethod
    def digest_size(cls, type_val=BYTE):
        if type_val not in (BYTE, BIT):
            raise ValueError(f"Bad type for size: {type_val}")

        return cls._digest_size if type_val == BIT else cls._digest_size // 8

    @classmethod
    def block_size(cls, type_val=BYTE):
        if type_val not in (BYTE, BIT):
            raise ValueError(f"Bad type for size: {type_val}")

        return cls._block_size if type_val == BIT else cls._block_size // 8

    @classmethod
    def word_size(cls, type_val=BYTE):
        if type_val not in (BYTE, BIT):
            raise ValueError(f"Bad type for size: {type_val}")

        return cls._word_size if type_val == BIT else cls._word_size // 8

    @classmethod
    def input_limit(cls, type_val=BYTE):
        if type_val not in (BYTE, BIT):
            raise ValueError(f"Bad type for size: {type_val}")

        return cls._input_limit if type_val == BIT else cls._input_limit // 8

    @abstractmethod
    def update(self, bytestream: bytes):
        pass

    @abstractmethod
    def padding(self):
        pass

    @abstractmethod
    def digest(self) -> bytes:
        pass

    @abstractmethod
    def hexdigest(self) -> str:
        pass


def create_AES_cipher(password, hash_algo, mode=MODE_CBC, IV=None):
    """ Create AES cipher that uses hash of password instead of password itself.

    :param password:  any array of bytes
    :param hash_algo: some implementation of Hash interface
    :param mode:      from aes.modes
    :param IV:        initialisation vector
    :return:
    """
    pass_hash = hash_algo(password).digest()[-128//8:]
    cipher = new(pass_hash, mode, IV)
    return cipher


class HMAC:
    """ Class that allows to make a HMAC signature of message with a given key
    using any of hash algorithms (as described by RFC 2104).

    :param hash_algo: some implementation of Hash interface
    :param key:       any array of bytes
    :param message:   any array of bytes
    """

    def __init__(self, hash_algo, key: bytes, message=None):

        self.message = b''
        self.key = key
        self.hash_algo = hash_algo
        if message is not None:
            self.update(message)

    def update(self, message: bytes):
        """ Add new data to the message.
        """
        self.message += message

    def _digest(self, data: bytes):
        return self.hash_algo(data).digest()

    def digest(self) -> bytes:
        key = self.key

        # Keys longer than blockSize are shortened by hashing them
        if len(key) > self.hash_algo.block_size(type_val=BYTE):
            key = self._digest(key)

        # Keys shorter than blockSize are padded to blockSize
        # by padding with zeros on the right
        key = key.ljust(self.hash_algo.block_size(type_val=BYTE), b'\x00')

        opad = bytes([_x ^ 0x5c for _x in key])
        ipad = bytes([_x ^ 0x36 for _x in key])

        return self._digest(opad + self._digest(ipad + self.message))

    def hexdigest(self) -> str:
        return self.digest().hex()

    def check(self, hmac) -> bool:
        return self.digest() == hmac
