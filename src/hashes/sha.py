#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 13.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from abc import abstractmethod, ABC
from functools import partial


class Hash(ABC):

    block_size = 0
    word_size = 0
    digest_size = 0

    @abstractmethod
    def update(self, bytestream: bytes):
        pass

    @abstractmethod
    def digest(self):
        pass

    @abstractmethod
    def hexdigest(self):
        pass


def _Ch(x, y, z):
    return ( x & y ) ^ ( (~x) & z )


def _Maj(x, y, z):
    return ( x & y ) ^ ( x & z ) ^ ( y & z)


def _SHR(x, n):
    return x >> n


def _rotl(x, n, word_size=32):
    return ((x << n) | (x >> (word_size - n))) % (1 << word_size)


def _rotr(x, n, word_size=32):
    return _rotl(x, (word_size - n))


class SHA256(Hash):

    block_size = 512
    word_size = 32
    digest_size = 256

    # SHA-224 and SHA-256 use the same sequence of sixty-four constant 32-bit
    # words. These words represent the first thirty-two bits of the
    # fractional parts of the cube roots of the first sixty-four prime numbers.
    # In hex, these constant words are (from left to right)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    # These words were obtained by taking the first thirty-two bits of
    # the fractional parts of the square roots of the first eight prime numbers
    H_0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    def __init__(self, message=None):
        self._message = b''
        self._padded_mess = b''
        self._hash = None
        if message is not None:
            self.update(message)

    @staticmethod
    def _Sigma0(x):
        rotr = partial(_rotr, word_size=SHA256.word_size)
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

    @staticmethod
    def _Sigma1(x):
        rotr = partial(_rotr, word_size=SHA256.word_size)
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

    @staticmethod
    def _sigma0(x):
        rotr = partial(_rotr, word_size=SHA256.word_size)
        return rotr(x, 7) ^ rotr(x, 18) ^ _SHR(x, 3)

    @staticmethod
    def _sigma1(x):
        rotr = partial(_rotr, word_size=SHA256.word_size)
        return rotr(x, 17) ^ rotr(x, 19) ^ _SHR(x, 10)

    def _do_padding(self):
        """ Suppose that the length of the message, M, is l bits.
        Append the bit “1” to the end of the message, followed by k zero bits,
        where k is the smallest, non-negative solution to the equation
                    l + k + 1 = 448 mod 512
        Then append the 64-bit block that is equal to the
        number l expressed using a binary representation.

        For  example, the (8-bit  ASCII) message “abc” has length 8x3 = 24,
        so the message is padded with a one bit, then 448 - (24 + 1) = 423
        zero bits, and then the message length, to become the 512-bit padded message
        """
        length = len(self._message) * 8
        k = (448 - length - 1) % 512
        add = '1' + '0' * k + bin(length)[2:].rjust(64, '0')
        self._padded_mess = self._message + bytes.fromhex( hex(int(add, 2))[2:] )

        assert len(self._padded_mess) * 8 % 512 == 0

    def _get_m(self):

        word_size_b = self.word_size // 8
        block_size_b = self.block_size // 8

        # list of 32-bits words
        tmp = [int(self._padded_mess[i: i + word_size_b].hex(), 16)
                    for i in range(0, len(self._padded_mess), word_size_b)]

        # thus len(tmp) == len(self._padded_mess) / 32
        assert len(tmp) == len(self._padded_mess) // word_size_b

        # list of N blocks (16 32-bits words per block)
        res = [tmp[i: i + (self.block_size // word_size_b)]
                    for i in range(0, len(tmp), block_size_b // word_size_b)]

        assert len(res) == (len(self._padded_mess)) // block_size_b
        return res

    def _calculate_hash(self):
        self._do_padding()
        m = self._get_m()
        h_prev = self.H_0.copy()
        for i, cur_m in enumerate(m):
            w = [cur_m[t] for t in range(16)] + [0] * 48
            for t in range(16, 64):
                w[t] = self._sigma1(w[t-2]) + w[t-7]\
                         + self._sigma0(w[t-15]) + w[t-16]
                w[t] %= 1 << self.word_size

            a, b, c, d, e, f, g, h = h_prev

            for t in range(64):
                T1 = (h + self._Sigma1(e) + _Ch(e, f, g) + self.K[t] + w[t]) \
                     % (1 << self.word_size)
                T2 = (self._Sigma0(a) + _Maj(a, b, c)) % (1 << self.word_size)
                h = g
                g = f
                f = e
                e = (d + T1) % (1 << self.word_size)
                d = c
                c = b
                b = a
                a = (T1 + T2) % (1 << self.word_size)

            h_next = [(h_prev[i] + _x) % (1 << self.word_size)
                      for i, _x in enumerate([a, b, c, d, e, f, g, h])]
            h_prev = h_next

        self._hash = b''.join(list(map(
            lambda x: bytes.fromhex( hex(x)[2:].rjust(self.word_size // 4, '0') ),
            h_prev
        )))

        assert len(self._hash) == self.digest_size // 8

    def update(self, bytestream: bytes):
        self._message += bytestream
        self._hash = None

    def digest(self):
        if self._hash is None:
            self._calculate_hash()
        return self._hash

    def hexdigest(self):
        if self._hash is None:
            self._calculate_hash()
        return self._hash.hex()
