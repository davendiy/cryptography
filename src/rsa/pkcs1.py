#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 28.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from ..hashes import SHA256
from ..utils.random import get_random_prime, get_random_bytes
from ..utils.asn1 import DerSequence, DerNull, \
    DerObjectIdentifier, DerOctedString

from math import ceil
import binascii

class RSAError(ValueError):
    pass


class DecryptionError(ValueError):
    def __str__(self):
        return "Decryption error."


def b(s):
    return s.encode("latin-1")  # utf-8 would cause some side-effects we don't want


def gcdExtended(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b % a, a)

    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


class RSAKey:
    """ Class that represents rsa key.

    Don't use its initialisation directly. Use generate(), construct()
    or import_from() instead.
    """

    algorithm_oid = '1.2.840.113549.1.1.1 '
    algorithm_identifier = DerSequence([
        DerObjectIdentifier(algorithm_oid), DerNull()
    ])

    def __init__(self, e=None, n=None, d=None, p=None, q=None,
                 dP=None, dQ=None, qInv=None, riditi=()):
        """ Initialisation of a key.

        It shall be used in 3 modes:
            1. Public key
            --> RSAKey(e, n)

            2. Private key (first representation)
            --> RSAKey(d, n)

            3. Private key (second representation)
            --> RSAKey(p, q, dP, dQ, qInv, (r_i, d_i, t_i))

        :param e: RSA public exponent
        :param n: RSA modulus
        :param d: RSA private exponent
        :param p: First factor of the RSA modulus
        :param q: Second factor of the RSA modulus
        :param dP: the first factor's CRT exponent, a positive integer
        :param dQ: the second factor's CRT exponent, a positive integer
        :param qInv: the first Chinese remainder component
        :param riditi: a (possibly empty) sequence of triplets (r_i, d_i, t_i),
                i = 3 ... u, where
                    r_i - the i-th factor, a positive integer
                    d_i - the i-th factor's CRT exponent, a positive integer
                    t_i - the i-th factor's CRT coefficient, a positive integer

        For more info check https://tools.ietf.org/html/rfc8017#section-3.1
        """
        self.e = e
        self.n = n
        self.p = p
        self.q = q
        self.d = d
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.riditi = riditi

    def has_private(self) -> bool:
        return self.d is not None or self.dP is not None

    def repr_version(self):
        if not self.has_private():
            return -1
        if self.dP is not None:
            return 2
        else:
            return 1

    # TODO:
    @classmethod
    def import_key(cls, filename):
        pass

    def export_key(self, format='PEM'):


        if self.has_private():
            keyType = 'RSA PRIVATE'
            version = 1 if self.riditi else 0
            der_seq = DerSequence([
                version, self.n, self.e, self.d, self.p, self.q,
                self.dP, self.dQ, self.qInv
            ])
            for ri, di, ti in self.riditi:
                der_seq.append(DerSequence([ri, di, ti]))
        else:
            keyType = 'PUBLIC'
            der_seq = DerSequence()
            der_seq.append(self.algorithm_identifier)
            der_key = DerSequence([ self.n, self.e ])
            bitmap = DerOctedString(b'\x00' + der_key.encode())
            der_seq.append(bitmap)
            
        if format == 'DER':
            return der_seq.encode()
        elif format == 'PEM':
            pem = b('-----BEGIN ' + keyType + ' KEY-----\n')
            binaryKey = der_seq.encode()
            # print(der_seq)
            # Each BASE64 line can take up to 64 characters (=48 bytes of data)
            chunks = [binascii.b2a_base64(binaryKey[i:i + 48]) for i in range(0, len(binaryKey), 48)]
            pem += b('').join(chunks)
            pem += b("-----END " + keyType + " KEY-----")
            return pem
        else:
            raise NotImplementedError()

    @classmethod
    def generate(cls, bits, e=65537):
        p = get_random_prime(bits)
        q = get_random_prime(bits)
        n = p * q
        d, dP, dQ, qInv = cls._prepare(e, p, q)
        return cls(e, n, d, p, q, dP, dQ, qInv)

    @classmethod
    def _prepare(cls, e, p, q):
        d = cls._inverse(e, (p - 1)*(q - 1))
        dP = d % (p - 1)
        dQ = d % (q - 1)
        qInv = cls._inverse(q, p)
        return d, dP, dQ, qInv

    @staticmethod
    def _inverse(number, base):
        flag, res, _ = gcdExtended(number, base)
        if flag != 1:
            raise ValueError(f"There is no inverse of {number} over {base} base.")
        return res % base        # res could be negative

    @classmethod
    def construct(cls, n, e, d=None, p=None, q=None):
        p1 = p or q
        p2 = n // p1 if p1 else None
        if p1 and p1 * p2 != n:
            raise ValueError("Bad prime numbers for RSA key.")
        if p1:
            d, dP, dQ, qInv = cls._prepare(e, p1, p2)
            return cls(e, n, d, p1, p2, dP, dQ, qInv)
        else:
            return cls(e, n, d)


def i2osp(x: int, xLen: int) -> bytes:
    """ Integer to Octet String Primitive.
    Converts a nonnegative integer to an octet string of a specified length.
    """
    if x >= 256 ** xLen:
        raise ValueError("Integer is too large.")
    return bytes.fromhex(hex(x)[2:].rjust(xLen*2, '0'))


def os2ip(b: bytes) -> int:
    """ Octet String to Integer Primitive.
    Interprets a sequence of bytes as a non-negative integer.
    """
    return int(b.hex(), 16)


def rsaep(message: int, key: RSAKey) -> int:
    """ RSA Encryption Primitive.
    Encrypts a message (integer representative) using a public key
    """
    if not (0 <= message <= key.n-1):
        raise ValueError("Message representative is out of range.")
    c = pow(message, key.e, key.n)
    return c


def rsadp(ciphertext: int, key: RSAKey) -> int:
    """ RSA Decryption Primitive.
    Decrypts ciphertext (integer representative) using a private key.
    """
    if not (0 <= ciphertext <= key.n-1):
        raise ValueError("Ciphertext representative is out of range.")
    if not key.has_private():
        raise RSAError("Key has just public part.")

    if key.repr_version() == 1:
        m = pow(ciphertext, key.d, key.n)
    else:
        m_1 = pow(ciphertext, key.dP, key.p)
        m_2 = pow(ciphertext, key.dQ, key.q)
        m_is = []
        for r_i, d_i, _ in key.riditi:
            m_is.append(pow(ciphertext, d_i, r_i))
        h = (m_1 - m_2) * key.qInv
        h %= key.p

        m = m_2 + key.q * h
        R = key.p
        prev_r_i = key.q
        for (r_i, _, t_i), m_i in zip(key.riditi, m_is):
            R = R * prev_r_i
            h = (m_i - m) * t_i
            h %= r_i
            m = m + R * h
            prev_r_i = r_i
    return m


def rsasp1(message: int, key: RSAKey) -> int:
    """ RSA Signature Primitive.
    A signature primitive produces a signature representative from a
    message representative under the control of a private key.
    """
    if not (0 <= message <= key.n-1):
        raise ValueError("Message representative is out of range.")
    if not key.has_private():
        raise RSAError("Key has just public part.")

    return rsadp(message, key)


def rsavp1(signature: int, key: RSAKey) -> int:
    """ RSA Verification Primitive.
    Recovers the message representative from the signature
    representative under the control of the corresponding public key.
    """
    if not (0 <= signature <= key.n-1):
        raise ValueError("Signature representative is out of range.")
    return rsaep(signature, key)


def xor(x: bytes, y: bytes) -> bytes:
    res = [_x ^ _y for _x, _y in zip(x, y)]
    return bytes(res)


class MGF1:

    def __init__(self, maskLen: int, mgfSeed=b'', hash_algo=SHA256):
        if maskLen > (1 << 32) * (hash_algo.digest_size('byte')):
            raise ValueError("Mask is too long.")

        self.hLen = hash_algo.digest_size('byte')
        self.seed = mgfSeed
        self.mask_len = maskLen
        self.hash_algo = hash_algo

    def update(self, data: bytes):
        self.seed += data

    def digest(self) -> bytes:
        t = b''
        for counter in range(ceil(self.mask_len / self.hLen)):
            c = i2osp(counter, 4)
            t += self.hash_algo(self.seed + c).digest()
        return t[:self.mask_len]


class RSAES_OAEP:

    # TODO: add key checking
    def __init__(self, key: RSAKey, hash_algo=SHA256, mgf_algo=MGF1):
        self.key = key
        self.hash_algo = hash_algo
        self.mgf_algo = mgf_algo
        self.k = ceil(len(hex(self.key.n)[2:]) / 2)
        self.hLen = self.hash_algo.digest_size('byte')

    def encrypt(self, message: bytes, label=b'') -> bytes:
        if len(label) > self.hash_algo.input_limit('byte'):
            raise ValueError("Label is too long.")

        mLen = len(message)
        if mLen > self.k - 2 * self.hLen - 2:
            raise ValueError("Message is too long.")

        # EME-OAEP encoding
        lHash = self.hash_algo(label).digest()
        ps = i2osp(0, max(self.k - mLen - 2 * self.hLen - 2, 0))
        db = lHash + ps + b'\x01' + message
        seed = get_random_bytes(self.hLen)
        dbMask = self.mgf_algo(self.k - self.hLen - 1, seed).digest()
        maskedDb = xor(db, dbMask)
        seedMask = self.mgf_algo(self.hLen, maskedDb).digest()
        maskedSeed = xor(seed, seedMask)
        em = b'\x00' + maskedSeed + maskedDb

        # RSA encryption
        m = os2ip(em)
        c = rsaep(m, self.key)
        c = i2osp(c, self.k)
        return c

    def decrypt(self, ciphertext: bytes, label=b'') -> bytes:
        if len(label) > self.hash_algo.input_limit('byte'):
            raise DecryptionError()
        if len(ciphertext) != self.k:
            raise DecryptionError()
        if self.k < 2 * self.hLen + 2:
            raise DecryptionError()

        # RSA decryption
        c = os2ip(ciphertext)
        try:
            m = rsadp(c, self.key)
        except RSAError:
            raise
        except ValueError:
            raise DecryptionError()
        em = i2osp(m, self.k)

        # EME-OAEP decoding
        lHash = self.hash_algo(label).digest()
        maskedSeed = em[1: self.hLen + 1]
        maskedDb = em[self.hLen + 1:]

        seedMask = self.mgf_algo(self.hLen, maskedDb).digest()
        seed = xor(maskedSeed, seedMask)
        dbMask = self.mgf_algo(self.k - self.hLen - 1, seed).digest()
        db = xor(maskedDb, dbMask)
        lHash2 = db[:self.hLen]
        if lHash2 != lHash:
            raise DecryptionError

        for i, el in enumerate(db[self.hLen:], self.hLen):
            if el == 1:
                break
        else:
            raise DecryptionError()

        message = db[i+1:]
        return message
