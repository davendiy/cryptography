#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 28.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from math import ceil
import random

from ..aes import AES
from ..aes.modes import MODE_CTR
from ..hashes import SHA256


def get_random_number(bits: int):
    x = random.randrange(0, 1 << bits - 1)
    return (1 << bits) + x


def get_random_bytes(n):
    res = [random.randrange(0, 255) for _ in range(n)]
    return bytes(res)


def get_random_number2(bits: int):
    # pseudorandom start_point
    seed = hex(random.randrange(0, 1 << 128))[2:]
    seed = bytes.fromhex(seed.rjust(32, '0'))  # add zeros for 16-bytes len
    h = SHA256(seed).digest()
    key = h[:16]
    iv = h[16:24]
    cipher = AES.new(key, mode=MODE_CTR, IV=iv)
    length = ceil(bits / 128)  # amount of blocks
    byte = random.randrange(0, 256)  # start point for message
    message = []
    for _ in range(length * 16):
        message.append(byte)
        byte += 1
        byte %= 256
    message = bytes(message)
    ciphertext = cipher.encrypt(message)

    # get last (bits-1) bits and add leading 1
    return (1 << bits) + int(ciphertext.hex(), 16) % (1 << bits)


# -------------------MillerRabinTest--------------------------------------------
# original: https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/

def miillerTest(d, n):
    """ This function is called  for all k trials. It returns
    false if n is composite and returns True if n is
    probably prime. d is an odd number such that d*2<sup>r</sup> = n-1
    for some r >= 1
    """
    # Pick a random number in [2..n-2]
    # Corner cases make sure that n > 4
    a = 2 + random.randint(1, n - 4)

    # Compute a^d % n
    x = pow(a, d, n)

    if x == 1 or x == n - 1:
        return True

    # Keep squaring x while one of the following doesn't happen
    #           (i) d does not reach n-1
    #           (ii) (x^2) % n is not 1
    #           (iii) (x^2) % n is not n-1
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True

    # Return composite
    return False


def isPrime(n, k):
    """ It returns false if n is composite and returns true if n
    is probably prime. k is an input parameter that determines
    accuracy level. Higher value of k indicates more accuracy.
    """
    # Corner cases
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    # check if the number is divisible by the first prime numbers
    for el in sieve_base:
        if n % el == 0:
            return n == el

    # Find r such that n = 2^d * r + 1 for some r >= 1
    d = n - 1
    while d % 2 == 0:
        d //= 2

    # Iterate given number of 'k' times
    for i in range(k):
        if not miillerTest(d, n):
            return False
    return True


def get_random_prime(bits: int):
    n = get_random_number(bits)
    if n & 1 == 0:
        n += 1

    while not isPrime(n, bits):
        n += 2
    return n


# First prime numbers for checking
sieve_base = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997,
)
