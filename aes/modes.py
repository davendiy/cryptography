#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Excusa. Quod scripsi, scripsi

# @Author: David Zashkolny <davidas>
# @Date:   20-Feb-2020
# @Email:  davendiy@gmail.com
# @Last modified by:   davidas
# @Last modified time: 20-Feb-2020


from Crypto.Random import get_random_bytes
from source import *


############################## CBC MODE ########################################
def cbc_encrypt(message: bytes, key: bytes):
    initial_block = get_random_bytes(16)
    res = initial_block
    prev_block = list(initial_block)

    blocks = [message[i: i+16] for i in range(0, len(message), 16)]
    for block in blocks:
        block += b'0'*(16-len(block))
        block = [x^y for x, y in zip(prev_block, block)]
        block = encrypt(block, key)
        res += bytes(block)
        prev_block = block
    return res


def cbc_decrypt(ciphertext: bytes, key: bytes):
    res = b''
    blocks = [ciphertext[i: i+16] for i in range(0, len(ciphertext), 16)]
    for i in range(len(blocks)-1, 0, -1):
        mi = decrypt(blocks[i], key)
        mi = [x^y for x, y in zip(mi, blocks[i-1])]
        res = bytes(mi) + res
    return res


CBC_MODE = (cbc_encrypt, cbc_decrypt)


############################## CTR MODE ########################################
def ctr_encrypt(message: bytes, key: bytes):
    nonce = get_random_bytes(8)
    res = nonce
    blocks = [message[i: i+16] for i in range(0, len(message), 16)]
    for i in range(len(blocks)):
        block = blocks[i]
        block += b'0'*(16-len(block))

        hex_i = hex(i)[2:]
        cur_count = nonce.hex() + '0' * (16-len(hex_i)) + hex_i
        cur_count = bytes.fromhex(cur_count)
        salt = encrypt(cur_count, key)
        res += bytes([x^y for x, y in zip(salt, block)])
    return res


def ctr_decrypt(ciphertext: bytes, key: bytes):
    nonce = ciphertext[:8]
    blocks = [ciphertext[i: i+16] for i in range(8, len(ciphertext), 16)]
    res = b''

    for i in range(len(blocks)):
        block = blocks[i]

        hex_i = hex(i)[2:]
        cur_count = nonce.hex() + '0' * (16-len(hex_i)) + hex_i
        cur_count = bytes.fromhex(cur_count)
        salt = encrypt(cur_count, key)
        res += bytes([x^y for x, y in zip(salt, block)])
    return res


CTR_MODE = (ctr_encrypt, ctr_decrypt)
