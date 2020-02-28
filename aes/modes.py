#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Excusa. Quod scripsi, scripsi

# @Author: David Zashkolny <davidas>
# @Date:   20-Feb-2020
# @Email:  davendiy@gmail.com
# @Last modified by:   davidas
# @Last modified time: 20-Feb-2020

from Crypto.Random import get_random_bytes


# ============================ CBC MODE ========================================
def MODE_ECB(sym_cipher_enc_func: callable,
             sym_cipher_dec_func: callable):

    def ecb_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Bad length of message: {len(message)}. Use padding.")
        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        res = b''
        for block in blocks:
            res += bytes(sym_cipher_enc_func(block, key))
        return res

    def ecb_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16:
            raise ValueError(f"Bad length of ciphertext: {len(ciphertext)}.")
        blocks = [ciphertext[i: i+16] for i in range(0, len(ciphertext), 16)]
        res = b''
        for block in blocks:
            res += bytes(sym_cipher_dec_func(block, key))
        return res

    return ecb_encrypt, ecb_decrypt


# ============================ CBC MODE ========================================
def MODE_CBC(sym_cipher_enc_func: callable,
             sym_cipher_dec_func: callable):

    def cbc_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Bad length of message: {len(message)}. Use padding.")

        initial_block = get_random_bytes(16)
        res = initial_block
        prev_block = list(initial_block)

        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        for block in blocks:
            block = [x ^ y for x, y in zip(prev_block, block)]
            block = sym_cipher_enc_func(block, key)
            res += bytes(block)
            prev_block = block
        return res

    def cbc_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16:
            raise ValueError(f"Bad length of ciphertext: {len(ciphertext)}.")
        res = b''
        blocks = [ciphertext[i: i + 16] for i in range(0, len(ciphertext), 16)]
        for i in range(len(blocks) - 1, 0, -1):
            mi = sym_cipher_dec_func(blocks[i], key)
            mi = [x ^ y for x, y in zip(mi, blocks[i - 1])]
            res = bytes(mi) + res
        return res

    return cbc_encrypt, cbc_decrypt


# ============================ CTR MODE ========================================
def MODE_CTR(sym_cipher_enc_func: callable,
             sym_cipher_dec_func: callable):
    def ctr_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Bad length of message: {len(message)}. Use padding.")

        nonce = get_random_bytes(8)
        res = nonce
        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        for i in range(len(blocks)):
            block = blocks[i]
            hex_i = hex(i)[2:]
            cur_count = nonce.hex() + '0' * (16 - len(hex_i)) + hex_i
            cur_count = bytes.fromhex(cur_count)
            salt = sym_cipher_enc_func(cur_count, key)
            res += bytes([x ^ y for x, y in zip(salt, block)])
        return res

    def ctr_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16 != 8:
            raise ValueError(f"Bad length of ciphertext: {len(ciphertext)}.")

        nonce = ciphertext[:8]
        blocks = [ciphertext[i: i + 16] for i in range(8, len(ciphertext), 16)]
        res = b''

        for i in range(len(blocks)):
            block = blocks[i]

            hex_i = hex(i)[2:]
            cur_count = nonce.hex() + '0' * (16 - len(hex_i)) + hex_i
            cur_count = bytes.fromhex(cur_count)
            salt = sym_cipher_enc_func(cur_count, key)
            res += bytes([x ^ y for x, y in zip(salt, block)])
        return res

    return ctr_encrypt, ctr_decrypt
