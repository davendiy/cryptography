#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 13.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from src.hashes import SHA256, create_AES_cipher, HMAC_SHA256
from Crypto.Hash import SHA256 as cr_SHA256, HMAC as cr_HMAC
from Crypto.Random import get_random_bytes

print("=============================task1=====================================")
N = 10
test = get_random_bytes(N)
hash_obj = cr_SHA256.SHA256Hash(test)
hash_obj2 = SHA256(test)
print("message:", test)
print()
print("Hash using Pycryptodome:", hash_obj.digest())
print("Hash using my implementation:", hash_obj2.digest())

print("Hex hash using Pycryptodome:", hash_obj.hexdigest())
print("Hex hash using my implementation:", hash_obj2.hexdigest())

print("=============================task2=====================================")

password = bytes(input("enter password for AES:\n--> "), encoding='utf-8')
message = bytes(input("enter message (length should be multiple of 16, "
                      "for example 'some_message4AES'):\n--> "),
                encoding='utf-8')

cipher = create_AES_cipher(password, SHA256)
print("Generated password:", cipher.key)
ciphertext = cipher.encrypt(message)
print("Result ciphertext:", ciphertext)

next_password = bytes(input("enter another password to check decryption "
                            "of the previous ciphertext:\n--> "),
                      encoding='utf-8')

cipher = create_AES_cipher(next_password, SHA256)
print("Decrypting resuld:", cipher.decrypt(ciphertext))

print("=============================task3=====================================")

password = bytes(input("enter password for HMAC:\n--> "), encoding='utf-8')
message = bytes(input("enter message (any length):\n--> "), encoding='utf-8')

hmac = HMAC_SHA256(password, message)
print("HMAC:", hmac.hexdigest())

hmac2 = cr_HMAC.new(key=password, msg=message, digestmod=cr_SHA256)
print("HMAC using Crypto:", hmac2.hexdigest())
