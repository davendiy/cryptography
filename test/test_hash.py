#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 13.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from src.hashes.sha import SHA256
from Crypto.Hash import SHA256 as cr_SHA256
from Crypto.Random import get_random_bytes

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
