#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 28.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from src.utils.random import get_random_number, get_random_prime
import matplotlib.pyplot as plt

bits = 4
n = 1000

tmp = [get_random_number(bits) for _ in range(n)]
plt.hist(tmp, bins=100)
plt.show()

print(get_random_prime(1024))
