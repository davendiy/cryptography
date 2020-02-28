#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections import Counter
import numpy as np


letters = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'

target_freq = 0.049713938364682506

t = '''А  0,072  Ї  0,006  У  0,04
Б  0,017  Й  0,008  Ф  0,001
В  0,052  К  0,035  Х  0,012
Г  0,016  Л  0,036  Ц  0,006
Д  0,035  М  0,031  Ч  0,018
Е  0,017  Н  0,065  Ш  0,012
Є  0,008  О  0,094  Щ  0,001
Ж  0,009  П  0,029  Ю  0,004
З  0,023  Р  0,047  Я  0,029
И  0,061  С  0,041  Ь  0,029
І  0,057  Т  0,055'''
t = t.split()

ua_freq = {
    t[i].lower() : float(t[i+1].replace(',', '.')) for i in range(0, len(t), 2)
}


def encrypt(message, key):
    res = ''
    for i, el in enumerate(message.lower()):
        if el not in letters:
            raise ValueError(f"bad element: {el}")
        res += letters[(letters.find(el) + letters.find(key[i % len(key)])) % 33]
    return res


def decrypt(message, key):
    res = ''
    for i, el in enumerate(message.lower()):
        if el not in letters:
            raise ValueError(f"bad element: {el}")
        res += letters[(letters.find(el) - letters.find(key[i % len(key)])) % 33]
    return res


def index_col(message, keylen):
    counter = Counter(message[::keylen])
    n = len(message[::keylen])
    if n <= 1:
        return 1
    x = [counter[i] * (counter[i]-1) / (n * (n-1)) for i in counter]
    res = sum(x)
    return res


def freq_col(message, key):
    res_message = ''
    for el in message:
        res_message += letters[letters.find(el) - key]
    counter = Counter(res_message)

    res = 0
    n = len(res_message)
    for letter in ua_freq:
        res += (counter[letter]/n - ua_freq[letter]) / ua_freq[letter]
    return res


def attack(message):
    print("[*] Finding best key length...")
    indexes = [index_col(message, i) for i in range(1, 32)]
    indexes = [(x - target_freq) ** 2 for x in indexes]
    best_i = np.argmin(indexes) + 1
    print(f'[*] Found best key length: {best_i}')

    print(f'[*] Finding best keys...')
    res_key = []
    for key_num in range(best_i):
        tmp_message = message[key_num::best_i]
        freqs = [freq_col(tmp_message, key_i) for key_i in range(len(letters))]
        res_key.append(np.argmin(freqs))
    print(f'[*] Found key: {res_key}')
    res_key = ''.join([letters[el] for el in res_key])
    return res_key
