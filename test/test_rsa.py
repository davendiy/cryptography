#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 28.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com


from src.rsa.pkcs1 import *
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# test_key = RSAKey.generate(1024)

test_key = RSAKey.construct(
    125239179350753870034264334306965105709380074349697270237490877839871556593581971973923123249642025004361849019681164374118430988816268002380527851570514507627251553257806740493723419819215685122468420132616471676470878301328341256646468142898299752979940501743839944420262086058174039438902729804752301660897,
    65537,
    121724907247574957862620650421671167485177716037154839549989989420390594807482558719424982906689316092098220224539585399127146758710631234503179319916057061943749517174264312568775176073281166644910189420777643458292302500239909980118394239134609669524515811818672537307733989204027094453078467103613012222337,
    9801878496828619525133577049422547366501395176867492648560449126745569897268171716415377364513919658923686650264284401436091094855988939383206842279581369,
    12777058947555285990002681164043020985605790517212979259404035462677642600785124266574923288312757600288861919152371457333529132565201801653945558519959913
)


print('Test key is generated.')
print("################## My implementation exporting ########################")
print(test_key.export_key().decode('latin'))
test_public_key = RSAKey.construct(test_key.n, test_key.e)
print(test_public_key.export_key().decode('latin'))

print(test_key.export_key("DER"))

print('\n\nCHECKING DER\n\n')
RSA.importKey(test_key.export_key('DER'))

print('\n\nCHEKCING PEM\n\n')
RSA.importKey(test_key.export_key())


print("################### Pycryptodome exporting ############################")
crypto_key = RSA.construct((test_key.n, test_key.e))
print(crypto_key.exportKey().decode("latin"))
crypto_key = RSA.construct((test_key.n, test_key.e, test_key.d))
print(crypto_key.exportKey().decode("latin"))

assert crypto_key.exportKey() == test_key.export_key(), 'Nope'
print("############################# RSA #####################################")
test_mess = get_random_bytes(32)
test_mess = os2ip(test_mess)
ciphertext = rsaep(test_mess, test_key)
print('message:', test_mess)
print('ciphertext:', ciphertext)
print('decrypted:', rsadp(ciphertext, test_key))

cipher = RSAES_OAEP(test_key)
test_mess = get_random_bytes(32)
ciphertext = cipher.encrypt(test_mess)
print("\n----------RSA OAEP---------\n")
print('message:', test_mess)
print('ciphertext:', ciphertext)
print('decrypted:', cipher.decrypt(ciphertext))
