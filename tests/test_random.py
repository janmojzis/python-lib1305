from lib1305 import poly1305
from secrets import randbelow
import os


def test_random():
    '''
    '''

    # generate a random 256-bit secret key
    k = os.urandom(32)

    # generate a massage
    m = os.urandom(128 + randbelow(128))

    # compute an 128-bit authenticator
    a = poly1305.auth(m, k)

    # verify and 128-bit authenticator
    poly1305.verify(a, m, k)

    # replace byte in a message and check if verification fails
    for i in range(len(m)):
        m1 = bytearray(m)
        m1[i] = (m1[i] + 1 + randbelow(255)) % 256
        m1 = bytes(m1)

        try:
            poly1305.verify(a, m1, k)
        except Exception as e:
            pass
        else:
            raise Exception('message forgery not detected !!!')

    # replace byte in an authentificatior and check if verification fails
    for i in range(len(a)):
        a1 = bytearray(a)
        a1[i] = (a1[i] + 1 + randbelow(255)) % 256
        a1 = bytes(a1)

        try:
            poly1305.verify(a1, m, k)
        except Exception as e:
            pass
        else:
            raise Exception('authenticator forgery not detected !!!')
