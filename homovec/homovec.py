import numpy as np
from gmpy2 import mpz

import paillier

DEFAULT_KEYSIZE = 512  # set here the default number of bits of the RSA modulus
DEFAULT_MSGSIZE = 64  # set here the default number of bits the plaintext can have
DEFAULT_SECURITYSIZE = 100  # set here the default number of bits for the one time pads
DEFAULT_PRECISION = int(DEFAULT_MSGSIZE / 2)  # set here the default number of fractional bits


def generate_keypair():
    return paillier.generate_paillier_keypair()


def encrypt_vector(pubkey, x, coins=None):
    if (coins == None):
        return [pubkey.encrypt(y) for y in x]
    else:
        return [pubkey.encrypt(y, coins.pop()) for y in x]


def sum_encrypted_vectors(x, y):
    return [x[i] + y[i] for i in range(np.size(x))]


def diff_encrypted_vectors(x, y):
    return [x[i] - y[i] for i in range(np.size(x))]


def mult_vect_by_constant(x, const):
    return [x[i] * const for i in range(np.size(x))]


def decrypt_vector(privkey, x):
    return np.array([privkey.decrypt(i) for i in x])


def fp(scalar, prec=DEFAULT_PRECISION):
    return mpz(scalar * (2 ** prec))


def fp_vector(vec, prec=DEFAULT_PRECISION):
    return [fp(x, prec) for x in vec]


def retrieve_fp(scalar, prec=DEFAULT_PRECISION):
    return scalar / (2 ** prec)


def retrieve_fp_vector(vec, prec=DEFAULT_PRECISION):
    return [retrieve_fp(x, prec) for x in vec]
