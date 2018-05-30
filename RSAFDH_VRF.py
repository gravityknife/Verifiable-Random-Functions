import hashlib
import binascii
import operator
import math
import sys
from sys import argv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
# https://github.com/bdauvergne/python-pkcs1/blob/master/pkcs1/keys.py
def integer_byte_size(n):
    '''Returns the number of bytes necessary to store the integer n.'''
    quanta, mod = divmod(integer_bit_size(n), 8)
    if mod or n == 0:
        quanta += 1
    return quanta

def integer_bit_size(n):
    '''Returns the number of bits necessary to store the integer n.'''
    if n == 0:
        return 1
    s = 0
    while n:
        s += 1
        n >>= 1
    return s

def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta

class RsaPublicKey(object):
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPublicKey n: %d e: %d bit_size: %d>' % (self.n, self.e, self.bit_size)

    def rsavp1(self, s):
        if not (0 <= s <= self.n-1):
            raise Exception("s not within 0 and n - 1")
        return self.rsaep(s)

    def rsaep(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return pow(m, self.e, self.n)

class RsaPrivateKey(object):
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPrivateKey n: %d d: %d bit_size: %d>' % (self.n, self.d, self.bit_size)

    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise Exception("c not within 0 and n - 1")
        return pow(c, self.d, self.n)

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return self.rsadp(m)

def i2osp(x, x_len):
    '''
    Converts the integer x to its big-endian representation of length
    x_len.
    '''
    # if x > 256**x_len:
    #     raise ValueError("integer too large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''
    Converts the byte string x representing an integer reprented using the
    big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    '''
    Mask Generation Function v1 from the PKCS#1 v2.0 standard.
    mgs_seed - the seed, a byte string
    mask_len - the length of the mask to generate
    hash_class - the digest algorithm to use, default is SHA1
    Return value: a pseudo-random mask, as a byte string
    '''
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = b''
    for i in xrange(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]

# RSA-FDH-VRF https://tools.ietf.org/html/draft-goldbe-vrf-01#section-4
def VRF_prove(public_key, private_key, alpha, k):
    # k is the length of pi
    EM = mgf1(alpha, k-1)
    m = os2ip(EM)
    s = private_key.rsasp1(m)
    pi = i2osp(s, k)
    return pi

def VRF_proof2hash(pi, hash=hashlib.sha1):
    beta = hash(pi).digest()
    return beta

def VRF_verifying(public_key, alpha, pi, k):
    s = os2ip(pi)
    m = public_key.rsavp1(s)
    EM = i2osp(m, k-1)
    EM_ = mgf1(alpha, k-1)
    if EM == EM_:
        return "VALID"
    else:
        return "INVALID"

if __name__ == "__main__":
    if len(argv) < 2:
        print "USAGE: python RSAFDH_VRF.py [alpha]"
        exit(1)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    private_numbers = private_key.private_numbers()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    d = private_numbers.d
    k = 20
    public_key = RsaPublicKey(n, e)
    private_key = RsaPrivateKey(n, d)
    alpha = " ".join(argv[1:])
    pi = VRF_prove(public_key, private_key, alpha, k)
    beta = VRF_proof2hash(pi)
    print(VRF_verifying(public_key, alpha, pi, k))
