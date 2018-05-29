import hashlib
import binascii
import operator
import math
import sys

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
        # if not (0 <= s <= self.n-1):
        #     raise Exception("s not within 0 and n - 1")
        return self.rsaep(s)

    def rsaep(self, m):
        # if not (0 <= m <= self.n-1):
        #     raise Exception("m not within 0 and n - 1")
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
        # if not (0 <= c <= self.n-1):
        #     raise Exception("c not within 0 and n - 1")
        return pow(c, self.d, self.n)

    def rsasp1(self, m):
        # if not (0 <= m <= self.n-1):
        #     print(m)
        #     raise Exception("m not within 0 and n - 1")
        return self.rsadp(m)

# https://stackoverflow.com/questions/39964383/implementation-of-i2osp-and-os2ip
# def i2osp(x, xLen):
#     if x >= 256^xLen:
#         raise ValueError("integer too large")
#     digits = []

#     while x:
#         digits.append(int(x % 256))
#         x //= 256
#     for i in range(xLen - len(digits)):
#         digits.append(0)
#     return digits[::-1]

# def os2ip(X):
#     xLen = len(X)
#     X = X[::-1]
#     x = 0
#     # print(X)
#     for i in range(xLen):
#         # print(X[i])
#         x += X[i] * (256^i)
#     return x

def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if x > 256**x_len:
        raise ValueError("integer too large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''Converts the byte string x representing an integer reprented using the
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

# https://en.wikipedia.org/wiki/Mask_generation_function
# def i2osp(integer, size=4):
#     return ''.join([chr((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])

# def mgf1(input, length, hash=hashlib.sha1):
#     def i2osp(integer, size=4):
#         return ''.join([chr((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])
#     counter = 0
#     output = ''
#     while (len(output) < length):
#         C = i2osp(counter, 4)
#         output += hash(input + C).digest()
#         counter += 1
#     return output[:length]

# RSA-FDH-VRF https://tools.ietf.org/html/draft-goldbe-vrf-01#section-4
def VRF_prove(private_key, alpha, k):
    # k is the length of pi
    EM = mgf1(alpha, k-1)
    m = os2ip(EM)
    s = private_key.rsasp1(m)
    pi = i2osp(s, k)
    return pi

def VRF_proof2hash(pi, hash=hashlib.sha1):
    beta = hash(pi).digest()
    return beta

def VRF_verifying(public_key, alpha, pi):
    k = len(pi)
    s = os2ip(pi)
    m = public_key.rsavp1(s)
    EM = i2osp(m, k-1)
    EM_ = mgf1(alpha, k-1)
    print "EM: %s" % (str(EM))
    print "EM_: %s" % (str(EM_))
    if EM == EM_:
        return "VALID"
    else:
        return "INVALID"

if __name__ == "__main__":
    n = 1000000
    e = 200
    d = 300
    public_key = RsaPublicKey(n, e)
    private_key = RsaPrivateKey(n, d)
    k = 20
    alpha = "encryptme"
    pi = VRF_prove(private_key, alpha, k)
    beta = VRF_proof2hash(pi)
    print(VRF_verifying(public_key, alpha, beta))
