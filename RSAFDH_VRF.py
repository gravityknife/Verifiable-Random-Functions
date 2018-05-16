# RSA-FDH-VRF https://tools.ietf.org/html/draft-goldbe-vrf-01#section-4
def VRF_prove (K, alpha):
    EM = MGF1(alpha, k-1)
    m = OS2IP(EM)
    s = RSASP1(K, m)
    pi = I2OSP(s, k)
    return pi

def VRF_proof2hash(pi):
    beta = Hash(pi)
    return beta

def VRF_verifying(public_key, alpha, pi):
    s = OS2IP(pi)
    m = RSAVP1(public_key, s)
    EM = I2OSP(m, k-1)
    EM_ = MGF1(alpha, k-1)
    if EM == EM_:
        return "VALID"
    else:
        return "INVALID"



# primitives

# https://stackoverflow.com/questions/39964383/implementation-of-i2osp-and-os2ip
def i2osp(x, xLen):
    if x >= 256^xLen:
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(xLen - len(digits)):
        digits.append(0)
    return digits[::-1]

def os2ip(X):
    xLen = len(X)
    X = X[::-1]
    x = 0
    for i in range(xLen):
        x += X[i] * 256^i
    return x


# https://github.com/bdauvergne/python-pkcs1/blob/master/pkcs1/keys.py
def rsasp1(self, m):
    if not (0 <= m <= self.n-1):
        raise exceptions.MessageRepresentativeOutOfRange
    return self.rsadp(m)

def rsadp(self, c):
    if not (0 <= c <= self.n-1):
        raise exceptions.CiphertextRepresentativeOutOfRange
    return primitives._pow(c, self.d, self.n)

def rsavp1(self, s):
    if not (0 <= s <= self.n-1):
        raise exceptions.SignatureRepresentativeOutOfRange
    return self.rsaep(s)

def rsaep(self, m):
    if not (0 <= m <= self.n-1):
        raise exceptions.MessageRepresentativeOutOfRange
    return primitives._pow(m, self.e, self.n)


# https://en.wikipedia.org/wiki/Mask_generation_function
import hashlib

def i2osp(integer, size=4):
    return ''.join([chr((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])

def mgf1(input, length, hash=hashlib.sha1):
    counter = 0
    output = ''
    while (len(output) < length):
        C = i2osp(counter, 4)
        output += hash(input + C).digest()
        counter += 1
    return output[:length]
