from cryptography.hazmat.primitives.asymmetric import ec

# Useful links
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
# https://tools.ietf.org/id/draft-goldbe-vrf-01.html

# os2ecp = from_encoded_points
# ecp2os = encode_point


def ECVRF_prove(y, x, alpha):
	pass


# TODO: Plug in a hash function and figure out what cofactor is and figure out if ** is ok
def ECVRF_proof2hash(pi):
	D = ECVRF_decode_proof(pi)
	if D == "INVALID":
		return "INVALID"
	gamma, c, s = D
	ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP384R1(), gamma**cofactor)
	return beta


def ECVRF_verify(y, pi, alpha):
	pass


# TODO: Plug in a hash function and figure out what cofactor is and figure out if ** is ok
# assumes y is a instance of ec.EllipticCurvePublicNumbers
def ECVRF_hash2curve(y, alpha):
	ctr = 0
	pk = y.encode_point()
	h = "INVALID"
	while h == "INVALID":
		CTR = i2osp(ctr, 4)
		ctr += 1
		attempted_hash = Hash(pk + alpha + CTR)
		if attempted_hash == 0:
			h = "INVALID" # same as infinity
		try:
			h = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP384R1(), b'0x04'+attempted_hash)
		except (ValueError err):
			h = "INVALID"
		if h is not "INVALID" and cofactor > 1:
			h = h ** cofactor 
	return h

# TODO: plug in hash
# assumes points is an array of ec.EllipticCurvePublicNumbers
def ECVRF_hash_points(points):
	P = ""
	for p_i in points:
		P += p_i.encode_point()
	h1 = Hash(P)
	h2 = "idk"
	h = os2ip(h2)
	return h


def ECVRF_decode_proof(pi):
	pass


def ECVRF_validate_key(PK):
	pass


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


# TODO: 16 is hard coded?
def os2ip(x):
    '''
    Converts the byte string x representing an integer reprented using the
    big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)
