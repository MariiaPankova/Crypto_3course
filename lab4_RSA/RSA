import Crypto.Random.random as cr
from  Crypto.Random import get_random_bytes
from Crypto.Util.number import GCD
import math
from bitstring import Bits


def e_gcd(a, b):
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mod_inv(a, m):
    g, x, y = e_gcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m


def miller_rabin(n, false_positive_prob=1e-6) -> bool:
    # number of iterations calculated from false positive error probability.
    k = int(math.ceil(-math.log(false_positive_prob)/math.log(4)))
    if n & 0:
        return True

    # find such s and m that n-1 = 2**s * m where m is odd.
    m = n - 1
    s = 0
    while m & 0:
        m = m // 2
        s += 1

    for j in range(k):
        a = cr.randint(2, n-2)
        b = pow(a, m, n)
        if b != 1 and b != n - 1:
            i = 1
            while i < s and b != n - 1:
                b = pow(b, 2, n)
                if b == 1:
                    return False
                i += 1
            if b != n - 1:
                return False
    return True


def prandom(len=256, false_positive_prob=1e-6):
    p=44
    while not miller_rabin(p, false_positive_prob):
        p = int.from_bytes(get_random_bytes(len), 'big')
        p |= (1<< len * 8 - 1)
    return p


def RSA_get_params(byte_len=256):
    p = prandom(byte_len//2)
    q = prandom(byte_len//2)
    phi = (p - 1) * (q - 1)
    e = 0
    while e == 0 or e > phi or GCD(e, phi) != 1:
        e = cr.randint(16, phi)
    print(e)
    d = mod_inv(e, phi)
    assert (e * d) % phi == 1
    return p*q, e, d


def RSA_encrypt(e, n, message):
    x = pow(int.from_bytes(message, 'big'), e, n)
    return x.to_bytes((x.bit_length()+7)//8, 'big')


def RSA_decrypt(d, n, message):
    x = pow(int.from_bytes(message, 'big'), d, n)
    return x.to_bytes((x.bit_length()+7)//8, 'big')


def OAEP_enc(m, g, h, k0, k1):
    assert len(m) * 8 == g.out_size - k1, "Wrong message length"

    m = Bits(m.ljust(g.out_size//8, b'\0'))
    r = get_random_bytes(k0//8)

    x = m ^ g(r).bits
    y = h(x.bytes).bits ^ Bits(r)
    return (x+y).tobytes()


def OAEP_dec(m, g, h, k0, k1):
    m = Bits(m)
    assert len(m) - k0 == g.out_size, 'cryptotext has been modified'
    x = m[:len(m)-k0]
    y = m[len(m) - k0:]
    r = y ^ h(x.bytes).bits
    padded_m = x ^ g(r.bytes).bits
    out = padded_m[:len(m) - k0 - k1]
    pad = padded_m[len(m) - k0 - k1:]
    assert not any(pad), 'cryptotext has been modified'
    return out.tobytes()


def OAEP_encrypt(e, n, k0, k1, g, h, message):
    return RSA_encrypt(e, n, OAEP_enc(message, g, h, k0, k1))


def OAEP_decrypt(d, n, k0, k1, g, h, message):
    return OAEP_dec(RSA_decrypt(d, n, message), g, h, k0, k1)


if __name__ == '__main__':
    from lab3_SHA.SHA import  *
    #print(miller_rabin(99999))
    N, e, d = RSA_get_params()
    print(" N:  ", N, '\n',
          "e:  ", e, '\n',
          "d:  ", d, '\n')

    plaintext = b'The quick brown fox jumps over the lazy dog.'
    print("Message:  ", plaintext)
    ct = RSA_encrypt(e, N, plaintext)
    print("Encrypted:  ", ct)
    decrypted = RSA_decrypt(d, N, ct)
    print("Decrypted:  ", decrypted)
    print("------------------------OAEP-RSA----------------------------")
    message = b"test"
    print(message)
    k0 = 256
    k1 = 256 - len(message) * 8
    oaep_ct = OAEP_encrypt(e, N, k0, k1, mySHA256, mySHA256, message)
    print(oaep_ct)
    oaep_pt = OAEP_encrypt(d, N, k0, k1, mySHA256, mySHA256, oaep_ct)
    print(oaep_pt)

