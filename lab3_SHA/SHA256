import os
import pickle
from numpy.random import randint
from os import urandom
from bitstring import BitArray, Bits
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC as crHMAC


def load_constants():
    """ Loads initial hash values - "H" and round constants "K".
    :return: (H, K)
    """
    this_dir, this_filename = os.path.split(__file__)
    data_path = os.path.join(this_dir, 'constants.pkl')

    with open(data_path, 'rb') as f:
        constants = pickle.load(f)
    return constants["H"], constants['K']


def padding(message):
    l = len(message) * 8
    k = (448 - l - 1) % 512
    pad = b'1' + b'0' * k + bin(l)[2:].rjust(64, '0').encode()
    pad = hex(int(pad, 2))
    message += bytes.fromhex(pad[2:])
    return message


def split_message(message):
    for i in range(len(message)//64):
        chunk = message[i * 64: (i+1) * 64]
        yield [Bits(chunk[j*4: (j+1)*4]) for j in range(16)]


def rrot(x, n):
    w = len(x)
    assert 0 <= n < w
    return x >> n | x << (w - n)


def lrot(x, n):
    w = len(x)
    assert 0 <= n < w
    return x << n | x >> (w - n)


def shr(x, n):
    w = len(x)
    assert 0 <= n < w
    return x >> n


MODULUS = 2 ** 32
def bits_sum(*args, width=8):
    rez = 0
    for bits in args:
        assert isinstance(bits, Bits)
        rez = (rez + bits.intbe) % MODULUS
    return Bits("{0:#0{1}x}".format(rez, width+2), length=32)


class mySHA256:
    block_size = 512
    out_size = 256

    def __init__(self, message):
        self.chunk_gen = split_message(padding(message))
        #self.hash = self._encode()
        self.H, self.K = load_constants()
        self.hash = self._encode()

    def _encode_block(self, chunk: list):
        for i in range(16, 64):
            s1 = rrot(chunk[i - 2], 17) ^ rrot(chunk[i - 2], 19) ^ shr(chunk[i - 2], 10)
            s0 = rrot(chunk[i - 15], 7) ^ rrot(chunk[i - 15], 18) ^ shr(chunk[i - 15], 3)
            chunk += [bits_sum(chunk[i - 7], s0, chunk[i - 16], s1)]

        a, b, c, d, e, f, g, h = self.H

        for i in range(64):
            S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = bits_sum(h, S1, ch, self.K[i], chunk[i])
            S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = bits_sum(S0, maj)
            h, g, f, e, d, c, b, a = g, f, e, bits_sum(d, temp1), c, b, a, bits_sum(temp2, temp1)

        self.H = [bits_sum(*t) for t in zip(self.H, [a, b, c, d, e, f, g, h])]

    def _encode(self):
        for chunk in self.chunk_gen:
            self._encode_block(chunk)
        return sum(self.H)

    @property
    def hex(self):
        return self.hash.hex

    @property
    def bytes(self):
        return self.hash.tobytes()

    @property
    def bits(self):
        return self.hash

    @property
    def aes128_key_bytes(self):
        return self.hash[128:].tobytes()

    @property
    def aes128_key_hex_dec(self):
        return self.hex[32:]

def HMAC_key(key):
    if len(key)*8 > mySHA256.block_size:
        key = mySHA256(key).bytes
    return Bits(key.ljust(mySHA256.block_size//8, b'\x00'))

def HMAC_encode(key, message):
    key = HMAC_key(key)
    o_pad = key ^ Bits('0x'+'5c'*(mySHA256.block_size//8))
    i_pad = key ^ Bits('0x'+'36'*(mySHA256.block_size//8))
    a = o_pad.tobytes() + mySHA256(i_pad.tobytes() + message).bytes
    return mySHA256(a)

if __name__ == '__main__':
    N = randint(0, 5120)
    message = urandom(N)
    print("Message:  \n", message, '\n')
    buildin = SHA256.SHA256Hash(message).hexdigest()
    print("Crypto.Hash implementation:   \n", buildin, '\n')
    sha = mySHA256(message)
    print("My implementation:   \n", sha._encode().hex, '\n')
    print("------------------------------AES-128 KEY GEN------------------------------------------")
    key = b"my good key"
    sha = mySHA256(key)
    print("Generatedd key:   \n", sha.aes128_key_bytes, '\n')
    print("Hexdigest:   \n", sha.aes128_key_hex_dec, '\n')
    print("------------------------------------HMAC-----------------------------------------------")
    key_length = randint(0, 800)
    key = urandom(key_length)
    print("Crypto.Hash implementation:   \n", crHMAC.new(key=key, msg=message, digestmod=SHA256).hexdigest(), '\n')
    print("My implementation:   \n", HMAC_encode(key, message).hex, '\n')






