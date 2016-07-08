import os
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def from_hex(s):
    return s.decode("hex")

def concat(s1, s2):
    s = (s1 + s2).encode("hex")
    return s1 + s2

def msb(j, W):
    j /= 8
    return W[0:j]

def lsb(j, W):
    j /= 8
    n = len(W)
    return W[len(W) - j:]

def to_bytes(n, length = 16):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s

def AES(K, B):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(K), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(B) + encryptor.finalize()
    return ct

def AESi(K, B):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(K), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    pt = decryptor.update(B) + decryptor.finalize()
    return pt

def xor(x, y):
    result = "".join(map(lambda (xx, yy): chr(ord(xx) ^ ord(yy)), zip(x, y)))
    return result

def wrap(K, P):
    ''' Wrap as specified in https://tools.ietf.org/html/rfc3394
    '''
    N = len(P)
    s = 6 * N

    A = from_hex("A6A6A6A6A6A6A6A6")
    R = P[:]

    for j in range(0, 6):
        for i in range(1, N + 1):
            input_block = concat(A, R[i - 1])
            B = AES(K, input_block)
            t = (N * j) + i
            msb_block = msb(64, B)
            A = xor(msb_block, to_bytes(t, length=8))
            R[i - 1] = lsb(64, B)

    C = [A]
    for i in range(1, N + 1):
        C.append(R[i - 1])

    return C

def unwrap(K, C):
    ''' Unwrap as specified in https://tools.ietf.org/html/rfc3394
    '''
    N = len(C) - 1
    A = C[0]
    R = C[1:]
    
    for j in range(5, -1, -1):
        for i in range(N, 0, -1):
            t = (N * j) + i
            input_block = concat(xor(A, to_bytes(t, length = 8)), R[i - 1])
            B = AESi(K, input_block)
            A = msb(64, B)
            R[i - 1] = lsb(64, B)

    return R

class TestCase(object):
    def __init__(self, kek, data, output):
        self.kek = from_hex(kek)
        self.data = data
        self.output = []
        for i in range(0, len(output), 16):
            self.output.append(from_hex(output[i:i+16]))

    def run(self):
        blocks = []
        for i in range(0, len(self.data), 16):
            blocks.append(from_hex(self.data[i:i+16]))

        output = wrap(self.kek, blocks)
        assert self.output == output

        original = unwrap(self.kek, output)
        assert original == blocks


# Test cases from https://tools.ietf.org/html/rfc3394 
test1 = TestCase("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
test2 = TestCase("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")
test3 = TestCase("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
test4 = TestCase("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
test5 = TestCase("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
test6 = TestCase("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")

# No assertions should fail
test1.run()
test2.run()
test3.run()
test4.run()
test5.run()
test6.run()
