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

def disp(array):
    print map(lambda x : x.encode("hex"), array)

def wrap(K, P):
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

KEK = from_hex("000102030405060708090A0B0C0D0E0F")
key_data = [from_hex("0011223344556677"), from_hex("8899AABBCCDDEEFF")]

wrapped_key = wrap(KEK, key_data)
print map(lambda x : x.encode("hex").upper(), wrapped_key)
unwrapped_key = unwrap(KEK, wrapped_key)
print map(lambda x : x.encode("hex").upper(), unwrapped_key)



