# src/crypto.py
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import struct

SALT_LEN = 16
KEY_LEN = 32  # 256 bits
PBKDF2_ITERS = 200_000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=None)

def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """
    Returns a packed blob: salt(16) || nonce_len(1) || nonce || ciphertext_len(4) || ciphertext || tag_len(1) || tag
    We pack lengths so extraction is deterministic.
    """
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce  # 12 bytes typically
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    out = salt + struct.pack('B', len(nonce)) + nonce + struct.pack('>I', len(ciphertext)) + ciphertext + struct.pack('B', len(tag)) + tag
    return out

def decrypt(blob: bytes, passphrase: str) -> bytes:
    idx = 0
    salt = blob[idx:idx+SALT_LEN]; idx += SALT_LEN
    nonce_len = blob[idx]; idx += 1
    nonce = blob[idx:idx+nonce_len]; idx += nonce_len
    ciphertext_len = struct.unpack('>I', blob[idx:idx+4])[0]; idx += 4
    ciphertext = blob[idx:idx+ciphertext_len]; idx += ciphertext_len
    tag_len = blob[idx]; idx += 1
    tag = blob[idx:idx+tag_len]; idx += tag_len
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
