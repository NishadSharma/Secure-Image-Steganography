# tests/test_crypto.py
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src import crypto


def test_encrypt_decrypt_roundtrip():
    message = b"Hello Stego!"
    passphrase = "strongpassword"
    blob = crypto.encrypt(message, passphrase)
    out = crypto.decrypt(blob, passphrase)
    assert out == message

def test_decrypt_with_wrong_password():
    message = b"Top Secret Data"
    blob = crypto.encrypt(message, "correct_pass")
    with pytest.raises(Exception):  # should fail on wrong password
        crypto.decrypt(blob, "wrong_pass")

def test_empty_message():
    message = b""
    passphrase = "emptytest"
    blob = crypto.encrypt(message, passphrase)
    out = crypto.decrypt(blob, passphrase)
    assert out == message

def test_large_message():
    message = b"A" * 10_000  # 10 KB message
    passphrase = "largemessage"
    blob = crypto.encrypt(message, passphrase)
    out = crypto.decrypt(blob, passphrase)
    assert out == message
