# tests/test_stego.py
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from src import stego, utils

def test_embed_and_extract(tmp_path):
    cover = "examples/cover.jpg"  # make sure this exists in your repo
    stego_path = tmp_path / "stego.png"
    message = b"SecretMessage123"
    stego.embed_bytes_into_image(cover, message, stego_path)
    extracted = stego.extract_bytes_from_image(stego_path)
    assert extracted == message

def test_payload_too_large(tmp_path):
    cover = "examples/cover.jpg"
    stego_path = tmp_path / "stego.png"
    # create a huge payload (1 MB)
    message = b"A" * (1024 * 1024)
    with pytest.raises(ValueError):  # should fail due to insufficient capacity
        stego.embed_bytes_into_image(cover, message, stego_path)

def test_psnr_after_embedding(tmp_path):
    from src.utils import psnr
    cover = "examples/cover.jpg"
    stego_path = tmp_path / "stego.png"
    message = b"ShortMessage"
    stego.embed_bytes_into_image(cover, message, stego_path)

    img_cover = Image.open(cover).convert("RGB")
    img_stego = Image.open(stego_path).convert("RGB")
    value = psnr(img_cover, img_stego)

    assert value > 35  # PSNR should be high enough for imperceptibility
