# src/stego.py
from PIL import Image
import math

def _int_to_bitlist(n: int, length: int):
    return [(n >> i) & 1 for i in reversed(range(length))]

def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in reversed(range(8)):
            yield (byte >> i) & 1

def _bits_to_bytes(bits):
    b = 0
    out = bytearray()
    for i, bit in enumerate(bits):
        b = (b << 1) | bit
        if (i + 1) % 8 == 0:
            out.append(b)
            b = 0
    return bytes(out)

def capacity_in_bits(image: Image.Image, channels=3):
    w, h = image.size
    return w * h * channels  # using 1 LSB per channel

HEADER_LEN_BYTES = 8  # we'll store payload length in first 8 bytes (unsigned 64-bit)

def embed_bytes_into_image(cover_image_path: str, payload: bytes, out_path: str, channels=(0,1,2)):
    img = Image.open(cover_image_path)
    img = img.convert('RGB')
    w, h = img.size
    max_bits = capacity_in_bits(img, channels=len(channels))
    total_payload_bits = (HEADER_LEN_BYTES + len(payload)) * 8
    if total_payload_bits > max_bits:
        raise ValueError(f"Payload too large for cover image. Need {total_payload_bits} bits, have {max_bits} bits.")
    pixels = list(img.getdata())
    bitgen = _bytes_to_bits(struct.pack('>Q', len(payload)) + payload)  # big-endian length + payload
    new_pixels = []
    for p in pixels:
        r, g, b = p
        rgb = [r, g, b]
        for ch_index in channels:
            try:
                bit = next(bitgen)
                rgb[ch_index] = (rgb[ch_index] & ~1) | bit
            except StopIteration:
                # remaining channels stay same
                pass
        new_pixels.append(tuple(rgb))
    out = Image.new('RGB', (w,h))
    out.putdata(new_pixels)
    out.save(out_path, 'PNG')

import struct
def extract_bytes_from_image(stego_image_path: str, channels=(0,1,2)):
    img = Image.open(stego_image_path).convert('RGB')
    pixels = list(img.getdata())
    bits = []
    for p in pixels:
        for ch_index in channels:
            bits.append(p[ch_index] & 1)
    # read header first
    header_bits = bits[:HEADER_LEN_BYTES*8]
    header_bytes = _bits_to_bytes(header_bits)
    payload_len = struct.unpack('>Q', header_bytes)[0]
    total_bits = (HEADER_LEN_BYTES + payload_len) * 8
    payload_bits = bits[HEADER_LEN_BYTES*8: total_bits]
    payload = _bits_to_bytes(payload_bits)
    return payload
