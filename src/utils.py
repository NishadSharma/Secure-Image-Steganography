# src/utils.py
from PIL import Image
import numpy as np
import math

def mse(image1: Image.Image, image2: Image.Image):
    a = np.array(image1).astype(np.float64)
    b = np.array(image2).astype(np.float64)
    return np.mean((a - b) ** 2)

def psnr(image1: Image.Image, image2: Image.Image):
    m = mse(image1, image2)
    if m == 0:
        return float('inf')
    max_pixel = 255.0
    return 20 * math.log10(max_pixel / math.sqrt(m))
