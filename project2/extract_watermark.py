
import cv2
import numpy as np
from utils import dct2

def extract_watermark(watermarked_img_path, shape=(32, 32), alpha=10):
    img = cv2.imread(watermarked_img_path, cv2.IMREAD_GRAYSCALE)
    wm = np.zeros(shape)

    blocks = np.array_split(img, shape[0], axis=0)
    for i in range(shape[0]):
        blocks[i] = np.array_split(blocks[i], shape[1], axis=1)

    for i in range(shape[0]):
        for j in range(shape[1]):
            dct_block = dct2(blocks[i][j])
            wm[i, j] = dct_block[4, 4] / alpha > 0.5

    return np.uint8(wm * 255)
