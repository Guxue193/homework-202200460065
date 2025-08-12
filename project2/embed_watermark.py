
import cv2
import numpy as np
from utils import dct2, idct2

def embed_watermark(host_img_path, watermark_img_path, output_path, alpha=10):
    host = cv2.imread(host_img_path, cv2.IMREAD_GRAYSCALE)
    watermark = cv2.imread(watermark_img_path, cv2.IMREAD_GRAYSCALE)
    watermark = cv2.resize(watermark, (host.shape[0]//8, host.shape[1]//8))
    watermark = np.round(watermark / 255)

    blocks = np.array_split(host, host.shape[0] // 8, axis=0)
    for i in range(len(blocks)):
        blocks[i] = np.array_split(blocks[i], host.shape[1] // 8, axis=1)

    for i in range(len(blocks)):
        for j in range(len(blocks[i])):
            block = blocks[i][j]
            dct_block = dct2(block)
            dct_block[4, 4] += alpha * watermark[i, j]
            blocks[i][j] = idct2(dct_block)

    result = np.vstack([np.hstack(blocks[i]) for i in range(len(blocks))])
    cv2.imwrite(output_path, result)
    print(f"Watermarked image saved to {output_path}")
