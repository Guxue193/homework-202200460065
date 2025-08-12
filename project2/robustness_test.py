
import cv2
from extract_watermark import extract_watermark

def apply_attack(img_path, attack_type):
    img = cv2.imread(img_path)

    if attack_type == 'flip':
        attacked = cv2.flip(img, 1)
    elif attack_type == 'crop':
        h, w = img.shape[:2]
        attacked = img[h//4:3*h//4, w//4:3*w//4]
        attacked = cv2.resize(attacked, (w, h))
    elif attack_type == 'contrast':
        attacked = cv2.convertScaleAbs(img, alpha=1.8, beta=0)
    elif attack_type == 'rotate':
        h, w = img.shape[:2]
        M = cv2.getRotationMatrix2D((w//2, h//2), 10, 1)
        attacked = cv2.warpAffine(img, M, (w, h))
    else:
        raise ValueError("Unknown attack type.")

    return attacked

if __name__ == '__main__':
    attacked_img = apply_attack('results/watermarked.png', 'contrast')
    cv2.imwrite('results/attacked.png', attacked_img)
    wm = extract_watermark('results/attacked.png', shape=(32, 32))
    cv2.imwrite('results/extracted_after_attack.png', wm)
