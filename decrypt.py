import os
import hashlib
from glob import glob


def generate_mask_list(filename):
    base_filename = os.path.splitext(os.path.basename(filename))[0].lower()
    md5_hash = hashlib.md5(base_filename.encode('utf-8')).hexdigest()
    mask_list = [
        int(md5_hash[:16], 16),
        int(md5_hash[16:], 16),
        int(md5_hash[:8] + md5_hash[16:24], 16),
        int(md5_hash[8:16] + md5_hash[24:], 16)
    ]
    return mask_list


def decrypt_file(input_file, mask_list):
    with open(input_file, 'rb') as f:
        file_data = f.read()
    decrypt_size = min(len(file_data), 212)
    decrypted_data = bytearray(file_data[:decrypt_size])
    for i in range(decrypt_size):
        mask_index = i // 8
        mask_value = mask_list[mask_index % len(mask_list)]
        byte_of_interest = (mask_value >> (8 * (i % 8))) & 0xff
        decrypted_data[i] ^= byte_of_interest

    return decrypted_data + file_data[decrypt_size:]


def main(i_f):
    output_folder = os.path.join(i_f, 'decrypted')
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for input_file in glob(os.path.join(i_f, '*.asset')):
        mask_list = generate_mask_list(input_file)
        decrypted_data = decrypt_file(input_file, mask_list)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f'Decrypted: {input_file} -> {output_file}')


if __name__ == '__main__':
    input_folder = '1'  # 改成你自己的输入文件夹路径
    main(input_folder)

