from arc4 import ARC4
from binascii import unhexlify, hexlify
import argparse
import os
import pefile
import re

# def rc4_decrypt(key, data):
#     cipher = ARC4(key)
#     return cipher.decrypt(data)

null_ending_bytes = b"\x00\x00\x00\x00"


def search_get_size(bytedata, token):
    # matches = re.findall(token.encode('utf-8'), bytedata)
    p = re.compile(token)
    size = next(p.finditer(bytedata)).start()
    return size


def arc4_decrypt_config(config):
    rc4_decrypt = lambda key, data: ARC4(key).decrypt(data)
    size = search_get_size(config, null_ending_bytes)
    key = config[:8]
    data = config[8:size]

    return (" | ".join(
        block
        for block in rc4_decrypt(key, data).decode('latin-1').split("\x00")
        if block != ''))


def config_extract(filename):
    pe = pefile.PE(filename)
    # pe.sections == list
    for section in pe.sections:
        # print(section.Name.decode('utf-8'))
        if (".data" in section.Name.decode('utf-8').strip()):
            # print(section.VirtualAddress)
            return section.get_data()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CAST-128 algorithm')
    parser.add_argument('-p',
                        '--pefile',
                        metavar='PEFILE',
                        type=str,
                        help='Target PE file to extract icedid config')

    parser.add_argument(
        '-c',
        '--config',
        metavar='CONFIG',
        type=str,
        help=
        'Input as hexadecimal string. First 8 bytes contains the key of the config, and the rest is the data. will be decrypted with RC4'
    )

    parser.add_argument('-o',
                        '--output_file',
                        metavar='OUTPUT',
                        type=str,
                        help='Filename to save results to')
    args = parser.parse_args()
    if args.config is not None:
        decrypted_config = arc4_decrypt_config(unhexlify(args.config))
        if args.output_file is not None:
            with open(args.output_file, 'w') as f:
                f.write(decrypted_config)
        else:
            print(decrypted_config)
    elif args.pefile is not None:
        encr_config = config_extract(args.pefile)
        decr_config = arc4_decrypt_config(encr_config)
        print(decr_config)
    else:
        parser.error("at least one of --pefile or --config required")
