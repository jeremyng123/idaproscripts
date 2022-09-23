from arc4 import ARC4
from binascii import unhexlify, hexlify
import argparse
import os
import pefile
import re

# def rc4_decrypt(key, data):
#     cipher = ARC4(key)
#     return cipher.decrypt(data)

_20bytes_key = "[a-zA-Z0-9]{20}"
# config_plus_key = ".{750,}" + _20bytes_key


def search_get_size(bytedata, token):
    # matches = re.findall(token.encode('utf-8'), bytedata)
    p = re.compile(token)
    size = next(p.finditer(bytedata)).start()
    return size


def retrieve_config(file):
    search_get_size(file, _20bytes_key)


# def arc4_extract_config_from_file(file):
#     rc4_decrypt = lambda key, data: ARC4(key).decrypt(data)
#     offset = retrieve_config(file)
#     key = file[offset:]
#     print(key)
#     # data = config[8:size]

#     return (" | ".join(
#         block
#         for block in rc4_decrypt(key, data).decode('latin-1').split("\x00")
#         if block != ''))


def arc4_decrypt_config(config):
    rc4_decrypt = lambda key, data: ARC4(key.encode("latin-1")).decrypt(
        data.encode("latin-1"))
    size = search_get_size(config, _20bytes_key)
    print(size)
    key = config[size:].split('\0')[0]
    data = config[4:size]
    # print(data)

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
        encr_config = config_extract(args.pefile).decode('latin-1')
        decr_config = arc4_decrypt_config(encr_config)
        print(decr_config)
    else:
        parser.error("at least one of --pefile or --config required")
