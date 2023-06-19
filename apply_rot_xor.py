from ida_bytes import get_byte, patch_byte
from ida_kernwin import read_selection
from idc import get_screen_ea, read_selection_start, read_selection_end, get_bytes
from idaapi import twinpos_t, get_current_viewer


def apply_xor_key(start, end, key):
    for addr in range(start, end):
        orig_byte = get_byte(addr)
        new_byte = orig_byte ^ key
        patch_byte(addr, new_byte)


def apply_rot_xor_key(start, end, key):
    keylen = len(key)
    for i, addr in enumerate(range(start, end)):
        orig_byte = get_byte(addr)
        new_byte = orig_byte ^ (key[i % keylen])
        patch_byte(addr, new_byte)


def main(xor_key):
    # start = read_selection_start()
    # end = read_selection_end()
    start = 0x2000c0
    end = start + 0x1F58 - 0xb0
    apply_rot_xor_key(start, end, xor_key)


if __name__ == "__main__":
    # main(0x25)
    rot_key = [
        0x51, 0x58, 0x75, 0x30, 0x78, 0x66, 0x34, 0x7D, 0xCB, 0x96, 0x68, 0x84,
        0x0A, 0x37, 0xCF, 0xE4
    ]
    main(rot_key)