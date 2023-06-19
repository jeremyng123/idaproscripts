from ida_bytes import get_byte, patch_byte
from ida_kernwin import read_selection
from idc import get_screen_ea, read_selection_start, read_selection_end, get_bytes
from idaapi import twinpos_t, get_current_viewer

def apply_xor_key(start, end, key):
    for addr in range(start, end):
        orig_byte = get_byte(addr)
        new_byte = orig_byte ^ key
        patch_byte(addr, new_byte)

def main(xor_key):
    # start = read_selection_start()
    # end = read_selection_end()
    start = 0x1000212c
    end = 0x10019ce7
    apply_xor_key(start,end, xor_key)
        


if __name__ == "__main__":
    main(0x25)