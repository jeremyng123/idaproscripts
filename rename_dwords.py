import ida_idaapi, ida_kernwin, ida_bytes, ida_name
import sys
import random
import re
import tkinter as tk
from tkinter import filedialog


# Function to do the actual renaming of the dword
def rename_global_dword(addr, new_name):
    print('Old Name %s' % ida_name.get_name(addr))
    try:
        ida_name.set_name(addr, new_name, ida_name.SN_CHECK)
    except:
        ida_name.set_name(addr, new_name + "_" + str(addr), ida_name.SN_CHECK)
    print('New Name %s' % ida_name.get_name(addr))


def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def get_var_name(addr):
    old_name = ida_name.get_name(addr)
    print(old_name)
    # new_byte = orig_byte ^ key
    # patch_byte(addr, new_byte)


# Iterate through each line of the text file
root = tk.Tk()
root.withdraw()
file_path = filedialog.askopenfilename()
keep_lib_prefix = ida_kernwin.ask_yn(1, "HIDECANCEL\nKeep library prefix?")
with open(file_path, 'r') as f:
    for line in f:
        # Get the address from the first column
        libfunc = line.split(".")[1][:-2]
        print(libfunc)
        # addr_hex = int(addr, 16)
        start = 0x0280F00C
        end = 0x0280F180+4
        step = 4
        pointer = start

        # Make sure the size at that location is a dword

        if ida_bytes.get_item_size(pointer) < 4:
            print('Making %i a dword' % pointer)
            ida_bytes.create_data(pointer, ida_bytes.FF_DWORD, 4,
                                  ida_idaapi.BADADDR)

        # Call our custom function to rename the dword
        rename_global_dword(pointer, libfunc)
        pointer += step