from idautils import *
from idc import *

# Byte() == get_wide_byte(ea)
# PatchByte == patch_byte(ea, new_byte)

sea = get_screen_ea()
print(f"Starting at address {sea}")

for i in range(0x00, 0x50):
    b = get_wide_byte(sea + i)
    decoded_byte = b ^ 0x55
    patch_byte(sea + i, decoded_byte)
