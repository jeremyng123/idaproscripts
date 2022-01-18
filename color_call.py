from idautils import *
from idc import *

# SegStart == get_segm_start
# SegEnd == get_segm_end
# ScreenEA == get_screen_ea
# GetMnem == print_insn_mnem
# SetColor == set_color

heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))

functionCalls = []
for i in heads:
    if print_insn_mnem(i) == "call":
        functionCalls.append(i)

print(f"Number of calls founds {len(functionCalls)}")

for i in functionCalls:
    set_color(i, CIC_ITEM, 0xc7fdff)