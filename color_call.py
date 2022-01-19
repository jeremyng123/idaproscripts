from idautils import *
from idc import *

# SegStart == get_segm_start
# SegEnd == get_segm_end
# ScreenEA == get_screen_ea
# GetMnem == print_insn_mnem
# SetColor == set_color

heads = Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea()))
jump_instr = [
    "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc",
    "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge",
    "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz",
    "jecxz", "jmp"
]  # http://unixwiz.net/techtips/x86-jumps.html

functionCalls = []
jumpCalls = []
for i in heads:
    # get operands (first and 2nd operands)
    # operand_1 = print_operand(i, 0)
    # operand_2 = print_operand(i, 1)
    # if "eip" in operand_1 or "eip" in operand_2:
    #     print(operand_1, operand_2)
    if print_insn_mnem(i) == "call":
        functionCalls.append(i)
    elif print_insn_mnem(i) in jump_instr:
        jumpCalls.append(i)

print(f"Number of calls founds {len(functionCalls)}")
print(f"Number of jumps founds {len(jumpCalls)}")

for i in functionCalls:
    set_color(i, CIC_ITEM, 0xc7fdff)

for i in jumpCalls:
    set_color(i, CIC_ITEM, 0xaed088)