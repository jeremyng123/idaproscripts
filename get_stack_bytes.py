from idc import *
from idautils import *


def getAllMnemonicAndOperands(start, end):
    found = []
    for h in Heads(start, end):
        mnemonic = print_insn_mnem(h)
        operand_0 = get_operand_value(h, 0)
        operand_1 = get_operand_value(h, 1)
        # print(mnemonic, hex(operand_0), hex(operand_1))
        if operand_0 == 0x0:
            found.append(hex(operand_1))
    return found


allbytes = getAllMnemonicAndOperands(0x40100A, 0x0402495)

f = open("shellcode.bin", "wb")
shellcode = bytes(int(x, 16) for x in allbytes)
print(shellcode)
f.write(shellcode)
f.close()