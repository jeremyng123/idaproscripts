from idc import *
from idautils import *
from binascii import hexlify


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


def XOR_Byte_patch(loc, bval):
    patch_byte(loc, ord(get_bytes(loc, 1)) ^ ord(bval))


def XOR_Word_patch(loc, wval):
    patch_byte(loc, bytes(int(hexlify(get_bytes(loc, 1)), 16) ^ wval))


def XOR_Double_patch(loc, dval):
    patch_byte(loc, bytes(int(hexlify(get_bytes(loc, 1)), 16) ^ dval))


################################################################
# First part
################################################################
def first():
    esi = 0x5 + 0x1c
    ecx = 0x1df
    while (ecx > 0):
        XOR_Byte_patch(esi, "\x66")
        ecx -= 1
        esi += 1


# first()


def second():
    ebx = "nopasaurus"
    key = ebx
    esp = 0x14
    esi = 0x47 + 0x2d
    ecx = esi + 0x18c
    i = 0
    while (ecx > 0):
        XOR_Byte_patch(esi, key[i % len(key)])
        ecx -= 1
        esi += 1
        i += 1


# second()


def third():
    esi = 0xaa + 0x1e
    ecx = 0x138
    key = "bOlG"
    i = 0
    while (ecx > 0):
        XOR_Byte_patch(esi, key[i % len(key)])
        ecx -= 1
        esi += 1
        i += 1


# third()


def fourth():
    key = "omg is it almost over?!?"
    esi = 0xfd + 0x2d
    ecx = esi + 0xd6
    i = 0  # ebx = i
    while (ecx != esi):
        XOR_Byte_patch(esi, key[i % len(key)])
        esi += 1
        i += 1


# fourth()
print(__name__)
if __name__ == '__main__':
    first()
    second()
    third()
    fourth()