from idc import *
from idautils import *


def retrieveStringReplacementTable(start, end):
    replace = {}
    found_call_copyChar = False
    foundkey = False
    foundvalue = False
    _key = ""
    _value = ""
    for h in Heads(start, end):
        mnemonic = print_insn_mnem(h)
        if not found_call_copyChar and mnemonic == "call":  # find call copyChar
            copyCharAddr = get_operand_value(h, 0)
            if copyCharAddr == 0x404F30:
                found_call_copyChar = True
        elif found_call_copyChar:
            if print_insn_mnem(h) == "mov" and print_operand(
                    h, 0) == "edx" and get_operand_type(h, 1) == o_imm:
                operand = get_operand_value(h, 1)
                size = int.from_bytes(get_bytes(operand - 4, 4), "little")
                _key = get_bytes(operand, size).decode('utf-8')
                found_call_copyChar = False
                foundkey = True
        elif foundkey:
            if print_insn_mnem(h) == "mov" and print_operand(
                    h, 0) == "eax" and get_operand_type(h, 1) == o_imm:
                operand = get_operand_value(h, 1)
                size = int.from_bytes(get_bytes(operand - 4, 4), "little")
                _value = get_bytes(operand, size).decode('utf-8')
                replace[_key] = _value
                found_call_copyChar = False
                foundkey = False
                foundvalue = True
        elif foundvalue:
            foundvalue = False
            _key = ""
            _value = ""
    return replace


def hunt_all_encrypted_strings(decrypting_ea, replaceTable):
    all_encrypted = []
    for xref in XrefsTo(decrypting_ea):
        for h in Heads(xref.frm - 10, xref.frm):
            mnemonic = print_insn_mnem(h)
            operand_1 = print_operand(h, 0)
            operand_2 = print_operand(h, 1)
            if "_str_" in operand_2 and operand_1 == "edx":
                operand = get_operand_value(h, 1)
                size = int.from_bytes(get_bytes(operand - 4, 4), "little")
                enc_str = get_bytes(operand, size).decode('utf-8')
                print(enc_str, end=':\t')
                decrypted = "".join(
                    [replaceTable[enc_char] for enc_char in enc_str])
                print(decrypted)
                print('\n')
                set_cmt(xref.frm, decrypted, False)


replaceTable = retrieveStringReplacementTable(0x48DB90, 0x48F6E6)
hunt_all_encrypted_strings(0x48DB90, replaceTable)
