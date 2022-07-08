from idautils import *
from idc import *
from biodata_4a_decrypt import decrypt


def key_encrypted_address(h):
    """Passed instruction from `Heads()` to find if that
    instruction is related to `mov eax,offset <encrypted_string>`

    Args:
        h (Generator): an iterator returned from idc.Heads()

    Returns:
        str | bool: If the instruction is not related to encrypted string, return False.  
         Else the Byte String of the encrypted string.
    """
    encrypted_string = False
    for i in range(3):
        t = get_operand_type(h, i)
        if t == o_reg:
            operand = print_operand(h, i)

        elif t == o_imm:
            operand = get_operand_value(h, i)
            size = int.from_bytes(get_bytes(operand - 4, 4),
                                  "little")  # see _string class from Delphi
            # This is equivalent to get_wide_dword(operand-4)
            encrypted_string = get_bytes(operand, size)
            #this is equivalent to get_strlit_contents(operand, size)
        elif t == o_void:
            operand = 'n/a'
    return encrypted_string


# def get_enc_and_key(ea):
#     for xref in XrefsTo(ea):
#         print(xref.type, XrefTypeName(xref.type), \
#                             'from', hex(xref.frm), 'to', hex(xref.to))


def get_enc_and_key(ea):
    for xref in XrefsTo(ea):
        # From Kaspersky class: teaches how to take each instruction and extract the mnemonic and the operands
        # between the 2 address.
        # Note: i have used 5 bytes before the address
        # in which it calls the function that we wants, however,
        # we should use a larger number because there is not guarantee
        #  that the compiler will always put mov eax,<encrypted string>
        # before the function call.
        for h in Heads(xref.frm - 5, xref.frm):
            mnemonic = print_insn_mnem(h)
            operand_1 = print_operand(h, 0)
            operand_2 = print_operand(h, 1)
            # print(f"{hex(h)}:", end='\t')
            # print(f"{mnemonic} {operand_1} {operand_2}")
            enc = key_encrypted_address(h)
            if enc:
                print(f"{enc}:\t{decrypt(enc)}")


get_enc_and_key(0x475610)
# print(hex(get_segm_end(get_screen_ea())))
# get_enc_and_key(0x475610)
# print(print_insn_mnem)
# Heads() is used to find, from start_ea to end_ea, all the working instructions/codes/data items.
# for h in Heads(get_segm_start(get_screen_ea()), get_segm_end(get_screen_ea())):
# print(get_segm_start(get_screen_ea())

# mov_instr = 0x476d71
# print(f"instruction:\t{print_insn_mnem(mov_instr)}")
