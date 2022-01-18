from idautils import *
from idc import *

heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
functionCalls = []
for i in heads:
    if GetMnem(i) == "call":
        functionCalls.append(i)
print("Number of calls found: %d" % (len(functionCalls)))
for i in functionCalls:
    SetColor(i, CIC_ITEM, 0xc7fdff)