from __future__ import annotations

from typing import List, Set, NewType, Union
from abc import ABC, abstractmethod
from enum import Enum, auto

#explicit imports to satisfy mypy
import idc #type: ignore
from ida_ida import inf_get_max_ea #type: ignore
from idautils import Functions, CodeRefsTo #type: ignore
from ida_bytes import del_items #type: ignore
from ida_xref import del_cref #type: ignore

#fundamental auxiliaries
class const:
    INSN_ADD = "add"
    INSN_RETN = "retn"
    MAX_EA = inf_get_max_ea()
    DELTA_OPND_POSITION = 1
    class hexa:
        SUFFIX = "h"
        BASE = 16

class Err(Enum):
    NEGATIVE_ADDR = auto(),
    IDA_PARAM_RECOVERY = auto(),
    IDA_PARAM_CONVERSION = auto(),
    IDA_GET_XREFS = auto(),
    IDA_EDIT_IDB = auto(),
    NO_PRF_HERE = auto()

def next_data(addr: Addr) -> Union[Addr, Err]:
    try:
        size = idc.get_item_size(addr)
    except Exception as e:
        print(e)
        return Err.IDA_PARAM_RECOVERY
    return Addr(addr + size)

#types and interfaces

Addr = NewType("Addr", int)

class PushRetFunc(ABC):
    @abstractmethod
    def __init__(self, addr: Addr) -> None: pass

    @abstractmethod
    def fix_flows(self) -> Union[int, Err]: pass
    """fix_flow on all incoming xrefs""" 

    @abstractmethod
    def fix_flow(self, xref: Addr) -> Union[None, Err]: pass
    """Fix IDA's inferred execution flow for an incoming xref""" 

    @abstractmethod
    def xrefs_to(self) -> Union[Set[Addr], Err]: pass
    """What addresses call this pushretfunc"""
   
    @abstractmethod
    def addr(self) -> Addr: pass
    """Address of this PRF"""

    @abstractmethod
    def esp_delta(self) -> Union[int, Err]: pass
    """The value X in add dword ptr [esp], X"""
    
    @abstractmethod
    def bottom_half(self, top_half_xref: Addr) -> Union[Addr, Err]: pass
    """What address does retn resume to?"""
    
    #concrete static methods -- no support for separate impls

    @staticmethod
    def exists_here(addr: Addr) -> Union[bool, Err]: 
        """Does a pushretfunc exist here?"""
        if addr < 0: return Err.NEGATIVE_ADDR
        try:
            mnems: List[str] = [idc.print_insn_mnem(a) for a in [addr,next_data(addr)]]
        except Exception as e:
            print(e)
            return Err.IDA_PARAM_RECOVERY
        if len(mnems) < 2:
            return Err.IDA_PARAM_RECOVERY
        return mnems == [const.INSN_ADD, const.INSN_RETN]
    
    @staticmethod
    def from_addr(addr: Addr) -> Union[PushRetFunc, Err]:
        """Create PRF object of a given address"""
        prf_exists = PushRetFunc.exists_here(addr)
        if isinstance(prf_exists,Err):
            return prf_exists
        if prf_exists == False:
            return Err.NO_PRF_HERE
        return _PushRetFunc(addr)


#impls

class _PushRetFunc(PushRetFunc):
    def __init__(self, addr: Addr) -> None:
        self._addr = addr

    def fix_flows(self) -> Union[int, Err]:
        xrefsto = self.xrefs_to()
        if isinstance(xrefsto,Err):
            return Err.IDA_PARAM_RECOVERY
        fixed_count = 0
        for xref in xrefsto:
            res = self.fix_flow(xref)
            if isinstance(res,Err):
                print(f"Error when fixing flow {hex(xref)}: {res}")
                continue
            fixed_count += 1
        return fixed_count

    def fix_flow(self, top_half_xref: Addr) -> Union[None, Err]:
        try:
            top_seam = idc.prev_head(top_half_xref)
        except Exception as e:
            print(e)
            return Err.IDA_PARAM_RECOVERY
        
        bottom_seam = self.bottom_half(top_half_xref)
        if isinstance(bottom_seam, Err):
            return bottom_seam
        
        try:
            res = True
            for a in [prev_head(bottom_seam), bottom_seam, next_data(bottom_seam)]:
                del_items(a)
            res &= idc.create_insn(bottom_seam)
            res &= idc.add_cref(top_seam, bottom_seam,idc.fl_JN|idc.XREF_USER)
            idc.del_cref(top_seam, top_half_xref, True)
        except Exception as e:
            print(e)
            return Err.IDA_EDIT_IDB
        if res == False:
            return Err.IDA_EDIT_IDB
        
        return None

    def xrefs_to(self) -> Union[Set[Addr], Err]:
        try:
            xrefs : Set[Addr] = set(CodeRefsTo(self.addr(),False))
        except Exception as e:
            print(e)
            return Err.IDA_GET_XREFS
        return xrefs
        

    def addr(self) -> Addr:
        return self._addr
    
    def esp_delta(self) -> Union[int, Err]:
        try:
            str_delta = idc.print_operand(self.addr(), const.DELTA_OPND_POSITION)
        except Exception as e:
            print(e)
            return Err.IDA_PARAM_RECOVERY
        try:
            if str_delta.endswith(const.hexa.SUFFIX):
                str_delta = str_delta[:-1]
            delta = int(str_delta,const.hexa.BASE)
        except Exception as e:
            print(e)
            return Err.IDA_PARAM_CONVERSION
        return delta

    
    def bottom_half(self, top_half_xref: Addr) -> Union[Addr, Err]: 
        delta = self.esp_delta()
        if isinstance(delta,Err):
            return delta
        retn_addr = next_data(top_half_xref)
        if isinstance(retn_addr,Err):
            return retn_addr
        return Addr(retn_addr + delta)
    

def pushret_func_addrs() -> Union[Set[Addr], Err]:
    result: Set[Addr] = set()
    for f in Functions():
        is_pushret = PushRetFunc.exists_here(f)
        if isinstance(is_pushret,Err):
            print(f"Failed to determine PRF status: {f}")
        if is_pushret:
            result |= set([f])
    return result


if __name__ == "__main__":
    addrs = pushret_func_addrs()
    if isinstance(addrs,Err):
        print("Failed to get pushret function addresses")
        exit(1)
    for addr in addrs:
        prf = PushRetFunc.from_addr(addr)
        if isinstance(prf, Err):
            print(f"Failed instantiate PRF from {hex(addr)}")
            continue
        res = prf.fix_flows()
        if isinstance(res, Err):
            print(f"Failed to fix flows for {hex(addr)}")
            continue
        if res > 0:
            print(f"Fixed {res} flow{'' if res==1 else 's'} for {hex(addr)}")

