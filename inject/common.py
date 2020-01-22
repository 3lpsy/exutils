from typing import List, Any
from inject.utils import printhexi

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class CommonMixin:
    def __init__(self, options: dict):
        self.log_level = int(options.get("log_level", 1))

    def out(self, *msgs, level=1, writer=None):
        if level >= self.log_level:
            if writer:
                writer(*msgs)
            else:
                print(*msgs)

    def outhexi(self, *msgs, level: int = 1):
        self.out(*msgs, level=level, writer=printhexi)

    def outins(self, ins: List[Any], level: int = 1):
        if level >= self.log_level:
            for i in ins:
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def get_ins_from_data(self, data: bytes, take: int = 8, offset: int = -1):
        if offset < 0:
            if hasattr(self, "address_of_entry_point_rel"):
                offset = getattr(self, "address_of_entry_point_rel")()
            else:
                offset = 0x1000
        c = 0
        ins = []
        for i in Cs(CS_ARCH_X86, CS_MODE_32).disasm(data, offset):
            ins.append(i)
            if take > 0 and c >= take:
                return ins
            c += 1
        return ins
