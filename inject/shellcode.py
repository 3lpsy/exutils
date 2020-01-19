from __future__ import annotations
from typing import List, Any
import sys
from struct import pack
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from inject.enums import (
    EXTRA_SIZE_TO_RESTORE,
    IX86_PUSHAD,
    IX86_PUSHFD,
    IX86_POPAD,
    IX86_JUMP,
    IX86_NOP,
)

from inject.utils import printhexi, byteslash


class Shellcode:
    def __init__(self, shellcode: bytes, options: dict):
        self.original_shellcode = shellcode
        self.shellcode = shellcode
        self.restore_data: bytes = None
        self.restore_jump_to_address: int = -1
        self.restore_cave_address: int = -1

        # options
        self.cave = options.get("cave", "auto")  # auto, cave, new-section
        self.enter = options.get("enter", "jump")  # jump, new-section
        self.should_restore = options.get("should_restore", True)
        self.log_level = int(options.get("log_level", 1))

    def get_final_size(self):
        _restore_size = EXTRA_SIZE_TO_RESTORE if self.should_restore else 0
        return len(self.shellcode) + _restore_size

    def get_size_when_restoring(self):
        self.restore_data_required()

        return (
            len(self.shellcode)
            + len(IX86_PUSHAD)
            + len(IX86_POPAD)
            + len(self.restore_data)
        )

    def generate(self) -> bytes:
        # nsc = bytes()
        # one_matched = False
        # two_matched = False
        # print("-- Fixing Hanging ShellCode --")
        # k = 0
        # for i in self.get_ins_from_data(self.shellcode, take=-1):
        #     if f"{i.mnemonic} {i.op_str}" == "call ebp":
        #         one_matched = k
        #     if f"{i.mnemonic} {i.op_str}" == "mov eax, esp" and one_matched == k - 1:
        #         two_matched = k

        #     if f"{i.mnemonic} {i.op_str}" == "dec esi" and two_matched == k - 1:
        #         self.out("[*] Removing 'dec esi' instruction")
        #         nsc = nsc + IX86_NOP * len(i.bytes)
        #     else:
        #         nsc = nsc + i.bytes

        #     k += 1
        # self.shellcode = nsc

        if self.should_restore:
            self.restore_data_required()
            self.restore_jump_to_address_required()
            self.restore_cave_address_required()
            size_when_restoring = self.get_size_when_restoring()
            self.out(f"[*] Shellcode Size When Restoring: {size_when_restoring}")
            self.outhexi(f"Restore Cave Address", self.restore_cave_address)
            restore_current_address = self.restore_cave_address + size_when_restoring
            self.outhexi(f"Restore Current Address", restore_current_address)
            self.outhexi(f"Retore New Entry Address", self.restore_jump_to_address)
            jmp_op = self.build_jump_op(restore_current_address)
            self.shellcode = (
                IX86_PUSHAD + self.shellcode + IX86_POPAD + self.restore_data + jmp_op
            )
        return self.shellcode

    def build_jump_op(self, current_address):
        jump_to_address = self.restore_jump_to_address
        # go backwards
        if jump_to_address < current_address:
            new_entry_loc = (current_address + 5 - jump_to_address) * -1
            self.outhexi(f"Final Jump To Address (Back)", new_entry_loc)
            return IX86_JUMP + pack("=l", new_entry_loc)
        # go forwards
        new_entry_loc = current_address + 5 - jump_to_address
        self.outhexi(f"Final Jump To Address (Forward)", new_entry_loc)
        jmp_op = IX86_JUMP + pack("=L", new_entry_loc)

    def set_restore_data(self, restore_data: bytes):
        self.restore_data = restore_data

    def restore_data_required(self):
        if not self.restore_data:
            print(
                "[!] Restore data not known. Cannot restore. Either tell Shellcode the restore data or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def set_restore_jump_to_address(self, jump_to_addr: int):
        self.restore_jump_to_address = jump_to_addr

    def restore_jump_to_address_required(self):
        if not self.restore_jump_to_address >= 0:
            print(
                "[!] Return Jump To Address is not known by Shellcode instance. Cannot restore. Either tell Shellcode the jump to address or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def set_restore_cave_address(self, cave_address: int):
        self.restore_cave_address = cave_address

    def restore_cave_address_required(self):

        if not self.restore_cave_address >= 0:
            print(
                "[!] Return Cave Address is not known by Shellcode instance. Cannot restore. Either tell Shellcode the cave address or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def __bytes__(self):
        return self.generate()

    def out(self, *msgs, level: int = 1, writer=None):
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
        offset = offset if offset >= 0 else 0x1000
        c = 0
        ins = []
        for i in Cs(CS_ARCH_X86, CS_MODE_32).disasm(data, offset):
            ins.append(i)
            if take != -1 and c >= take:
                return ins
            c += 1
        return ins
