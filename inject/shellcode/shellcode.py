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
from inject.common import CommonMixin
from inject.shellcode.restorer import Restorer
from inject.shellcode.fixer import Fixer

from inject.utils import printhexi, byteslash, intbyte


# TODO: encapsulare restoration in it's own class
class Shellcode(CommonMixin):
    def __init__(self, shellcode: bytes, options: dict = None):
        options = options or {}
        self.original_shellcode = shellcode
        self.shellcode = shellcode
        # options
        self.cave = options.get("cave", "auto")  # auto, cave, new-section
        self.enter = options.get("enter", "jump")  # jump, new-section
        self.restorer = Restorer(options)
        self.fixer = Fixer(options)

        super().__init__(options)

    def get_final_size(self):
        _restore_size = EXTRA_SIZE_TO_RESTORE if self.restorer.should_restore else 0
        return len(self.shellcode) + _restore_size

    def generate(self) -> bytes:
        # assumes certain payload, need better way
        if self.fixer.should_fix:
            self.shellcode = self.fixer.apply(self)

        if self.encoder.should_encode:
            stub = self.encoder.make_stub(self)
            blob = self.encoder.encode(self)

        if self.restorer.should_restore:
            self.shellcode = self.restorer.apply(self)

        return self.shellcode

    def set_restore_data(self, restore_data: bytes):
        self.restorer.data = restore_data

    def set_restore_jump_to_address(self, jump_to_addr: int):
        self.restorer.jump_to_address = jump_to_addr

    def set_restore_cave_address(self, cave_address: int):
        self.restorer.cave_address = cave_address

    def set_restore_ep_relative(self, ep_ava):
        self.restorer.ep_relative = ep_ava

    def __bytes__(self):
        return self.generate()
