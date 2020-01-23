from __future__ import annotations
from inject.common import CommonMixin
from inject.opcodes import IX86_NOP


class Encoder(CommonMixin):
    def __init__(self, options: dict = None):
        options = options or {}
        self.should_encode = options.get("should_encode", True)
        super().__init__(options)

    def make_stub(self, shellcode: Shellcode) -> bytes:
        pass

    def encode(self, shellcode: Shellcode) -> bytes:
        pass
