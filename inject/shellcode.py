import sys
from inject.enums import EXTRA_SIZE_TO_RESTORE


class Shellcode:
    def __init__(self, shellcode: bytes, options: dict):
        self.shellcode = shellcode
        self.options = options
        self.jump_distance: int = -1

    def get_final_size(self):
        _restore_size = EXTRA_SIZE_TO_RESTORE if self.should_restore() else 0
        return len(self.shellcode) + _restore_size

    def generate(self) -> bytes:
        if self.should_restore():
            if not self.is_jump_distance_known():
                print(
                    "[!] Jump Distance is not known by Shellcode instance. Cannot restore. Either tell Shellcode the jump distance or disable restoration."
                )
                sys.exit(1)
        return self.shellcode

    def should_restore(self):
        return self.options.get("should_restore", True)

    def is_jump_distance_known(self):
        return self.jump_distance >= 0

    def set_jump_distance(self, jump_distance: int):
        self.jump_distance = jump_distance

    def __bytes__(self):
        return self.generate()

