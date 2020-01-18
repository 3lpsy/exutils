from pathlib import Path
from shutil import copy
import mmap

from inject.utils import align
from inject.enums import HEADER_SIZE


class Output:
    def __init__(self, target: Path, source: Path, options: dict = None):
        # Verbosity
        options = options or {}
        self.log_level = int(options.get("log_level", 1))

        self.target = target
        self.source = source
        self.expanded_size: int = 0

    def exists(self):
        return self.target.is_file()

    def stat(self):
        return self.target.stat()

    def expand_for_sc(self, shellcode_size: int, file_alignment: int) -> int:
        needed_section_size = shellcode_size + HEADER_SIZE
        # TODO: is alignment necessary or correct here?
        expanded_size = align(needed_section_size, file_alignment)
        fd = open(str(self), "a+b")
        map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
        map.resize(self.stat().st_size + expanded_size)
        map.close()
        fd.close()
        self.out(
            f"[*] Expanded {self} by {needed_section_size} bytes with file alignment {file_alignment} for a total of {expanded_size} new bytes",
            level=2,
        )
        self.expanded_size = expanded_size
        return self.expanded_size

    def create_from_source(self):
        # copy the source file to the output file
        # expand the binary by the neede bytes (with alignment)
        self.out(f"[*] Copying {str(self.source)} to {str(self)}")
        copy(str(self.source), str(self))

    def clean(self) -> bool:
        # delete output if exists
        if self.target.is_file():
            self.out("[*] Deleting old file", level=2)
            self.target.unlink()
            return True
        return False

    def __str__(self):
        return str(self.target)

    def out(self, *msgs, level=1, writer=None):
        if level >= self.log_level:
            if writer:
                writer(*msgs)
            else:
                print(*msgs)
