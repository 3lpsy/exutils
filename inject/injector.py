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
    def __init__(
        self, shellcode: bytes, file: Path, output: Path, options: dict = None
    ):
        # Verbosity
        options = options or {}
        self.log_level = int(options.get("log_level", 1))

        # Set Basics
        self.shellcode: Shellcode = Shellcode(shellcode, options)
        self.output: Output = Output(output, file, {"log_level": self.log_level})

        # Loaded /Computed Later
        self.manager: PEManager = None

    def section_injection(self):
        self.setup()
        self.expand()
        self.create_new_section()
        self.enter_at_last_section()
        self.write_shellcode()
        self.out("-- Injection Complete --", level=3)

    def create_new_section(self):
        self.load_required()
        self.out("-- Creating New Section --", level=2)
        self.manager = self.manager.create_new_section(self.shellcode, ".extra")

    def enter_at_last_section(self):
        self.out("-- Changing Entry Point --", level=2)
        self.manager = self.manager.enter_at_last_section()

    def write_shellcode(self):
        self.out("-- Injecting Shellcode --", level=2)
        self.manager.write_shellcode(self.shellcode)

    def setup(self):
        self.init()
        self.load()

    def init(self):
        # delete old output if it exists
        self.output.clean()
        # copy source file to output file
        self.output.create_from_source()

    def init_required(self):
        if not self.is_init():
            msg = "[!] PEManager not initialized. Output may not exist. Please call 'init' first."
            print(msg)
            sys.exit()

    def is_init(self) -> bool:
        if not self.output.exists():
            return False
        return True

    def expand(self):
        self.out("-- Expanding File --", level=2)
        # actually expand the file
        self.output.expand_for_sc(
            self.shellcode.get_final_size(), self.manager.file_alignment()
        )

    def load(self):
        self.init_required()
        self.manager = PEManager(self.output, options={"log_level": self.log_level})
        self.out("-- PE Basic Info --")
        self.manager.dump_basic_info()

    def load_required(self):
        if not self.is_loaded():
            print('[!] PE was not loaded into "manager" target on PEManager')
            sys.exit()

    def is_loaded(self) -> bool:
        if not self.manager:
            return False
        return True

    def out(self, *msgs, level=1, writer=None):
        if level >= self.log_level:
            if writer:
                writer(*msgs)
            else:
                print(*msgs)
