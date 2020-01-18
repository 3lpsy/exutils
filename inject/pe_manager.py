from __future__ import annotations
import sys

from pefile import PE

from inject.shellcode import Shellcode
from inject.output import Output
from inject.utils import printhexi, align
from inject.enums import HEADER_SIZE, RWE_CHARACTERISTIC


class PEManager:
    def __init__(self, output: Output):
        self.output = output
        self.pe = PE(str(self.output))

    def dump_basic_info(self):
        print("[*] Number of Sections:", self.number_of_sections())
        printhexi("File Alignment", self.file_alignment())
        printhexi("Section Alignment", self.section_alignment())
        printhexi("Virtual Offset", self.virtual_offset())
        printhexi("Aligned Virtual Offset", self.aligned_virtual_offset())
        printhexi("Raw Offset", self.raw_offset())
        printhexi("Aligned Raw Offset", self.aligned_raw_offset())

    def number_of_sections(self) -> int:
        return self.pe.FILE_HEADER.NumberOfSections

    def address_of_entry_point(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def size_of_image(self):
        return self.pe.OPTIONAL_HEADER.SizeOfImage

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

    def write_shellcode(self, shellcode: Shellcode):
        raw_offset = self.last_section().PointerToRawData
        printhexi("Raw Offset for Injection", raw_offset)
        printhexi("Writing shellcode to offset", raw_offset)
        self.pe.set_bytes_at_offset(raw_offset, bytes(shellcode))
        self.save_changes()
        self.refresh()

    def enter_at_last_section(self) -> PEManager:
        printhexi("Original Entry Point", self.address_of_entry_point())
        print(f"[*] New Last Section Name: {self.last_section().Name.decode()}")
        new_entry_point = self.last_section().VirtualAddress
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
        printhexi("New Entry Point", new_entry_point)
        self.save_changes()
        self.refresh()
        return self
        # adds new section to the end of the PE file

    def create_new_section(self, shellcode: Shellcode, name: str) -> PEManager:
        name = self.normalize_name(name)
        # lets take our size of the new section, and align that as well
        aligned_virtual_size = self.get_aligned_virtual_size(shellcode)
        printhexi("Aligned Virtual Size", aligned_virtual_size)
        aligned_raw_size = self.get_aligned_raw_size(shellcode)
        printhexi("Aligned Raw Size", aligned_raw_size)

        # write the new section header
        print("[*] Writing Data")
        printhexi("New Section Offset", self.new_section_offset())

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
        print(f"[*] Writing name {name} to new section offset")
        self.pe.set_bytes_at_offset(self.new_section_offset(), name)

    def write_aligned_virtual_size(self, aligned_virtual_size):
        dst = self.new_section_offset() + 8
        printhexi("Writing aligned virtual size to", dst)
        self.pe.set_dword_at_offset(dst, aligned_virtual_size)

    def write_aligned_virtual_offset(self, aligned_virtual_offset):
        dst = self.new_section_offset() + 12
        printhexi("Writing aligned virtual offset to", dst)
        self.pe.set_dword_at_offset(dst, aligned_virtual_offset)

    def write_aligned_raw_size(self, aligned_raw_size):
        dst = self.new_section_offset() + 16
        printhexi("Writing aligned raw size to", dst)
        self.pe.set_dword_at_offset(dst, aligned_raw_size)

    def write_aligned_raw_offset(self, aligned_raw_offset):
        dst = self.new_section_offset() + 20
        printhexi("Writing aligned raw offset to", dst)
        self.pe.set_dword_at_offset(dst, aligned_raw_offset)

    def write_nothing(self, nothing):
        dst = self.new_section_offset() + 24
        printhexi("Writing nothing to", dst)
        self.pe.set_bytes_at_offset(dst, nothing)

    def write_characteristics(self, characteristics):
        dst = self.new_section_offset() + 36
        printhexi("Writing characteristics to", dst)
        self.pe.set_dword_at_offset(dst, characteristics)

    def increment_number_of_sections(self):
        _original = self.number_of_sections()
        self.pe.FILE_HEADER.NumberOfSections += 1
        print(
            f"[*] Increasing section number from {_original} to {self.pe.FILE_HEADER.NumberOfSections}"
        )

    def update_size_of_image(self, new_image_size):
        _orginal_image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        printhexi("Original SizeOfImage", _orginal_image_size)
        self.pe.OPTIONAL_HEADER.SizeOfImage = new_image_size
        printhexi("New SizeOfImage", self.pe.OPTIONAL_HEADER.SizeOfImage)

    def save_changes(self):
        print(f"[*] Writing changes to {str(self.output)}")
        self.pe.write(str(self.output))

    def refresh(self):
        print(f"[*] Refreshing PE in current PEManager: {str(self.output)}")
        self.pe = PE(str(self.output))

    def regenerate(self):
        print(f"[*] Regenerating PE with new PEManager: {str(self.output)}")
        new_pem = PEManager(self.output)
        return new_pem
