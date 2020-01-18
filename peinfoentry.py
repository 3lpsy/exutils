#!/usr/bin/env python

import sys
from pathlib import Path

from pefile import PE
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from argparse import ArgumentParser, Namespace
from utils import hexstr


def find_entry_point_section(pe, eop_rva):
    for section in pe.sections:
        if section.contains_rva(eop_rva):
            return section
    return None


def display_pe_entry_info(file: Path):
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
    data = section.get_data(eop, 32)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in cs.disasm(data, eop_relative):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def apply_parser(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument(
        "-f", "--file", type=str, help="path to pe file", required=True,
    )
    return parser


def normalize_args(args: Namespace) -> dict:
    items = vars(args)
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    return items


if __name__ == "__main__":
    parser = ArgumentParser(description="Inspect PE File Entrypoint")
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())

    display_pe_entry_info(Path(args["file"]))

    sys.exit(0)
