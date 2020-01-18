#!/usr/bin/env python3
import sys
from typing import List
from argparse import ArgumentParser, Namespace
from pathlib import Path
from pefile import PE, machine_types
from utils import printhex, hexstr

from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86

PELIB_TO_CAP = {
    "IMAGE_FILE_MACHINE_AMD64": {"arch": CS_ARCH_X86, "mode": CS_MODE_64},
    "IMAGE_FILE_MACHINE_I386": {"arch": CS_ARCH_X86, "mode": CS_MODE_32},
}


def display_pe_info(file: Path, infos: List[str]):
    pe = PE(str(file))
    if "dump" in infos:
        print(pe.dump_info())
    else:
        if "all" in infos or "sections" in infos:
            print("Sections:")
            for section in pe.sections:
                print(
                    " " * 3,
                    section.Name.decode(),
                    hex(section.VirtualAddress),
                    hex(section.Misc_VirtualSize),
                    section.SizeOfRawData,
                )
            print()

        if "all" in infos or "imported" in infos:
            print("Imported Symbols:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(" " * 3, "DLL:", entry.dll.decode())
                for imp in entry.imports:
                    print(" " * 7, hex(imp.address), imp.name.decode())
            print()

        if "all" in infos or "exported" in infos:
            print("Exported Symbols:")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(
                    hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    exp.name,
                    exp.ordinal,
                )
            print()

        if "all" in infos or "entry" in infos:
            print("Entry Point:", hexstr(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            print(
                "Relative Entry Point:",
                hexstr(
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    + pe.OPTIONAL_HEADER.ImageBase
                ),
            )
            print()

        if "all" in infos or "start" in infos:
            machine = pe.FILE_HEADER.Machine
            conv = None
            for (name, val) in machine_types:
                if machine == val and name in PELIB_TO_CAP.keys():
                    conv = PELIB_TO_CAP[name]
            if conv:
                entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                # image_base = pe.OPTIONAL_HEADER.ImageBase
                # ep_ava = entry + image_base
                data = pe.get_memory_mapped_image()[entry : entry + 64]
                md = Cs(conv["arch"], conv["mode"])
                dis = md.disasm_lite(data, entry)
                for (addr, sz, mnem, op) in dis:
                    print("0x%x:\t%s\t%s" % (addr, mnem, op))

            else:
                print(
                    f"No valid machine value found in pefile to capstone converstion table for {hex(machine)}"
                )


def apply_parser(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument(
        "-f", "--file", type=str, help="path to pe file", required=True,
    )
    parser.add_argument(
        "-i",
        "--info",
        type=str,
        help="information to show",
        action="append",
        choices=["all", "sections", "imported", "exported", "dump", "entry", "start"],
    )
    return parser


def normalize_args(args: Namespace) -> dict:
    items = vars(args)
    if not items["info"]:
        items["info"] = ["all"]
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    return items


if __name__ == "__main__":
    parser = ArgumentParser(description="Inspect PE File")
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())

    display_pe_info(Path(args["file"]), args["info"])

    sys.exit(0)
