#!/usr/bin/env python3
import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace
from pathlib import Path
from utils import shellcode_encoder
from pefile import PE

from inject import Injector

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
    parser.add_argument(
        "--enter-new-section",
        action="store_true",
        help="enter at new section instead of jumping from original",
        default=False,
    )
    return parser


def normalize_args(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(items["shellcode"])
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"[!] File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    if items["output"] in ["stdout", "/proc/self/fd/1"]:
        print("[!] Writing to stdout not supported")
        sys.exit(1)
    p_output = Path(items["output"])
    if p_output.is_file() and not items["force"]:
        print("[!] Output file already exists. Delete it or use '--force' to overwrite")
        sys.exit(1)
    items["output"] = p_output
    return items


if __name__ == "__main__":
    parser = ArgumentParser(description="Inject shellcode into new section")
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())
    options = {
        "should_restore": not args["no_restore"],
        "entry": "new_section" if args["enter_new_section"] else "jump",
    }
    print("-- Starting --")
    manager = Injector(args["shellcode"], args["file"], args["output"], options)
    manager.section_injection()
    # create_injected_pe(args["shellcode"], args["file"], args["output"], args["no_fix"])
    sys.exit(0)
