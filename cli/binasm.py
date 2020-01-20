#!/usr/bin/env python3
import sys
from pathlib import Path
from argparse import ArgumentParser, Namespace, _SubParsersAction
from utils import shellcode_encoder
from pefile import PE
from cli.enums import SHELLCODE_HELP
from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86

ARCHES = {"x86": CS_ARCH_X86}
MODES = {"x32": CS_MODE_32, "x64": CS_MODE_64}


def run(args):
    file = args["file"]
    arch = ARCHES[args["arch"]]
    mode = MODES[args["mode"]]
    start = args["start"]
    md = Cs(arch, mode)
    pe = PE(str(file))
    start = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # image_base = pe.OPTIONAL_HEADER.ImageBase
    # ep_ava = entry + image_base
    data = pe.get_memory_mapped_image()[start : start + 64]
    for i in md.disasm(data, start):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("binasm", help="get asm from shellcode")
    parser.add_argument("-f", "--file", type=str, help="path to pe file", required=True)
    parser.add_argument(
        "-a",
        "--arch",
        type=str,
        choices=ARCHES.keys(),
        default="x86",
        help="architecture (default: x86)",
    )
    # mode can be combined with MODES[args.mode] + CS_MODE_LITTLE_ENDIAN
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        choices=MODES.keys(),
        default="x64",
        help="mode (default: 64)",
    )
    parser.add_argument(
        "-S",
        "--start",
        type=str,
        default="0x1000",
        help="start in hex or decimal format (default: 0x1000)",
    )
    return parser


def normalize(args: Namespace) -> dict:
    items = vars(args)
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"[!] File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    if "0x" in args.start:
        items["start"] = int(args.start, 16)
    else:
        items["start"] = int(args.start)

    return items
