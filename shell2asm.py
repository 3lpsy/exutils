#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace
from utils import shellcode_encoder
from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86

ARCHES = {"x86": CS_ARCH_X86}
MODES = {"x32": CS_MODE_32, "x64": CS_MODE_64}


def display_assembly(shellcode: bytes, arch: int, mode: int, start: int):
    md = Cs(arch, mode)
    for (address, size, mnemonic, op_str) in md.disasm_lite(shellcode, start):
        print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))


def apply_parser(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument(
        "-s",
        "--shellcode",
        type=str,
        help="shellcode to convert in \\xAA\\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \\AA format in a file via 'txt:/path/to/file', and binary data in a file via 'bin:/path/to/binary')",
        required=True,
    )
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


def normalize_args(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(args.shellcode)

    if "0x" in args.start:
        items["start"] = int(args.start, 16)
    else:
        items["start"] = int(args.start)

    return items


if __name__ == "__main__":
    parser = ArgumentParser(description="Convert shellcode to assembly")
    parser = apply_parser(parser)
    args = normalize_args(parser.parse_args())

    display_assembly(
        args["shellcode"], ARCHES[args["arch"]], MODES[args["mode"]], args["start"]
    )
    sys.exit(0)
