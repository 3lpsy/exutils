#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction
from utils import shellcode_encoder
from cli.enums import SHELLCODE_HELP
from capstone import Cs, CS_MODE_32, CS_MODE_64, CS_ARCH_X86

ARCHES = {"x86": CS_ARCH_X86}
MODES = {"x32": CS_MODE_32, "x64": CS_MODE_64}


def run(args):
    shellcode = args["shellcode"]
    arch = ARCHES[args["arch"]]
    mode = MODES[args["mode"]]
    start = args["start"]
    md = Cs(arch, mode)
    for (address, size, mnemonic, op_str) in md.disasm_lite(shellcode, start):
        print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("shellasm", help="get asm from shellcode")
    parser.add_argument(
        "-s", "--shellcode", type=str, help=SHELLCODE_HELP, required=True,
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


def normalize(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(args.shellcode)

    if "0x" in args.start:
        items["start"] = int(args.start, 16)
    else:
        items["start"] = int(args.start)

    return items
