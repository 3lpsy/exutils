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
    length = args["length"]
    md = Cs(arch, mode)
    pe = PE(str(file))
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for section in pe.sections:
        data = section.get_data()
        print(f"Searching section {section.Name.decode()} for a cave")
        caves = []
        tracker = 0
        start = -1
        end = -1
        for i in range(len(data)):
            dint = data[i]
            if dint == 0:
                if start < 0:
                    start = i  # change to offset/addrt later
                tracker += 1
            else:
                if tracker > 0 and tracker > length:
                    # check for need to save data and reset
                    end = i - 1  # inclusive end
                    caves.append((section.Name.decode(), start, end, tracker))
                start = -1
                end = -1
                tracker = 0
        for c in caves:
            print(c)


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("bincave", help="find code caves")
    parser.add_argument("-f", "--file", type=str, help="path to pe file", required=True)
    parser.add_argument("-s", "--shellcode", type=str, help=SHELLCODE_HELP)
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        help="instead of passing in shellcode, just pass in the length",
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

    return parser


def normalize(args: Namespace) -> dict:
    items = vars(args)
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"[!] File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    if args.shellcode:
        items["shellcode"] = shellcode_encoder(items["shellcode"])
        items["length"] = len(items["shellcode"])
    elif args.length:
        items["shellcode"] = b"\x00" * args.length
        items["length"] = args.length
    return items
