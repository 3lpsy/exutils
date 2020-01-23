#!/usr/bin/env python3
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction
from utils import shellcode_encoder, intbyte, shellcode_hexer, byteslash, xorbytes
from cli.enums import SHELLCODE_HELP


def run(args):
    shellcode = args["shellcode"]
    key = args["key"]
    print(f"Key: {byteslash(key)}")
    print(f"Shellcode ({len(shellcode)}):")
    print(byteslash(shellcode))
    encoded = xorbytes(shellcode, key)
    print(f"Encoded ({len(encoded)}):")
    print(byteslash(encoded))


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("shellxor", help="bitwise xor on shellcode")
    parser.add_argument(
        "-s", "--shellcode", type=str, help=SHELLCODE_HELP, required=True,
    )
    parser.add_argument(
        "-k",
        "--key",
        type=str,
        help="single or multi-byte xor key in shellcode format (0xab, \\xab)",
        required=True,
    )
    return parser


def normalize(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(args.shellcode)

    if "0x" in args.key:
        items["key"] = intbyte(int(args.key, 16))
    elif "\\" in args.key:
        items["key"] = shellcode_hexer(args.key)
    else:
        items["key"] = intbyte(int(args.key))

    return items
