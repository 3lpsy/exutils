import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace, _SubParsersAction
from pathlib import Path
from os.path import join
from utils import shellcode_encoder
from cli.enums import SHELLCODE_HELP
from inject import Injector


def run(args: List[Any]):
    # when only length is specified, shellcode is stubbed
    injector = Injector(args["shellcode"], args["file"], args["output"], {})
    injector.setup()
    shellcode_size = injector.shellcode.get_final_size()
    print("-- Expanding File --")
    expanded_size = injector.output.expand_for_sc(
        shellcode_size, injector.manager.file_alignment()
    )
    print(
        f"[*] Finished: Output {injector.output} expanded by {shellcode_size} ({expanded_size} actual) bytes"
    )


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("expand", help="expand binary (creates a copy)")
    parser.add_argument("-s", "--shellcode", type=str, help=SHELLCODE_HELP)
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        help="instead of passing in shellcode, just pass in the length",
        required=True,
    )
    parser.add_argument(
        "-f", "--file", type=str, help="path to source pe file", required=True
    )
    parser.add_argument(
        "-o", "--output", type=str, help="path to newly created pe file"
    )
    parser.add_argument(
        "-F",
        "--force",
        action="store_true",
        help="force overwrite output",
        default=False,
    )
    return parser


def normalize(args: Namespace) -> dict:
    items = vars(args)
    if args.shellcode:
        items["shellcode"] = shellcode_encoder(items["shellcode"])
        items["length"] = len(items["shellcode"])
    elif args.length:
        items["shellcode"] = b"\x00" * args.length
        items["length"] = args.length
    else:
        print("[!] Please either pass in shellcode (-s) or length (-l)")
        sys.exit(1)
    p_file = Path(items["file"])
    if not p_file.is_file():
        print(f"[!] File not found at {items['file']}")
        sys.exit(1)
    items["file"] = p_file
    if not args.output or Path(args.output).is_dir():
        if Path(args.output).is_dir():
            parent = args.output
        else:
            parent = p_file.parent
        parts = p_file.name.split(".")
        if len(parts) > 1:
            output = (
                "".join(parts[: len(parts) - 1]) + "-injected." + parts[len(parts) - 1]
            )
        else:
            output = p_file.name + "-injected"

        items["output"] = join(parent, output)
    if items["output"] in ["stdout", "/proc/self/fd/1"]:
        print("[!] Writing to stdout not supported")
        sys.exit(1)
    p_output = Path(items["output"])
    if p_output.is_file() and not items["force"]:
        print("[!] Output file already exists. Delete it or use '--force' to overwrite")
        sys.exit(1)
    items["output"] = p_output
    return items
