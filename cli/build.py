import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace, _SubParsersAction
from pathlib import Path
from os.path import join
from utils import shellcode_encoder
from cli.enums import SHELLCODE_HELP
from inject import Injector


def run(args: List[Any]):
    options = {
        "should_restore": not args["no_restore"],
        "enter": args["enter"],
        "cave": args["cave"],
        "nop_restore_data": args["nop_restore_data"],
    }
    manager = Injector(args["shellcode"], args["file"], args["output"], options)
    return manager.inject()


def apply(subparser: _SubParsersAction) -> ArgumentParser:
    parser = subparser.add_parser("build", help="build injected binary")
    parser.add_argument(
        "-s", "--shellcode", type=str, help=SHELLCODE_HELP, required=True,
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
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="do not fix the payload with popa and pusha",
        default=False,
    )
    parser.add_argument(
        "--nop-restore-data",
        action="store_true",
        help="fill replaced/removed original instructions with NOPs instead of appending them to shellcode",
        default=False,
    )
    parser.add_argument(
        "-c",
        "--cave",
        action="store",
        choices=["auto", "cave", "new-section"],
        default="auto",
        help="where to write the shellcode. defaults to auto",
    )

    parser.add_argument(
        "-e",
        "--enter",
        action="store",
        choices=["jump", "new-section"],
        default="jump",
        help="how to handle the entrypoing. defaults to 'jump' where the executable uses 'jmp' to move to new section",
    )

    return parser


def normalize(args: Namespace) -> dict:
    items = vars(args)
    items["shellcode"] = shellcode_encoder(items["shellcode"])
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
