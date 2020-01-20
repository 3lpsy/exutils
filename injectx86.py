#!/usr/bin/env python3
import sys
from typing import List, Any
from argparse import ArgumentParser, Namespace
from pathlib import Path
from os.path import join
from utils import shellcode_encoder
from pefile import PE
from parser import make_parser
from cli import parsers
from inject import Injector


if __name__ == "__main__":
    parser = make_parser()
    args = parser.parse_args()
    for command, parser_funcs in parsers.items():
        if args.command == command:
            normalize = parser_funcs[1]
            run = parser_funcs[2]
            sys.exit(run(normalize(args)))
    sys.exit(parser.print_help())
