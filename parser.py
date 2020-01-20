import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction
from cli import parsers


def make_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Inject shellcode into new section")
    subparsers = parser.add_subparsers(help="action", dest="command")
    for command, parser_funcs in parsers.items():
        # run "apply" for sub command
        parser_funcs[0](subparsers)
    return parser
