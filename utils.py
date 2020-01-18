import sys
from typing import List
from pathlib import Path
from importlib import import_module


def hexstr(val):
    return f"{val:#0{10}x}"


def printhex(val):
    print(f"{hexstr(val)}")


def tabluate(headers: List[str], data: List[List[str]], title: str):
    x = PrettyTable()
    x.field_names = headers
    for r in data:
        x.add_row(r)
    print(x.get_string(title=title))


def shellcode_hexer(shellcode: str) -> str:
    return shellcode.replace("\\x", "")


def shellcode_encoder(shellcode: str) -> bytes:
    unconverted = b""
    if shellcode.startswith("py:"):
        target_module = shellcode.split(":", 1)[1]
        if ":" in target_module:
            target_parts = target_module.rsplit(":", 1)
        elif "." in target_module:
            target_parts = target_module.rsplit(".", 1)
        else:
            target_parts = [target_module, target_module]
        module_name = target_parts[0]
        module_object = import_module(module_name)
        target_name = target_parts[1]
        val = getattr(module_object, target_name)
        if not val:
            print(
                f"Unable to find shellcode for python import for {target_name} in module {module_name}"
            )
            sys.exit(1)
        if isinstance(val, bytes):
            return val
        unconverted = val

    elif shellcode.startswith("txt:"):
        target_file = shellcode.split(":", 1)[1]
        if not Path(target_file).is_file():
            print(f"Unable to find a file with text shellcode at {str(target_file)}")
            sys.exit(1)
        data = Path(target_file).read_text().replace("\n", "")
        unconverted = data.strip()

    elif shellcode.startswith("bin:"):
        target_file = shellcode.split(":", 1)[1]
        if not Path(target_file).is_file():
            print(f"Unable to find a file with binary shellcode at {str(target_file)}")
            sys.exit(1)
        data = Path(target_file).read_bytes()
        return data
    else:
        unconverted = shellcode

    hexed = shellcode_hexer(unconverted)
    converted = bytes.fromhex(hexed)
    if len(converted) > 4096:
        print("Shellcode is too large. Must be less than 4096")
        sys.exit(1)
    return converted
