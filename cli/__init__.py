from os import walk
from pathlib import Path
from os.path import join, basename, abspath, dirname
from importlib import import_module

parsers = {}


def extract_parsers(parent_dir, parent_mod):
    _parsers = {}
    for directory_name, _, files in walk(parent_dir):
        # import each file in parent_dir
        if not basename(directory_name).startswith(("__", "enums")):
            for f in sorted(files):
                if (
                    not f.startswith(("__", "enums"))
                    and Path(join(parent_dir, f)).is_file()
                ):
                    base_name = f.split(".")[0]
                    module_path = f"{parent_mod}.{base_name}"
                    module = import_module(module_path, "normalize")
                    normalize = getattr(module, "normalize", None)
                    apply = getattr(module, "apply", None)
                    run = getattr(module, "run", None)
                    if normalize and apply:
                        _parsers[base_name] = (apply, normalize, run)
                    else:
                        print(
                            f"failed to find command parser helpers for {module_path}"
                        )
    return _parsers


for name, parser_funcs in extract_parsers(abspath(dirname(__file__)), "cli").items():
    parsers[name] = parser_funcs
