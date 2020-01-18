from utils import hexstr


def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) // alignment) * alignment


def printhexi(msg, val):
    print(f"[*] {msg}: {hexstr(val)} - {val}",)


def printsecnames(msg, sections):
    print(
        f"[*] {msg}",
        " ".join([s.Name.decode() for s in sections]),
        f"({len(sections)})",
    )
