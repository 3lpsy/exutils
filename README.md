# Exutils: A Small Collection of Python Scripts for Binary Analysis and Manipulation

## Usage

```
usage: injectx86.py [-h] {build,peinfo,shellasm} ...

Inject shellcode into new section

positional arguments:
  {build,peinfo,shellasm}
                        action
    build               build injected binary
    peinfo              get info about pefile
    shellasm            get asm from shellcode

optional arguments:
  -h, --help            show this help message and exit
```

### build;

Inject shellcode into a binary by creating a new section and changing the entrypoint via pefile. Attempts can be made to 'fix' the executable so that it restores the registers.

```
usage: injectx86.py build [-h] -s SHELLCODE -f FILE [-o OUTPUT] [-F] [--no-restore] [-c {auto,cave,new-section}] [-e {jump,new-section}]

optional arguments:
  -h, --help            show this help message and exit
  -s SHELLCODE, --shellcode SHELLCODE
                        shellcode to convert in \xAA\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \AA format in a file via 'txt:/path/to/file', and binary data in a file
                        via 'bin:/path/to/binary')
  -f FILE, --file FILE  path to source pe file
  -o OUTPUT, --output OUTPUT
                        path to newly created pe file
  -F, --force           force overwrite output
  --no-restore          do not fix the payload with popa and pusha
  -c {auto,cave,new-section}, --cave {auto,cave,new-section}
                        where to write the shellcode. defaults to auto
  -e {jump,new-section}, --enter {jump,new-section}
                        how to handle the entrypoing. defaults to 'jump' where the executable uses 'jmp' to move to new section

```

### shellasm

Convert shellcode to assembly via capstone

```
usage: injectx86.py shellasm [-h] -s SHELLCODE [-a {x86}] [-m {x32,x64}] [-S START]

optional arguments:
  -h, --help            show this help message and exit
  -s SHELLCODE, --shellcode SHELLCODE
                        shellcode to convert in \xAA\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \AA format in a file via 'txt:/path/to/file', and binary data in a file
                        via 'bin:/path/to/binary')
  -a {x86}, --arch {x86}
                        architecture (default: x86)
  -m {x32,x64}, --mode {x32,x64}
                        mode (default: 64)
  -S START, --start START
                        start in hex or decimal format (default: 0x1000)

```

### peinfo

Get basic info from a PE using pefile

```
usage: injectx86.py peinfo [-h] -f FILE [-i {all,sections,imported,exported,dump,entry,start}]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to pe file
  -i {all,sections,imported,exported,dump,entry,start}, --info {all,sections,imported,exported,dump,entry,start}
                        information to show

```

### Shoulders of Giants:

- https://github.com/rmadair/PE-Injector/blob/master/pe-injector.py
- https://axcheron.github.io/code-injection-with-python/#adding-the-section-header
- https://github.com/v-p-b/peCloakCapstone
- https://github.com/secretsquirrel/the-backdoor-factory
- https://nightcr4wl3r.blogspot.com/2017/11/automating-backdoor-creation-for-pe.html
