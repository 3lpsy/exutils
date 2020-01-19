# Exutils: A Small Collection of Python Scripts for Binary Analysis and Manipulation

### injectnewsectionpex86.py

Inject shellcode into a binary by creating a new section and changing the entrypoint via pefile. Attempts can be made to 'fix' the executable so that it restores the registers.

```
usage: injectnewsectionpex86.py [-h] -s SHELLCODE -f FILE [-o OUTPUT] [-F] [--no-fix]

Inject shellcode into new section

optional arguments:
  -h, --help            show this help message and exit
  -s SHELLCODE, --shellcode SHELLCODE
                        shellcode to convert in \xAA\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \AA format in a
                        file via 'txt:/path/to/file', and binary data in a file via 'bin:/path/to/binary')
  -f FILE, --file FILE  path to pe file
  -o OUTPUT, --output OUTPUT
                        path to newly created pe file
  -F, --force           force overwrite output
  --no-fix              do not fix the payload with popa and pusha

```

### shell2asm.py

Convert shellcode to assembly via capstone

```
usage: shell2asm.py [-h] -s SHELLCODE [-a {x86}] [-m {x32,x64}] [-S START]

Convert shellcode to assembly

optional arguments:
  -h, --help            show this help message and exit
  -s SHELLCODE, --shellcode SHELLCODE
                        shellcode to convert in \xAA\xBB format (can also pass: a python import path via 'py:somefile.someimporttarget', shellcode in \AA format in a
                        file via 'txt:/path/to/file', and binary data in a file via 'bin:/path/to/binary')
  -a {x86}, --arch {x86}
                        architecture (default: x86)
  -m {x32,x64}, --mode {x32,x64}
                        mode (default: 64)
  -S START, --start START
                        start in hex or decimal format (default: 0x1000)
```

### peinfo.py

Get basic info from a PE using pefile

```
usage: peinfo.py [-h] -f FILE [-i {all,sections,imported,exported,dump,entry,start}]

Inspect PE File

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
