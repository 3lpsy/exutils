#!/bin/bash

if [[ ! -f "samples/winrar-x64.exe" ]]; then
    echo "Downloading winrar-x64.exe to samples/"
    wget 'https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-580.exe' -O "samples/winrar-x64.exe"
fi

if [[ ! -f "samples/winrar-x86.exe" ]]; then
    echo "Downloading winrar-x86.exe to samples/"
    wget 'https://www.win-rar.com/fileadmin/winrar-versions/winrar/wrar580.exe' -O "samples/winrar-x86.exe"
fi