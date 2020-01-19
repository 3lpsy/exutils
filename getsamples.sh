#!/bin/bash

if [[ ! -f "samples/winrar-x64.exe" ]]; then
    echo "Downloading winrar-x64.exe to samples/"
    wget 'https://www.win-rar.com/fileadmin/winrar-versions/winrar/winrar-x64-580.exe' -O "samples/winrar-x64.exe"
fi

if [[ ! -f "samples/winrar-x86.exe" ]]; then
    echo "Downloading winrar-x86.exe to samples/"
    wget 'https://www.win-rar.com/fileadmin/winrar-versions/winrar/wrar580.exe' -O "samples/winrar-x86.exe"
fi

if [[ ! -f 'samples/7zip-x64.exe' ]]; then 
    echo "Downloading 7zip-x64.exe";
    wget 'https://www.7-zip.org/a/7z1900-x64.exe' -O "samples/7zip-x64.exe"
fi

if [[ ! -f 'samples/7zip-x86.exe' ]]; then 
    echo "Downloading 7zip-x86.exe";
    wget 'https://www.7-zip.org/a/7z1900.exe' -O "samples/7zip-x86.exe"
fi

if [[ ! -f "samples/putty-x86.exe" ]]; then 
    echo "Downloading putty-x86.exe"
    wget "https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe" -O "samples/putty-x86.exe";
fi

if [[ ! -f "samples/psftp-x86.exe" ]]; then 
    echo "Downloading psftp-x86.exe"
    wget "https://the.earth.li/~sgtatham/putty/latest/w32/psftp.exe" -O "samples/psftp-x86.exe";
fi

if [[ ! -f "samples/puttygen-x86.exe" ]]; then 
    echo "Downloading puttygen-x86.exe"
    wget "https://the.earth.li/~sgtatham/putty/latest/w32/puttygen.exe" -O "samples/puttygen-x86.exe";
fi
