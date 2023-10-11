#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_file_name>"
    exit 1
fi

search_dir=/llvm-source/edk2/
clang_pass=/llvm-source/llvm-15.0.7/build/bin/firmware-analyzer
input_file_name="$1"

find "$search_dir" -type f -name "$input_file_name" -exec "$clang_pass" {} \;