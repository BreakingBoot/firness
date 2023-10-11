#!/bin/bash

cd /home/gl055/clang-llvm/llvm-project/build/

# Compile
ninja -j10

# Execute
bin/test-scan -p $1
