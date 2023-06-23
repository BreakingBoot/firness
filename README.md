# Auto-Generate EDK2 Harness

## Overview

## Functionality

### Code Analysis
The current implementation utilizes Python's `clang` library to create an AST to trace calls through a tree. This part has three main goals:

1. Find all of the function definitions of the given services and capture its information.
2. Find all of the function calls of the given services and capture the input information (Mostly works, but has problems when the main function is called through a pointer in the System Table).
3. Determine which parameters are directly fuzzable with random inputs or whether it needs to be well-formed (Currently under development). 

So with the above information two files are created:

1. `Function_Information.json`: this stores the function calls and function definitions.
2. `Fuzzability.json`: this stores all of the input information and whether it needs to be well-formed or can be random data from AFL.

### Code Generation
This section currently uses Python's `jinja` library which allows for creating data dependent files (aka. the file structure can change depending on the given input data). This comes in handy when input data depends on the services being fuzzed, so it could have one input or five. 

## ToDo's
- Need to be able to trace function calls through the System Tables (Difficult to do with Python Clangs AST)
- 
bear -- build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t CLANG38
ninja -j6
bin/test-scan -p /home/gl055/Research/Bootloaders/src/edk2/ /home/gl055/Research/Bootloaders/src/edk2/MdeModulePkg/Application/Demo1_Bob/Demo1_Bob.c

