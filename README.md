# Firness

An automated well-formed data type harness generator. 

## Overview

## Functionality

### Code Analysis

This section performs a Clang AST pass to gather all function calls and any type/structure definitions that are used within the function calls.

### Code Generation

This section currently uses Python's `jinja` library which allows for creating data dependent files (aka. the file structure can change depending on the given input data). This comes in handy when input data depends on the services being fuzzed, which could have one input or five. 

There are 3 steps that are used within this program:
- Performs a frequency analysis to only keep function calls of a certain name with the most number of arguments. This is important because some function calls may have local definitions of the same function name. For example, `CopyMem` is apart of the system table in EDK2 and only takes 3 arguements, but there is one file specific to a PEI module that has a `CopyMem` function defined that requires 5 arguments so my analysis removes that.
- Perform pre-processing of data to capture specific types for each argument. If one of the arguments is a string that is predefined in the code or a specific integer from an enum then I want to use those to allow to pass certain blocking statements that perform checks on those arguemnts (allowing for deeper code coverage). The pre-processing with save those interesting data structures to be used in a switch statement, along with identifying directly fuzzable arguments (i.e. scalable parameters).
- Perform a second stage of pre-process, which has the goal of tracing the non-scalable paremters through the datastructure and determine its fuzzablility. Currently, I go 3 levels deep of analysis (i.e. if a structure has a field of another structure it will only work down to 3 levels of structures). Sometimes the structures are defined via generator functions, so I maintain a data structure that contains all of the generator functions for any of the used data types. Once all of the anlysis is done then a final structure is generated to be used by the last part.
- Generate the code based of pre-defined tempaltes from `jinja`.

## Notes

The static anlysis utilizes a compilation database, which can be generated with the `bear` library:

```
bear -- build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t CLANG38
```

All of the dependencies are included in the included docker which can be built and run with:

```
sudo docker build -t fimware-analyzer .
sudo docker run -it -v ./:/llvm-source/llvm-15.0.7/clang-tools-extra/firness firness
```