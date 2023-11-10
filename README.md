# Firness

An automated well-formed data type harness generator for UEFI. 

## Overview

Firness has three major components broken down into two steps:

1. Static Analysis
    - Clang AST passes
2. Harness Generation
    - Pre-processing the data
    - Code generation through templates

These steps will be explained in more detail in the sections below [Code Analysis][#analysis] and [Code Generation](#generation), respectively. Overall, the static analysis gathers all of the function calls of interest (along with additional helpful information) and outputs everything into a `.json` file for analysis by step 2. Step 2 is the harness generation, which is a python script responsible for analyzing the output from the code analysis to be able to then pass it into the templates after it has been properly formatted and parsed.

Most of the process has been completely automated, the only input required by the user is the input file which holds the functions that are trying to be harnessed. The input file looks as follows:

```
# Input file for Firness
[OtherFunctions]

[Protocols]

[BootServices]

[RuntimeServices]
    GetTime
    SetTime
```

We classified UEFI functions into 4 groups: Runtime Services, Boot Services, Protocols, and OtherFunctions. The first three are straight forward if you are familiar with UEFI, and the last group is a general method to handle the rest. This will be explained more in the [Code Analysis](#analysis) section.

## Functionality

### Code Analysis <a id="analysis"></a>

For the Clang AST passes, we perform Call Site Analysis along with Data Flow Analysis to help in the capturing of all of the necessary information. There are three passes used to handle this information:

1. [Data Flow Analysis](firness/VariableFlow.h)
2. [Call Site Analysis](firness/CallSiteAnalysis.h)
3. [Generator Function Analysis](firness/GeneratorAnalysis.h)

The Data Flow Analysis is responsible for gather all of the variables that are being used and their assignements. It does this by creating a map of the variable declerations that map to a stack of assignments where the top of the stack is the most recent assignmet. Special care was taken to also account for assignments made via library calls. Those calls are handled by utilizing the fact that the EDK2 codebase has identifiers for all function defintions (`IN`, `OUT`, `IN_OUT`), which tell the direction of the variable. Therefore, I am able to determine if a variable is assigned in another function if that functions definition is either `OUT` or `IN_OUT`.

Now that all of the variables and their assignments are captured, we started the Call Site Analysis. We visited all of the call sites that matched the functions inside the input file and collected all information about the call: the arguments directions, the source code input argument, the argument type, the input data type(incase there was a cast), the potential assignments(some inputs utilized branches so I calculate all options and save it to a list), the variable name that gets passed in, and finally, the last assignment before the call to that input variable (if there was one). There are two more pieces of information that get captured that aren't as important as the other ones: the includes statement for the file that the call appears in and the service of the function (i.e. the function table name if it is called via a function pointer).

With all of the call site information collected, we now have a general idea of what functions types we are interested in based of the `IN` identifier of the function calls that were captured. We mainted a set of those `IN` argument types and now perform a second, unrestricted call site anlaysis to gather any functions that have an `OUT` type that matched the set of `IN` types. We gather the same information as in the last analysis.

When the analysis is complete four `.json` files are outputed:

- `aliases.json`: Contains a map of typedef names
- `call-database.json`: This the output from the Call Site Analysis
- `generator-database.json`: This is the output from the Generator Analysis
- `types.json`: This is a map of structures and the fields of the structures to the types, which gets used when generating the harness.
- `macros.json`: This is the output of all macros, their value they are assigned, and their file location.

### Code Generation <a id="generation"></a>

This section utilizes a custom Python template engine used for generating the harness source code. It takes the analyzed `call-database.json` after post-processing, along with several other helper files with information extracted from the call database. 

There are several phases of the processing of the data before it is ready for the template engine:
1. Utilizes the `input.txt` that was used during the static analysis, along with a frequency analysis to do a preliminary pruning of the data.This is important because some function calls may have local definitions of the same function name. For example, `CopyMem` is apart of the system table in EDK2 and only takes 3 arguements, but there is one file specific to a PEI module that has a `CopyMem` function defined that requires 5 arguments so my analysis removes that.
2. Type based analysis on all of the function calls. Given a function, process all of the arguments and determine the function type. We have 4 type classifications:
    - Constants: Arguments that are predefined in the source code (Integers, Strings, enum values, macros that are constants, etc.).
    - Fuzzable Scalars: Arguments that aren't predefined, but have types that are of scalar type (Integers, String, etc.).
    - Fuzzable Structs: Structures that to one level type expansion have all Fuzzable Scalar fields.
    - Generator Functions: These are arguments that get generated through other function calls, which are important because in the instances where a structure isn't fuzzable to one level the generator functions can produce them.
    - Other: These would be structures that aren't fuzzable to one level or have a generator function (e.g. function pointers, linked-list structures). The analysis does capture function pointers, so it will utilize them if they can.
3. Once all of the analysis is complete, the structure which maps the functions to argument lists is passed to the template to generate the code.

The template engine creates 4 files based off of the information obtained from the call database during the anlysis: The main file to call the harnessed functions, a harnessed file which holds all of the harnessed functions, a header file for the harnessed functions, and an INF file needed for compiling with EDK2.

## Notes

The static anlysis utilizes a compilation database, which can be generated with the `bear` library:

```
Example: 
bear -- build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t CLANGPDB
```

All of the dependencies are included in the included docker which can be built and run with:

```
sudo docker build -t firness .
sudo docker run -it -v ./:/llvm-source/llvm-15.0.7/clang-tools-extra/firness firness
/llvm-source/llvm-15.0.7/clang-tools-extra/firness/patch.sh
/llvm-source/llvm-15.0.7/clang-tools-extra/firness/analyze.sh
```