import json
import argparse
import uuid
import ast
import re
import os
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any, Tuple, Set

class TypeTracker:
    def __init__(self, arg_type: str, variable: str, pointer_count: int):
        self.arg_type = arg_type
        self.name = variable
        self.pointer_count = pointer_count


class Argument:
    def __init__(self, arg_dir: str, arg_type: str, assignment: str, data_type: str, usage: str, variable: str, potential_outputs: List[str] = []):
        self.arg_dir = arg_dir
        self.arg_type = arg_type
        self.assignment = assignment
        self.data_type = data_type
        self.pointer_count = arg_type.count('*')
        self.usage = usage
        self.potential_outputs = potential_outputs
        self.variable = variable
    
    def to_dict(self):
        return {
            'Arg Dir': self.arg_dir,
            'Arg Type': self.arg_type,
            'Assignment': self.assignment,
            'Data Type': self.data_type,
            'Usage': self.usage,
            'Pointer Count': self.pointer_count,
            'Potential Values': self.potential_outputs,
            'Variable': self.variable
        }

class FunctionBlock:
    def __init__(self, arguments: Dict[str, List[Argument]], function: str, service: str, includes: Set[str] = [], return_type: str = ""):
        self.arguments = arguments
        self.service = service
        self.function = function
        self.includes = includes
        self.return_type = return_type

    def to_dict(self):
        return {
            'arguments': {key: [arg.to_dict() for arg in args] for key, args in self.arguments.items()},
            'service': self.service,
            'function': self.function,
            'includes': self.includes
        }

class Macros:
    def __init__(self, File: str, Name: str, Value: str):
        self.file = File
        self.name = Name
        self.value = Value

class FieldInfo:
    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type

aliases_map = {}

# this is a function that will return the underlying data type for any function
# so given EFI_PHYSICAL_ADDRESS it will return UINT64 by searching the aliases
# dictionary
def get_type(arg_type: str) -> str:
    if remove_ref_symbols(arg_type) in aliases_map.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases_map[remove_ref_symbols(arg_type)])
    else:
        return arg_type

def set_undefined_constants(argument: Argument) -> str:
    if "int" in get_type(argument.arg_type).lower() or argument.variable == "__ENUM_ARG__":
        return "0"
    elif "bool" in argument.arg_type.lower():
        return "FALSE"
    else:
        return "NULL"

def remove_ref_symbols(type_str: str) -> str:
    return re.sub(r" *\*| *&", "", type_str)

def generate_outputs(function: str,
                     all_args: Dict[str, List[Argument]],
                     arg_type_list: List[TypeTracker],
                     indent: bool) -> List[str]:
    output = []
    tmp = []
    
    for arg_key, arguments in all_args.items():
        if "OUT" in arguments[0].arg_dir and not "IN" in arguments[0].arg_dir:
            tmp.extend(declare_var(function, arg_key, arguments, arg_type_list, False))
            tmp.append(f"UINT8 {function}_{arg_key}_OutputChoice = 0;")
            tmp.append(f"ReadBytes(Input, sizeof({function}_{arg_key}_OutputChoice), &{function}_{arg_key}_OutputChoice);")
            tmp.append(f"if({function}_{arg_key}_OutputChoice % 2)")
            tmp.append("{")
            if arguments[0].pointer_count > 0:
                tmp.append(f"    ReadBytes(Input, sizeof(*{function}_{arg_key}), &{function}_{arg_key});")
            else:
                tmp.append(f"    ReadBytes(Input, sizeof({function}_{arg_key}), {function}_{arg_key});")
            tmp.append("}") 
    
    if len(tmp) > 0:
        output.append("/*")
        output.append("    Output Variable(s)")
        output.append("*/")
        output.extend(tmp)
     
    return add_indents(output, indent)

def harness_includes(includes: List[str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_INCLUDES__")
    output.append("#define __FIRNESS_INCLUDES__")

    output.append("")
    for include in includes:
        output.append(f"#include <{include}>")

    output.append("")
    output.append("#endif // __FIRNESS_INCLUDES__")

    return output

def harness_header(functions: Dict[str, FunctionBlock],
                   matched_macros: Dict[str, str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_HARNESSES__")
    output.append("#define __FIRNESS_HARNESSES__")

    output.append("")
    output.append("#include \"FirnessIncludes.h\"")
    output.append("#include \"FirnessHelpers.h\"")
    output.append("")

    for name, value in matched_macros.items():
        output.append(f"#define {name} {value}")
    output.append("")

    for function, function_block in functions.items():
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable")
        output.append(");")
        output.append("")

    output.append("#endif // __FIRNESS_HARNESSES__")

    return output

# properly add casts to the arguments based off the difference
# between the argument type and the type tracker type along with
# the pointer count
def cast_arg(function: str, 
             arg_key:str,
             arguments: List[Argument],
             arg_type_list: List[TypeTracker]) -> str:
    
    update_arg = ""
    for arg in arg_type_list:
        if arg.name == arg_key:
            if arg.arg_type != arguments[0].arg_type:
                update_arg += f'({arguments[0].arg_type})'
            if arguments[0].pointer_count > arg.pointer_count:
                update_arg += f'&'
            break
    update_arg += f'{function}_{arg_key}'

    return update_arg
    

def call_function(function: str, 
                  function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str,
                  arg_type_list: List[TypeTracker],                    
                  indent: bool) -> List[str]:
    output = []

    if "protocol" in services[function].service:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[function].service or "Boot" in services[function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[function].service or "Runtime" in services[function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    else:
        call_prefix = ""
    
    if function_block.return_type == "EFI_STATUS":
        output.append(f"Status = {call_prefix}{function}(")
    else:
        output.append(f"{call_prefix}{function}(")
    for arg_key, arguments in function_block.arguments.items():
        tmp = f"    {cast_arg(function, arg_key, arguments, arg_type_list)},"
        # if the last iteration remove the comma
        if arg_key == list(function_block.arguments.keys())[-1]:
            tmp = tmp[:-1]
        output.append(tmp)
    output.append(f");")

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def declare_var(function: str,
                arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        print(f"ERROR: {function} {arg_key} has more than 2 pointers")
        return output
    elif arguments[0].pointer_count == 2:
        arg_type = "UINTN*" if "void" in arguments[0].arg_type.lower()  else arguments[0].arg_type.replace('**', '*')
        arg_type_list.append(TypeTracker(arg_type, arg_key, 1))
        # output.append(f'UINT8 *{arg_key}_array = NULL;')
        # output.append(f'ReadBytes(&Input, sizeof({arg_key}_array), &{arg_key}_array);')
        # arg_type = f'{arg_type}[{arg_key}_array[0]]'
    else:
        arg_type = add_ptrs("UINTN", arguments[0].pointer_count) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count))
    if arguments[0].pointer_count > 0 and not "char" in arguments[0].arg_type.lower():
        output.append(f'{arg_type} {function}_{arg_key} = AllocatePool(sizeof({remove_ref_symbols(arg_type)}));')
    else:
        output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arguments[0])};")
    
    return add_indents(output, indent)

def fuzzable_args(function: str,
                  arg: str, 
                  indent: bool) -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    output.append(f"ReadBytes(Input, sizeof({function}_{arg}), &{function}_{arg});")
    
    return add_indents(output, indent)

def generate_inputs(function_block: FunctionBlock, 
                    types: Dict[str, List[FieldInfo]], 
                    services: Dict[str, FunctionBlock], 
                    protocol_variable: str, 
                    generators: Dict[str, FunctionBlock],
                    arg_type_list: List[TypeTracker],
                    indent: bool) -> List[str]:
    output = []
    tmp = []
    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            tmp.extend(declare_var(function_block.function, arg_key, arguments, arg_type_list, False))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if arguments[0].variable == "__FUZZABLE__":
                output.extend(fuzzable_args(function_block.function, arg_key, False))
            elif "__CONSTANT" in arguments[0].variable or "__ENUM_ARG__" in arguments[0].variable:
                output.extend(constant_args(function_block.function, arg_key, arguments, False))
            elif "__FUNCTION_PTR__" in arguments[0].variable:
                output.extend(function_ptr_args(function_block.function, arg_key, arguments, False))
            elif "EFI_GUID" in arguments[0].arg_type:
                output.extend(guid_args(function_block.function, arg_key, arguments, False))
            elif (
                arguments[0].variable.startswith('__FUZZABLE_')
                and arguments[0].variable.endswith('_STRUCT__')
            ) or "__GENERATOR_FUNCTION__" in arguments[0].variable:
                output.extend(generator_struct_args(function_block.function, arg_key, arguments, types, services, protocol_variable, generators, False))
                    
            output.append("")

    return add_indents(output, indent)

def constant_args(function: str,
                  arg_key: str, 
                  arguments: List[Argument],
                  indent: bool) -> List[str]:
    output = []
    output.append("// Constant Variable Initialization")
    output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
    output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        if argument.usage == "":
            output.append(f'        {function}_{arg_key} = {set_undefined_constants(argument)};')
        elif "char" in argument.arg_type.lower():
            output.append(f'        {function}_{arg_key} = StrDuplicate({argument.usage});')
        else:
            output.append(f'        {function}_{arg_key} = {argument.usage};')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def function_ptr_args(function:str, 
                      arg_key: str, 
                      arguments: List[Argument],
                      indent: bool) -> List[str]:
    output = []
    output.append("// Function Pointer Variable Initialization")
    output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
    output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        {function}_{arg_key} = {argument.usage};')
        output.append(f'        break;')
    output.append('}')
    
    # VOID* {{ arg_key }};

    return add_indents(output, indent)

def guid_args(function:str, 
              arg_key: str, 
              arguments: List[Argument],
              indent: bool) -> List[str]:
    output = []
    output.append("// EFI_GUID Variable Initialization")
    output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
    output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        {function}_{arg_key} = &{argument.variable};')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def generator_struct_args(function: str, 
                          arg_key: str, 
                          arguments: List[Argument], 
                          types: Dict[str, List[FieldInfo]], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock],
                          indent: bool) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    if len(arguments) > 1:
        output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
        output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
        output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' +' {')
        for index, argument in enumerate(arguments):
            output.append(f'    case {index}: ' + '{')
            if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
                for field in types[remove_ref_symbols(argument.arg_type)]:
                    output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), &({function}_{arg_key}->{field.name}));')
            elif "__GENERATOR_FUNCTION__" in argument.variable:
                generator_outputs = function_body(generators[argument.assignment], services, protocol_variable, generators, types, True)
                for line in generator_outputs:
                    output.append(f'    {line}')
                for generator_arg_key, generator_arguments in generators[argument.assignment].arguments.items():
                    if "OUT" in generator_arguments[0].arg_dir and not "IN" in generator_arguments[0].arg_dir:
                        if argument.arg_type in generator_arguments[0].arg_type:
                            output.append(f'        {function}_{arg_key} = {argument.assignment}_{generator_arg_key};')
            output.append(f'        break;')
            output.append('    }')
        output.append('}')
    else:
        if arguments[0].variable.startswith('__FUZZABLE_') and arguments[0].variable.endswith('_STRUCT__'):
            for field in types[remove_ref_symbols(arguments[0].arg_type)]:
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), &({function}_{arg_key}->{field.name}));')
        elif "__GENERATOR_FUNCTION__" in arguments[0].variable:
            output.extend(function_body(generators[arguments[0].assignment], services, protocol_variable, generators, types, False))        

    return add_indents(output, indent)

def function_body(function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str, 
                  generators: Dict[str, FunctionBlock], 
                  types: Dict[str, List[FieldInfo]],
                  indent: bool) -> List[str]:
    output = []
    arg_type_list = []
    output.extend(generate_inputs(function_block, types, services, protocol_variable, generators, arg_type_list, False))
    output.extend(generate_outputs(function_block.function, function_block.arguments, arg_type_list, False))
    output.extend(call_function(function_block.function, function_block, services, protocol_variable, arg_type_list, False))

    return add_indents(output, indent)


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, List[FieldInfo]], 
                      generators: Dict[str, FunctionBlock],
                      aliases: Dict[str, str]) -> List[str]:
    aliases_map.update(aliases)
    # Initialize an empty string to store the generated content
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the {services[function].service} service")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable")
        output.append(") {")
        output.append(f"    EFI_STATUS Status = EFI_SUCCESS;")
        protocol_variable = ""
        if "protocol" in services[function].service:
            protocol_variable = "ProtocolVariable"
            output.append(f"    {function_block['Arg_0'][0].arg_type} {protocol_variable};")

        output.extend(function_body(function_block, services, protocol_variable, generators, types, True))

        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output


def gen_firness_main(functions: Dict[str, FunctionBlock]) -> List[str]:
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    output.append("EFI_STATUS")
    output.append("EFIAPI")
    output.append("FirnessMain (")
    output.append("    IN EFI_HANDLE ImageHandle,")
    output.append("    IN EFI_SYSTEM_TABLE *SystemTable")
    output.append(") {")
    output.append("    EFI_STATUS Status = EFI_SUCCESS;")
    output.append("    UINT32 _a, _b, _c, _d = 0;")
    output.append("")
    output.append("    UINT8 buffer[0x20];")
    output.append("    UINTN size = sizeof(buffer) - 1;")
    output.append("    UINT8 *buffer_ptr = &buffer[0];")
    output.append("    UINTN *size_ptr = &size;")
    output.append("")
    output.append("    __asm__ __volatile__(")
    output.append("        \"cpuid\\n\\t\"")
    output.append("        : \"=a\"(_a), \"=b\"(_b), \"=c\"(_c), \"=d\"(_d), \"=S\"(buffer_ptr), \"=D\"(size_ptr)")
    output.append("        : \"0\"((0x0001U << 16U) | 0x4711U), \"S\"(buffer_ptr), \"D\"(size_ptr));")
    output.append("")
    output.append("    Input.Buffer = buffer_ptr;")
    output.append("    Input.Length = size;")
    output.append("")
    output.append("    UINT8 DriverChoice = 0;")
    output.append("    ReadBytes(&Input, sizeof(DriverChoice), &DriverChoice);")
    output.append(f'    switch(DriverChoice%{len(functions)})')
    output.append("    {")
    for index, function in enumerate(functions):
        output.append(f'        case {index}:')
        output.append(f'            Status = Fuzz{function}(&Input, SystemTable);')
        output.append("            break;")
    output.append("    }")

    output.append("")
    output.append("    __asm__ __volatile__(")
    output.append("        \"cpuid\\n\\t\"")
    output.append("        : \"=a\"(_a), \"=b\"(_b), \"=c\"(_c), \"=d\"(_d)")
    output.append("        : \"0\"((0x0002U << 16U) | 0x4711U));")
    output.append("")
    output.append("    return Status;")
    output.append("}")

    return output



def gen_firness_inf(uuid: str, 
                    driver_guids: List[str], 
                    protocol_guids: List[str]) -> List[str]:
    output = []

    output.append("[Defines]")
    output.append("  INF_VERSION                    = 0x00010005")
    output.append("  BASE_NAME                      = Firness")
    output.append(f'  FILE_GUID                      = {uuid}')
    output.append("  MODULE_TYPE                    = UEFI_APPLICATION")
    output.append("  VERSION_STRING                 = 1.0")
    output.append("  ENTRY_POINT                    = FirnessMain")

    output.append("")
    output.append("#")
    output.append("#  This flag specifies whether HII resource section is generated into PE image.")
    output.append("#")
    output.append("  UEFI_HII_RESOURCE_SECTION      = TRUE")

    output.append("")
    output.append("#")
    output.append("# The following information is for reference only and not required by the build tools.")
    output.append("#")
    output.append("#  VALID_ARCHITECTURES           = IA32 X64 EBC")
    output.append("#")

    output.append("")
    output.append("[Sources]")
    output.append("  FirnessMain.c")
    output.append("  FirnessHarnesses.c")
    output.append("  FirnessHelpers.c")

    output.append("")
    output.append("[Packages]")
    output.append("  MdePkg/MdePkg.dec")
    output.append("  MdeModulePkg/MdeModulePkg.dec")
    output.append("  ShellPkg/ShellPkg.dec")
    output.append("  NetworkPkg/NetworkPkg.dec")
    output.append("  OvmfPkg/OvmfPkg.dec")

    output.append("")
    output.append("[LibraryClasses]")
    output.append("  UefiApplicationEntryPoint")
    output.append("  UefiLib")
    output.append("  BaseLib")
    output.append("  BaseMemoryLib")
    output.append("  DebugLib")
    output.append("  UefiBootServicesTableLib")
    output.append("  UefiRuntimeServicesTableLib")
    # output.append("  UefiDriverEntryPoint")
    output.append("  PcdLib")
    output.append("  DxeServicesTableLib")
    output.append("  HobLib")

    output.append("")
    output.append("[Guids]")
    for guid in driver_guids:
        output.append(f'  {guid}')

    output.append("")
    output.append("[Protocols]")
    for guid in protocol_guids:
        output.append(f'  {guid}')

    return output


def add_indents(output: List[str], indent: bool) -> List[str]:
    if not indent:
        return output
    
    indented_output = []
    for line in output:
        indented_output.append(f"    {line}")
    return indented_output

def write_to_file(filename: str, output: List[str]):
    with open(filename, 'w') as f:
        f.writelines([line + '\n' for line in output])

