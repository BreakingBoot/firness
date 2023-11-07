import json
import argparse
import uuid
import ast
import re
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
from typing import List, Dict, Any, Tuple, Set

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
    def __init__(self, arguments: Dict[str, List[Argument]], function: str, service: str, includes: List[str] = []):
        self.arguments = arguments
        self.service = service
        self.function = function
        self.includes = includes

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

def generate_outputs(all_args: Dict[str, List[Argument]]):
    output = ""
    output += "/*\n"
    output += "    Output Variable Declerations\n"
    output += "*/\n"

    for arg_key, arguments in all_args.items():
        if "OUT" in arguments[0].arg_dir:
            output += declare_var(arg_key, arguments)
    # if "*" in arguments[0].arg_type:
    #     arg_type = "UINTN" if arguments[0].arg_type == "void" else arguments[0].arg_type.replace('*', '')
    #     output += f"{arg_type} {arg_key};\n"
    # else:
    #     arg_type = "UINTN" if arguments[0].arg_type == "void" else arguments[0].arg_type
    #     output += f"{arg_type} {arg_key};\n"
    
    return output


def harness_header(includes: List[str], functions: Dict[str, FunctionBlock]):
    output = ""
    output += "#ifndef __FIRNESS_HARNESSES__\n"
    output += "#define __FIRNESS_HARNESSES__\n"

    for include in includes:
        output += f"#include <{include}>\n"
    output += "#include \"FirnessHelpers.h\"\n"

    for function, function_block in functions.items():
        output += f"EFI_STATUS\n"
        output += f"EFIAPI\n"
        output += f"Fuzz{function}(\n"
        output += f"    IN INPUT_BUFFER *Input,\n"
        output += f"    IN EFI_SYSTEM_TABLE *SystemTable\n"
        output += ");\n"

    output += "#endif\n"

    return output

def call_function(function: str, function_block: FunctionBlock, services: Dict[str, FunctionBlock], protocol_variable: str):
    output = ""
    if "protocol" in services[function].service:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[function].service or "Boot" in services[function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[function].service or "Runtime" in services[function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    else:
        call_prefix = ""
    
    output += f"    Status = {call_prefix}{function}(\n"
    for arg_key, arguments in function_block.arguments.items():
        arg_prefix = "&" if "void" in arguments[0].arg_type or arguments[0].pointer_count > 1 else ""
        output += f"        {arg_prefix}{arg_key},\n"
    output += f"    );\n"

    return output

def declare_var(arg_key: str, arguments: List[Argument]):
    output = ""
    if arguments[0].pointer_count > 1:
        arg_type = "UINTN" if arguments[0].arg_type == "void" else arguments[0].arg_type.replace('*', '')
    else:
        arg_type = "UINTN" if arguments[0].arg_type == "void" else arguments[0].arg_type

    output += f"{arg_type} *{arg_key} = NULL;\n"
    
    return output

def fuzzable_args(arg: str):
    output = ""
    output += "// Fuzzable Variable Initialization\n"
    output += f"ReadBytes(&Input, 1, &{arg});\n"
    
    return output

def generate_inputs(function_block: FunctionBlock, 
                    types: Dict[str, List[FieldInfo]], 
                    services: Dict[str, FunctionBlock], 
                    protocol_variable: str, 
                    generators: Dict[str, FunctionBlock]):
    output = ""
    output += "/*\n"
    output += "    Input Variable Declerations\n"
    output += "*/\n"

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            output += declare_var(arg_key, arguments)

    output += "\n"
    output += "/*\n"
    output += "    Input Variable Initialization\n"
    output += "*/\n"

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if arguments[0].variable == "__FUZZABLE__":
                output += fuzzable_args(arg_key)
            elif "__CONSTANT" in arguments[0].variable or "__ENUM_ARG__" in arguments[0].variable:
                output += constant_args(arg_key, arguments)
            elif "__FUNCTION_PTR__" in arguments[0].variable:
                output += function_ptr_args(arg_key, arguments)
            elif "EFI_GUID" in arguments[0].arg_type:
                output += guid_args(arg_key, arguments)
            elif (
                arguments[0].variable.startswith('__FUZZABLE_')
                and arguments[0].variable.endswith('_STRUCT__')
            ) or "__GENERATOR_FUNCTION__" in arguments[0].variable:
                output += generator_struct_args(arg_key, arguments, types, services, protocol_variable, generators)

    return output

def constant_args(arg_key: str, arguments: List[Argument]):
    output = ""
    output += "// Constant Variable Initialization\n"
    output += f'UINT8 *{arg_key}_choice = NULL;\n'
    output += f'ReadBytes(&Input, 1, &{arg_key}_choice);\n'
    output += f'switch({arg_key}_choice % {len(arguments)})' + ' {\n'
    for index, argument in enumerate(arguments):
        output += f'    case {index}:\n'
        if argument.usage == "":
            output += f'        {arg_key} = NULL;\n'
        else:
            output += f'        {arg_key} = {argument.usage};\n'
        output += f'        break;\n'
    output += '}\n'

    return output

def function_ptr_args(arg_key: str, arguments: List[Argument]):
    output = ""
    output += "// Function Pointer Variable Initialization\n"
    output += f'UINT8 *{arg_key}_choice = NULL;\n'
    output += f'ReadBytes(&Input, 1, &{arg_key}_choice);\n'
    output += f'switch({arg_key}_choice % {len(arguments)})' + ' {\n'
    for index, argument in enumerate(arguments):
        output += f'    case {index}:\n'
        output += f'        {arg_key} = {argument.usage};\n'
        output += f'        break;\n'
    output += '}\n'
    
    # VOID* {{ arg_key }};

    return output

def guid_args(arg_key: str, arguments: List[Argument]):
    output = ""
    output += "// EFI_GUID Variable Initialization\n"
    output += f'UINT8 *{arg_key}_choice = NULL;\n'
    output += f'ReadBytes(&Input, 1, &{arg_key}_choice);\n'
    output += f'switch({arg_key}_choice % {len(arguments)})' + ' {\n'
    for index, argument in enumerate(arguments):
        output += f'    case {index}:\n'
        output += f'        {arg_key} = &{argument.variable};\n'
        output += f'        break;\n'
    output += '}\n'

    return output

def generator_struct_args(arg_key: str, 
                          arguments: List[Argument], 
                          types: Dict[str, List[FieldInfo]], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock]):
    output = ""
    output += "// Generator Struct Variable Initialization\n"
    if len(arguments) > 1:
        output += f'UINT8 *{arg_key}_choice = NULL;\n'
        output += f'ReadBytes(&Input, 1, &{arg_key}_choice);\n'
        output += f'switch({arg_key}_choice % {len(arguments)})' +' {\n'
    for index, argument in enumerate(arguments):
        if len(arguments) > 1:
            output += f'    case {index}:\n'
            if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
                for field in types[argument.arg_type]:
                    output += f'ReadBytes(&Input, sizeof({field.name}), &{arg_key}.{field.name});\n'
            elif "__GENERATOR_FUNCTION__" in argument.variable:
                output += function_body(generators[argument.assignment], services, protocol_variable, generators, types)
            output += f'        break;\n'
        else:
            if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
                for field in types[argument.arg_type]:
                    output += f'ReadBytes(&Input, sizeof({field.name}), &{arg_key}.{field.name});\n'
            elif "__GENERATOR_FUNCTION__" in argument.variable:
                output += function_body(generators[argument.assignment], services, protocol_variable, generators, types)
    if len(arguments) > 1:
        output += '}\n'

    return output

def function_body(function_block: FunctionBlock, services: Dict[str, FunctionBlock], protocol_variable: str, generators: Dict[str, FunctionBlock], types: Dict[str, List[FieldInfo]]):
    output = ""
    output += generate_inputs(function_block, types, services, protocol_variable, generators)
    output += generate_outputs(function_block.arguments)
    output += call_function(function_block.function, function_block, services, protocol_variable)

    return output


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, List[FieldInfo]], 
                      generators: Dict[str, FunctionBlock]):
    # Initialize an empty string to store the generated content
    output_string = ""

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output_string += f"/*\n"
        output_string += f"    This is a harness for fuzzing the {services[function].service} service\n"
        output_string += f"    called {function}.\n"
        output_string += f"*/\n"
        output_string += f"EFI_STATUS\n"
        output_string += f"EFIAPI\n"
        output_string += f"Fuzz{function}(\n"
        output_string += f"    IN INPUT_BUFFER *Input,\n"
        output_string += f"    IN EFI_SYSTEM_TABLE *SystemTable\n"
        output_string += ") {\n"
        output_string += f"    EFI_STATUS Status = EFI_SUCCESS;\n"
        protocol_variable = ""
        if "protocol" in services[function].service:
            protocol_variable = "ProtocolVariable"
            output_string += f"    {function_block['Arg_0'][0].arg_type} {protocol_variable};\n"

        output_string += function_body(function_block, services, protocol_variable, generators, types)

        output_string += f"    // Include code for calling the function\n"
        output_string += f"    return Status;\n"
        output_string += "}\n"

    # Print or use the output_string as needed
    return output_string