import re
import os
from typing import List, Dict, Any, Tuple, Set

convert_type = {
    "UINT8": "uint8_t",
    "UINT16": "uint16_t",
    "UINT32": "uint32_t",
    "UINT64": "uint64_t",
    "INT8": "int8_t",
    "INT16": "int16_t",
    "INT32": "int32_t",
    "INT64": "int64_t",
    "BOOLEAN": "bool",
    "CHAR8": "char",
    "CHAR16": "char16_t",
    "VOID": "void",
    "VOID*": "void*",
    "UINTN": "uint64_t",
    "INTN": "int64_t",
    "EFI_GUID": "EFI_GUID"
}

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

aliases_map = {}

def get_type(arg_type: str) -> str:
    if remove_ref_symbols(arg_type) in aliases_map.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases_map[remove_ref_symbols(arg_type)])
    else:
        return arg_type

# create the structures converted to normal c types
def create_structs(type: str, fields: List[FieldInfo]) -> List[str]:
    output = []
    output.append("typedef struct {")
    for field in fields:
        if get_type(field.type) in convert_type.keys():
            output.append(f"    {field.type.replace(remove_ref_symbols(field.type), convert_type[get_type(field.type)])} {field.name};")
        else:
            output.append(f"    uint64_t {field.name};")
    output.append('}' + f" {type};")
    output.append("")

    return output


def remove_ref_symbols(type_str: str) -> str:
    return re.sub(r" *\*| *&", "", type_str)

def generate_outputs(all_args: Dict[str, List[Argument]],
                    arg_type_list: List[TypeTracker],
                     indent: bool) -> List[str]:
    output = []
    tmp = []
    
    for arg_key, arguments in all_args.items():
        if "OUT" in arguments[0].arg_dir and not "IN" in arguments[0].arg_dir:
            tmp.extend(declare_var(arg_key, arguments, arg_type_list, False))
    
    if len(tmp) > 0:
        output.append("/*")
        output.append("    Output Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    return add_indents(output, indent)


def harness_header(includes: List[str], 
                   functions: Dict[str, FunctionBlock],
                   types: Dict[str, List[FieldInfo]]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_HARNESSES__")
    output.append("#define __FIRNESS_HARNESSES__")

    output.append("#include \"FirnessHelpers_std.h\"")

    for type, fields in types.items():
        output.extend(create_structs(type, fields))
        output.append("")

    for function, function_block in functions.items():
        output.append(f"int Fuzz{function}(")
        output.append(f"    INPUT_BUFFER *Input")
        output.append(");")

    output.append("#endif")

    return output
    

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
    
    output.append(f"printf(\"Status = {call_prefix}{function}\\n\");")

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def declare_var(arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        print(f"ERROR: {arg_key} has more than 2 pointers")
        return output
    elif arguments[0].pointer_count == 2:
        arg_type = "uint64_t*" if "void" in arguments[0].arg_type.lower()  else arguments[0].arg_type.replace('**', '*')
        arg_type_list.append(TypeTracker(arg_type, arg_key, 1))
    else:
        arg_type = add_ptrs("uint64_t", arguments[0].pointer_count) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count))
    if arguments[0].pointer_count > 0:
        output.append(f'printf(\"{arg_type} {arg_key} = NULL;\\n\");')
    else:
        output.append(f"printf(\"{arg_type} {arg_key};\\n\");")
    
    return add_indents(output, indent)

def fuzzable_args(arg: str, 
                  indent: bool) -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    output.append(f'uint64_t {arg} = 0;')
    output.append(f"ReadBytes(Input, sizeof({arg}), &{arg});")
    output.append(f'printf(\"{arg} = %lx;\\n\", {arg});')
    
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
            tmp.extend(declare_var(arg_key, arguments, arg_type_list, False))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if arguments[0].variable == "__FUZZABLE__":
                output.extend(fuzzable_args(arg_key, False))
            elif "__CONSTANT" in arguments[0].variable or "__ENUM_ARG__" in arguments[0].variable:
                output.extend(constant_args(arg_key, arguments, False))
            elif "__FUNCTION_PTR__" in arguments[0].variable:
                output.extend(function_ptr_args(arg_key, arguments, False))
            elif "EFI_GUID" in arguments[0].arg_type:
                output.extend(guid_args(arg_key, arguments, False))
            elif (
                arguments[0].variable.startswith('__FUZZABLE_')
                and arguments[0].variable.endswith('_STRUCT__')
            ) or "__GENERATOR_FUNCTION__" in arguments[0].variable:
                output.extend(generator_struct_args(arg_key, arguments, types, services, protocol_variable, generators, False))
            output.append("")

    return add_indents(output, indent)

def remove_quotes(string):
    if string is None:
        return None
    
    return string.replace("\"", "")

def constant_args(arg_key: str, 
                  arguments: List[Argument],
                  indent: bool) -> List[str]:
    output = []
    output.append("// Constant Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        if argument.usage == "":
            output.append(f'        printf(\"{arg_key} = NULL;\\n\");')
        else:
            output.append(f'        printf(\"{arg_key} = {remove_quotes(argument.usage)};\\n\");')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def function_ptr_args(arg_key: str, 
                      arguments: List[Argument],
                      indent: bool) -> List[str]:
    output = []
    output.append("// Function Pointer Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        printf(\"{arg_key} = {argument.usage};\");')
        output.append(f'        break;')
    output.append('}')
    
    # VOID* {{ arg_key }};

    return add_indents(output, indent)

def guid_args(arg_key: str, 
              arguments: List[Argument],
              indent: bool) -> List[str]:
    output = []
    output.append("// EFI_GUID Variable Initialization")
    output.append(f'uint8_t {arg_key}_choice = 0;')
    output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
    output.append(f'switch({arg_key}_choice % {len(arguments)})' + ' {')
    for index, argument in enumerate(arguments):
        output.append(f'    case {index}:')
        output.append(f'        printf(\"{arg_key} = &{argument.variable};\\n\");')
        output.append(f'        break;')
    output.append('}')

    return add_indents(output, indent)

def generator_struct_args(arg_key: str, 
                          arguments: List[Argument], 
                          types: Dict[str, List[FieldInfo]], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock],
                          indent: bool) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    if len(arguments) > 1:
        output.append(f'uint8_t {arg_key}_choice = 0;')
        output.append(f'ReadBytes(Input, sizeof(uint8_t), &{arg_key}_choice);')
        output.append(f'switch({arg_key}_choice % {len(arguments)})' +' {')
        for index, argument in enumerate(arguments):
            output.append(f'    case {index}:')
            if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
                output.append(f'        printf(\"{argument.arg_type}\\n\");')
                output.append(f'        {remove_ref_symbols(arguments[0].arg_type)} {arg_key};')
                for field in types[remove_ref_symbols(argument.arg_type)]:
                    if field.type != "EFI_GUID":
                        output.append(f'        {arg_key}.{field.name} = 0;')
                    output.append(f'        ReadBytes(Input, sizeof({arg_key}.{field.name}), &({arg_key}.{field.name}));')
                    output.append(f'        printf(\"\t{field.name} = %lx;\\n\", {arg_key}.{field.name});')            # elif "__GENERATOR_FUNCTION__" in argument.variable:
            #     output.extend(function_body(generators[argument.assignment], services, protocol_variable, generators, types, True))
            output.append(f'        break;')
        output.append('}')
    else:
        if arguments[0].variable.startswith('__FUZZABLE_') and arguments[0].variable.endswith('_STRUCT__'):
            output.append(f'printf(\"{arguments[0].arg_type}\\n\");')
            output.append(f'{remove_ref_symbols(arguments[0].arg_type)} {arg_key};')
            for field in types[remove_ref_symbols(arguments[0].arg_type)]:
                if field.type != "EFI_GUID":
                    output.append(f'{arg_key}.{field.name} = 0;')
                output.append(f'ReadBytes(Input, sizeof({arg_key}.{field.name}), &({arg_key}.{field.name}));')
                output.append(f'printf(\"\t{field.name} = %lx;\\n\", {arg_key}.{field.name});')
        #     output.extend(function_body(generators[arguments[0].assignment], services, protocol_variable, generators, types, False))        

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
    output.extend(generate_outputs(function_block.arguments, arg_type_list, False))
    output.extend(call_function(function_block.function, function_block, services, protocol_variable, arg_type_list, False))

    return add_indents(output, indent)


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, List[FieldInfo]], 
                      aliases: Dict[str, str],
                      generators: Dict[str, FunctionBlock]) -> List[str]:
    # Initialize an empty string to store the generated content
    aliases_map.update(aliases)
    output = []

    output.append("#include \"FirnessHarnesses_std.h\"")
    output.append("")

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the {services[function].service} service")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f"int Fuzz{function}(")
        output.append(f"    INPUT_BUFFER *Input")
        output.append(") {")
        output.append(f"    printf(\"Fuzzing {function}...\\n\");")
        output.append(f"    int Status = 0;")
        protocol_variable = ""
        if "protocol" in services[function].service:
            protocol_variable = "ProtocolVariable"
            output.append(f"    printf(\"{function_block['Arg_0'][0].arg_type} {protocol_variable};\\n\");")

        output.extend(function_body(function_block, services, protocol_variable, generators, types, True))

        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output


def gen_firness_main(functions: Dict[str, FunctionBlock]) -> List[str]:
    output = []

    output.append("#include \"FirnessHarnesses_std.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    output.append("int main (int argc, char *argv[])")
    output.append("{")
    output.append("    if (argc != 2) {")
    output.append("        printf(\"Usage: %s <filename>\\n\", argv[0]);")
    output.append("        return 1;")
    output.append("    }")
    output.append("")
    output.append("    int Status = 0;")
    output.append("")
    output.append('    uint64_t input_max_size = 0x1000;')
    output.append('    Input.Length = input_max_size;')
    output.append('    uint8_t *input = (uint8_t *)malloc(sizeof(uint8_t)*input_max_size);')
    output.append("")
    output.append("    if (!input) {")
    output.append("        return 1;")
    output.append("    }")
    output.append("")
    output.append("    memset(input, 0, input_max_size);")
    output.append("    read_byte_file(argv[1], input, input_max_size);")
    output.append("    Input.Buffer = input;")
    output.append("")
    output.append("    uint8_t DriverChoice = 0;")
    output.append("    ReadBytes(&Input, sizeof(uint8_t), &DriverChoice);")
    output.append(f'    switch(DriverChoice%{len(functions)})')
    output.append("    {")
    for index, function in enumerate(functions):
        output.append(f'        case {index}:')
        output.append(f'            Status = Fuzz{function}(&Input);')
        output.append("            break;")
    output.append("    }")
    output.append("")
    output.append("    if(input)")
    output.append("    {")
    output.append("        free(input);")
    output.append("    }")
    output.append("")
    output.append("    return Status;")
    output.append("}")

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

def compile(harness_folder: str):
    os.system(f'clang -w -g -o firness_decoder {harness_folder}/FirnessMain_std.c {harness_folder}/FirnessHarnesses_std.c')