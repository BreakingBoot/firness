import json
import argparse
import uuid
import ast
import re
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
from typing import List, Dict, Any


scalable_params = [
    "int",
    "char",
    "bool",
    "uint",
    "long",
    "short",
    "float",
    "double",
    "size_t",
    "ssize_t"
]

ignore_constant_keywords = [
    "max",
    "size",
    "length",
    "min"
]

class Argument:
    def __init__(self, arg_dir: str, arg_type: str, assignment: str, data_type: str, usage: str, variable: str, potential_outputs: List[str] = []):
        self.arg_dir = arg_dir
        self.arg_type = arg_type
        self.assignment = assignment
        self.data_type = data_type
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

class FieldInfo:
    def __init__(self, name, type):
        self.name = name
        self.type = type

def object_to_dict(obj):
    if isinstance(obj, str):
        return obj 
    return obj.__dict__

function_template = {}
current_args_dict = defaultdict(list)
protocol_guids = set()
driver_guids = set()

#
# Load in the function call database and perform frequency analysis across
# the function calls to make sure to only keep the function calls that have
# the same type of input args
#
def load_data(json_file: str) -> Dict[str, List[FunctionBlock]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**raw_argument)]
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get('Function'), raw_function_block.get('Service'), raw_function_block.get('Include'))
        function_dict[function_block.function].append(function_block)

    # Determine the most common number of parameters for each function
    most_common_param_counts = {}
    for function, function_blocks in function_dict.items():
        param_counts = Counter(len(fb.arguments) for fb in function_blocks)
        most_common_param_counts[function] = param_counts.most_common(1)[0][0]

    # Filter the function_dict to only include FunctionBlock instances with the most common number of parameters
    filtered_function_dict = {function: [fb for fb in function_blocks if len(fb.arguments) == most_common_param_counts[function]]
                            for function, function_blocks in function_dict.items()}

    void_star_data_type_counter = defaultdict(Counter)

    # Step 1: Collect data_type statistics for arg_type of "void *"
    for function, function_blocks in filtered_function_dict.items():
        if function not in function_template:
            function_template[function] = function_blocks[0]
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update([argument[0].data_type])

                # Add a check for the services and if there is no service in the template add it
                if function_template[function].service == "" and not function_block.service == "":
                    function_template[function].service = function_block.service
            if len(function_block.arguments) > 0:
                if "protocol" in function_block.arguments["Arg_0"][0].arg_type.lower():
                    function_template[function].service = "protocol"

    # Step 2: Determine dominant data_type for each arg_key
    dominant_data_types = {}
    for arg_key, data_type_counter in void_star_data_type_counter.items():
        total = sum(data_type_counter.values())
        for data_type, count in data_type_counter.items():
            if count / total >= 0.9:
                dominant_data_types[arg_key] = data_type

    # Step 3: Filter out FunctionBlock instances with differing data_type for dominant arg_keys
    for function, function_blocks in filtered_function_dict.items():
        filtered_function_dict[function] = [
            fb for fb in function_blocks
            if all(
                arg_key not in dominant_data_types or
                argument[0].data_type == dominant_data_types[arg_key]
                for arg_key, argument in fb.arguments.items()
                if contains_void_star(argument[0].arg_type)
            )
        ]

    return filtered_function_dict


def load_generators(json_file: str) -> Dict[str, List[FunctionBlock]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**raw_argument)]
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get('Function'), raw_function_block.get('Service'))
        function_dict[function_block.function].append(function_block)

    return function_dict

#
# Get the intersect between all of the includes for each function of the same name
#
def get_intersect(input_data: Dict[str, List[FunctionBlock]],
                  pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            if len(pre_processed_data[function].includes) == 0:
                pre_processed_data[function].includes = function_block.includes
            else:
                pre_processed_data[function].includes = list(set(pre_processed_data[function].includes) & set(function_block.includes))
    return pre_processed_data

#
# Get the union between all of the includes between all functions
#
def get_union(pre_processed_data: Dict[str, FunctionBlock]) -> List[str]:
    union = []
    for function, function_block in pre_processed_data.items():
        union = list(set(union) | set(function_block.includes))
    return union

#
# Load in the structures
#
def load_types(json_file: str) -> Dict[str, List[FieldInfo]]:
    with open(json_file, 'r') as file:
        data = json.load(file)
    type_data_list = defaultdict(list)
    for type_data_dict in data:
        fields_list = []
        for field_dict in type_data_dict['Fields']:
            field_info = FieldInfo(field_dict['Name'], field_dict['Type'])
            fields_list.append(field_info)
        type_data_list[type_data_dict['TypeName']] = fields_list
    return type_data_list

#
# Filter out the guids that don't start with g and end with guid
#
def filter_guids(guids: List[str]) -> List[str]:
    filtered_guids = []
    for guid in guids:
        if guid.startswith('g') and guid.endswith('Guid'):
            filtered_guids.append(guid)
    return filtered_guids


def is_fuzzable_type(type: List[FieldInfo]) -> bool:
    is_fuzzable = False

    for field_info in type:
        is_scalable = any(param.lower() in field_info.type.lower() or 'efi_guid' in field_info.type.lower() for param in scalable_params)
        if is_scalable:
            is_fuzzable = True
        else:
            is_fuzzable = False
            break

    return is_fuzzable

def remove_ref_symbols(type: str) -> str:
    return re.sub(r"[ * &]", "", type)

def variable_fuzzable(input_data: Dict[str, List[FunctionBlock]], 
                      types: Dict[str, List[FieldInfo]],
                      pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    # for all of the functionblock argument data_types, check the types structure for the matching type
    # if the type is found and all of the fields are scalars, then add it to the create a new argument
    # and have the variable be __FUZZABLE_STRUCT__ and add it to the list

    # Add a check to not add an argument if the is already an argument of the variable name __FUZZABLE__
    # and a check to make sure that the variable name isn't __FUZZABLE_ARG_STRUCT__
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                is_scalable = any(param.lower() in argument[0].arg_type.lower() for param in scalable_params)
                contains_fuzzable_arg = any("__FUZZABLE_ARG_STRUCT__" in arg.variable for arg in pre_processed_data[function].arguments.setdefault(arg_key, []))
                added_struct = False
                if len(pre_processed_data[function].arguments.setdefault(arg_key, [])) > 0:
                    if pre_processed_data[function].arguments.get(arg_key)[0].variable == "__FUZZABLE__" or contains_fuzzable_arg:
                        break

                if argument[0].arg_dir == "IN" and not is_scalable:
                    if not contains_void_star(argument[0].arg_type):
                        if is_fuzzable_type(types[remove_ref_symbols(argument[0].arg_type)]):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE_ARG_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            added_struct = True
                    if not contains_void_star(argument[0].data_type) and not added_struct:
                        if is_fuzzable_type(types[remove_ref_symbols(argument[0].data_type)]):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE_DATA_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)

    return pre_processed_data
#
# Filters out any arguments that are not IN and CONSTANT values, but making sure
# to not keep duplicates
#
def collect_known_constants(input_data: Dict[str, List[FunctionBlock]],
                            pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    usage_seen = defaultdict(lambda: defaultdict(set))  # Keeps track of arg.usage values seen for each function and arg_key

    # Step 1: Collect all arguments, respecting the unseen filter
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                should_ignore_constant = any(keyword in argument[0].usage.lower() for keyword in ignore_constant_keywords)
                for arg in argument:
                    if 'efi_guid' in arg.arg_type.lower():
                        if 'protocolguid' in arg.variable.lower():
                            protocol_guids.add(arg.variable)  # Add to the protocol_guids set
                        else:
                            driver_guids.add(arg.variable)    # Add to the driver_guids set

                if not should_ignore_constant and (((argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and 
                      ((argument[0].variable == "__CONSTANT_STRING__" or 
                        argument[0].variable == "__CONSTANT_INT__" or 
                        argument[0].variable == "__FUNCTION_PTR__" or
                        argument[0].variable == "__ENUM_ARG__") 
                       and not contains_void_star(argument[0].arg_type))) or "efi_guid" in argument[0].arg_type.lower()):

                    # Check if arg.usage is already in the set for this function and arg_key
                    if len(argument[0].potential_outputs) > 1:
                        for argument_value in argument[0].potential_outputs:
                            if argument_value not in usage_seen[function][arg_key]:
                                new_arg = Argument(argument[0].arg_dir, argument[0].arg_type, argument[0].assignment, argument[0].data_type, argument_value, argument[0].variable, [])
                                pre_processed_data[function].arguments.setdefault(arg_key, []).append(new_arg)
                                current_args_dict[function].append(arg_key)
                                usage_seen[function][arg_key].add(argument_value)
                    elif argument[0].usage not in usage_seen[function][arg_key]:
                        pre_processed_data[function].arguments.setdefault(arg_key, []).append(argument[0])
                        current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].add(argument[0].usage)  # Update the set with the new arg.usage value

    return pre_processed_data

def contains_void_star(s):
    s_no_spaces = s.replace(" ", "").lower()
    return "void*" in s_no_spaces

# 
# Get fuzzable saves the arguments that take scalar inputs and also saves void * inputs that vary argument type
# by more than 5 since the assumption is that means the function is most likely manipulating data, not structures
# themselves
# 
def get_directly_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                          pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:

    for function, function_blocks in input_data.items():
        void_star_data_type_counter = defaultdict(Counter)

        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update([argument[0].data_type])
        
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                arg_type = argument[0].arg_type.lower()
                is_scalable = any(param.lower() in arg_type for param in scalable_params)
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and is_scalable and (arg_key not in current_args_dict[function])and (arg_key not in current_args_dict[function]) and (argument[0].variable != "__CONSTANT_INT__" and argument[0].variable != "__CONSTANT_STRING__"):
                    scalable_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                    current_args_dict[function].append(arg_key)
                    pre_processed_data[function].arguments.setdefault(arg_key, []).append(scalable_arg)
                    break
                elif contains_void_star(argument[0].arg_type) and (arg_key not in current_args_dict[function]) and len(void_star_data_type_counter[arg_key]) > 5:
                    scalable_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                    current_args_dict[function].append(arg_key)
                    pre_processed_data[function].arguments.setdefault(arg_key, []).append(scalable_arg)
                    break

    return pre_processed_data


def generate_main(function_dict: Dict[str, List[FunctionBlock]], harness_folder):
    env = Environment(loader=FileSystemLoader('./Templates/'))
    template = env.get_template('Firness_main_template.jinja')
    code = template.render(functions=function_dict)
    with open(f'{harness_folder}/FirnessMain.c', 'w') as f:
        f.write(code)

def generate_code(function_dict: Dict[str, FunctionBlock], data_template: Dict[str, FunctionBlock], types_dict: Dict[str, List[FieldInfo]], harness_folder):
    env = Environment(loader=FileSystemLoader('./Templates/'))
    template = env.get_template('code_template.jinja')
    code = template.render(functions=function_dict, services=data_template, types=types_dict)
    with open(f'{harness_folder}/FirnessHarnesses.c', 'w') as f:
        f.write(code)

def generate_header(function_dict: Dict[str, List[FunctionBlock]], 
                    all_includes: List[str], 
                    harness_folder):
    env = Environment(loader=FileSystemLoader('./Templates/'))
    template = env.get_template('header_template.jinja')
    code = template.render(functions=function_dict, includes=all_includes)
    with open(f'{harness_folder}/FirnessHarnesses.h', 'w') as f:
        f.write(code)

def generate_inf(harness_folder):
    env = Environment(loader=FileSystemLoader('./Templates/'))
    template = env.get_template('inf_template.jinja')
    code = template.render(uuid=uuid.uuid4(), guids=driver_guids, protocols=protocol_guids)
    with open(f'{harness_folder}/FirnessHarnesses.inf', 'w') as f:
        f.write(code)


def write_to_file(filtered_args_dict: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = [function_block.to_dict() for function_block in filtered_args_dict.values()]

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)


def print_filtered_args_dict(filtered_args_dict: Dict[str, List[FunctionBlock]]) -> None:
    for function, function_blocks in filtered_args_dict.items():
        print(f'Function: {function}')
        for idx, function_block in enumerate(function_blocks, 1):
            print(f'   Service: {function_block.service}')
            for arg_key, argument in function_block.arguments.items():
                print(f'    Argument Key: {arg_key}')
                print(f'      Arg Dir: {argument.arg_dir}')
                print(f'      Arg Type: {argument.arg_type}')
                print(f'      Assignment: {argument.assignment}')
                print(f'      Data Type: {argument.data_type}')
                print(f'      Usage: {argument.usage}')
                print(f'      Variable: {argument.variable}')

def print_template(template: Dict[str, FunctionBlock]) -> None:
    for function, function_block in template.items():
        print(f'Function: {function}')
        print(f'   Service: {function_block.service}')
        for arg_key, argument in function_block.arguments.items():
            print(f'    Argument Key: {arg_key}')
            print(f'      Arg Dir: {argument.arg_dir}')
            print(f'      Arg Type: {argument.arg_type}')
            print(f'      Assignment: {argument.assignment}')
            print(f'      Data Type: {argument.data_type}')
            print(f'      Usage: {argument.usage}')
            print(f'      Variable: {argument.variable}')

# write the template to a file
def write_template(template: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = {
        function: function_block.to_dict()
        for function, function_block in template.items()
    }

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

def get_generators(pre_processed_data: Dict[str, FunctionBlock], 
                   generators: Dict[str, List[FunctionBlock]], 
                   function_template: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:

    matching_generators = {}  # Dictionary to store the matching generators
    for func_name, generator_blocks in generators.items():
        for generator_block in generator_blocks:
            for argument in generator_block.arguments.values():
                # Check if argument direction is OUT
                if argument[0].arg_dir == "OUT" or argument[0].arg_dir == "IN_OUT":
                    # Look for a matching argument in function_template
                    for func_temp_name, func_temp_block in function_template.items():
                        for ft_arg_key, ft_argument in func_temp_block.arguments.items():
                            # Check if argument types match and the argument is missing from known_inputs
                            if (argument[0].arg_type == ft_argument[0].arg_type and 
                                    ft_arg_key not in current_args_dict[func_temp_name] and
                                    ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                # If matching generator is found, add it to the matching_generators dictionary
                                matching_generators.setdefault(func_temp_name, []).append(func_name)
                                generator_arg = Argument(ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__")
                                # current_args_dict[func_temp_name].append(ft_arg_key)
                                pre_processed_data[func_temp_name].arguments.setdefault(ft_arg_key, []).append(generator_arg)

    return pre_processed_data


def generate_harness_folder():
    # Define the outer directory name
    outer_dir = 'GeneratedHarnesses'

    # Get the date and time in the formate MM_DD_YYYY_HH_MM
    now = datetime.now()
    time_str = now.strftime('%m_%d_%Y_%H_%M')

    # Define the inner directory name based on the current time
    inner_dir = f'Harness_{time_str}'

    # Combine the outer and inner directory names to get the full path
    full_path = os.path.join(outer_dir, inner_dir)

    # Check if the outer directory exists, if not create it
    if not os.path.exists(outer_dir):
        os.makedirs(outer_dir)

    # Create the inner directory (this will create it regardless of whether it already exists)
    os.makedirs(full_path, exist_ok=True)
    
    # Copy the FirnessHelper.h to the full path
    os.system(f'cp HarnessHelpers/* {full_path}')

    # Return the full path of the inner directory
    return full_path

def write_to_file_output(data: Dict[str, List[FunctionBlock]], file_path: str):
    serializable_data = {
        func: {
            arg_key: [arg.to_dict() for arg in arg_list] 
            for arg_key, arg_list in func_block.arguments.items()
        } 
        for func, func_block in data.items()
    }
    
    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)

def generate_harness(merged_data: Dict[str, FunctionBlock], 
                     template: Dict[str, FunctionBlock], 
                     types: Dict[str, List[FieldInfo]], 
                     all_includes: List[str],
                     harness_folder: str):
    
    generate_main(merged_data, harness_folder)
    generate_code(merged_data, template, types, harness_folder)
    generate_header(merged_data, all_includes, harness_folder)
    generate_inf(harness_folder)


def initialize_data() -> Dict[str, FunctionBlock]:
    initial_data = {}
    for func, func_block in function_template.items():
        initial_data[func] = FunctionBlock({}, func, func_block.service)
    return initial_data

# Now add the output variables because we aren't trying to fuzz those
def add_output_variables(function_template: Dict[str, FunctionBlock],
                         pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if (argument[0].arg_dir == "OUT" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                pre_processed_data[function].arguments.setdefault(arg_key, []).append(argument[0])
                current_args_dict[function].append(arg_key)
    
    return pre_processed_data


def collect_all_function_arguments(input_data: Dict[str, List[FunctionBlock]],
                                   types: Dict[str, List[FieldInfo]],
                                   input_generators: Dict[str, List[FunctionBlock]]) -> Dict[str, FunctionBlock]:
    # Collect all of the arguments to be passed to the template
    pre_processed_data = initialize_data()
    pre_processed_data = get_intersect(input_data, pre_processed_data)

    # Step 1: Collect the constant arguments
    pre_processed_data = collect_known_constants(input_data, pre_processed_data)

    # Step 2: Collect the fuzzable arguments
    pre_processed_data = get_directly_fuzzable(input_data, pre_processed_data)

    # Step 3: collect the generator functions
    pre_processed_data = get_generators(pre_processed_data, input_generators, function_template)

    # Step 4: Collect the fuzzable structs
    pre_processed_data = variable_fuzzable(input_data, types, pre_processed_data)

    # Step 5: Add the output variables
    pre_processed_data = add_output_variables(function_template, pre_processed_data)

    return pre_processed_data


def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('-d', '--data-file', dest='data_file', default='tmp/call-database.json', help='Path to the data file (default: tmp/call-database.json)')
    parser.add_argument('-g', '--generator-file', dest='generator_file', default='tmp/generator-database.json', help='Path to the generator file (default: tmp/generator-database.json)')
    parser.add_argument('-t', '--types-file', dest='types_file', default='tmp/types.json', help='Path to the types file (default: tmp/types.json)')

    args = parser.parse_args()

    generators = load_generators(args.generator_file)
    data = load_data(args.data_file)
    types = load_types(args.types_file)
    harness_folder = generate_harness_folder()
    
    # These two are treated together because we want to use generators to handle any
    # input argument that isn't either directly fuzzable or of a known input
    # we will primarily use generators to handle the more compilicated structs
    # (i.e. more than one level of integrated structs) and the basic structs
    # that have all scalable fields will be directly generated with random input

    processed_data = collect_all_function_arguments(data, types, generators)
    all_includes = get_union(processed_data)

    write_to_file(processed_data, f'{harness_folder}/processed_data.json')
    generate_harness(processed_data, function_template, types, all_includes, harness_folder)


if __name__ == '__main__':
    main()
