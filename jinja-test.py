import json
import argparse
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
from typing import List, Dict, Any


scalable_params = [
    "int",
    "char"
]

ignore_constant_keywords = [
    "max",
    "size",
    "length",
    "min"
]

class Argument:
    def __init__(self, arg_dir: str, arg_type: str, assignment: str, data_type: str, usage: str, variable: str):
        self.arg_dir = arg_dir
        self.arg_type = arg_type
        self.assignment = assignment
        self.data_type = data_type
        self.usage = usage
        self.variable = variable

class FunctionBlock:
    def __init__(self, arguments: Dict[str, Argument], function: str):
        self.arguments = arguments
        self.function = function

function_template = Dict[str, FunctionBlock]

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
            arg_key: Argument(**raw_argument)
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get('Function'))
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
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if contains_void_star(argument.arg_type):
                    void_star_data_type_counter[arg_key].update([argument.data_type])

    # Step 2: Determine dominant data_type for each arg_key
    dominant_data_types = {}
    for arg_key, data_type_counter in void_star_data_type_counter.items():
        total = sum(data_type_counter.values())
        for data_type, count in data_type_counter.items():
            if count / total >= 0.9:
                dominant_data_types[arg_key] = data_type
                break

    # Step 3: Filter out FunctionBlock instances with differing data_type for dominant arg_keys
    for function, function_blocks in filtered_function_dict.items():
        filtered_function_dict[function] = [
            fb for fb in function_blocks
            if all(
                arg_key not in dominant_data_types or
                argument.data_type == dominant_data_types[arg_key]
                for arg_key, argument in fb.arguments.items()
                if contains_void_star(argument.arg_type)
            )
        ]

    return filtered_function_dict


def get_dominant_data_types(data_type_counter_dict):
    dominant_data_types = {
        function: {
            arg_key: max(data_type_counter, key=data_type_counter.get)
            for arg_key, data_type_counter in arg_keys_dict.items()
            if sum(data_type_counter.values()) * 0.9 <= data_type_counter[max(data_type_counter, key=data_type_counter.get)]
        }
        for function, arg_keys_dict in data_type_counter_dict.items()
    }
    return dominant_data_types

class FieldInfo:
    def __init__(self, name, type):
        self.name = name
        self.type = type

def object_to_dict(obj):
    if isinstance(obj, str):
        return obj 
    return obj.__dict__

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
# Filters out any arguments that are not IN and CONSTANT values, but making sure
# to not keep duplicates
#
def pre_process_data(function_dict: Dict[str, List[FunctionBlock]]) -> Dict[str, Dict[str, List[Argument]]]:
    filtered_args_dict = defaultdict(lambda: defaultdict(list))
    collected_args_dict = defaultdict(lambda: defaultdict(list))  # Temporary storage for collected arguments
    usage_seen = defaultdict(lambda: defaultdict(set))  # Keeps track of arg.usage values seen for each function and arg_key

    # Step 1: Collect all arguments, respecting the unseen filter
    for function, function_blocks in function_dict.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                should_ignore_constant = any(keyword in argument.usage.lower() for keyword in ignore_constant_keywords)
                if not should_ignore_constant and (((argument.arg_dir == "IN" or argument.arg_dir == "IN_OUT") and 
                      ((argument.variable == "__CONSTANT_STRING__" or argument.variable == "__CONSTANT_INT__") 
                       and not contains_void_star(argument.arg_type))) or "efi_guid" in argument.arg_type.lower()):
                    
                    # Check if arg.usage is already in the set for this function and arg_key
                    if argument.usage not in usage_seen[function][arg_key]:
                        collected_args_dict[function][arg_key].append(argument)
                        usage_seen[function][arg_key].add(argument.usage)  # Update the set with the new arg.usage value

    # Step 2: Filter arguments based on type consistency
    for function, arg_keys_dict in collected_args_dict.items():
        for arg_key, arguments in arg_keys_dict.items():
            # Check if all arguments have the same type
            type_set = {argument.variable for argument in arguments}
            # Check if any argument has 'efi_guid' in its arg_type
            efi_guid_present = any('efi_guid' in argument.arg_type.lower() for argument in arguments)
            if len(type_set) == 1 or efi_guid_present:  # All arguments have the same type or 'efi_guid' is present
                filtered_args_dict[function][arg_key] = arguments  # Keep these arguments

    return filtered_args_dict

def contains_void_star(s):
    s_no_spaces = s.replace(" ", "").lower()
    return "void*" in s_no_spaces

# 
# Get fuzzable saves the arguments that take scalar inputs and also saves void * inputs that vary argument type
# by more than 5 since the assumption is that means the function is most likely manipulating data, not structures
# themselves
# 
def get_fuzzable(function_dict: Dict[str, List[FunctionBlock]]) -> Dict[str, List[FunctionBlock]]:
    filtered_args_dict = defaultdict(list)

    for function, function_blocks in function_dict.items():
        void_star_data_type_counter = defaultdict(Counter)

        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if contains_void_star(argument.arg_type):
                    void_star_data_type_counter[arg_key].update([argument.data_type])
        
        for function_block in function_blocks:
            new_arguments = {}

            for arg_key, argument in function_block.arguments.items():
                arg_type = argument.arg_type.lower()
                is_scalable = any(param.lower() in arg_type for param in scalable_params)
                if (argument.arg_dir == "IN" or argument.arg_dir == "IN_OUT") and is_scalable and (argument.variable != "__CONSTANT_INT__" and argument.variable != "__CONSTANT_STRING__"):
                    scalable_arg = Argument(argument.arg_dir, argument.arg_type, "", argument.data_type, argument.usage, "__FUZZABLE__")
                    new_arguments[arg_key] = scalable_arg
                elif contains_void_star(argument.arg_type) and len(void_star_data_type_counter[arg_key]) > 5:
                    scalable_arg = Argument(argument.arg_dir, argument.arg_type, "", argument.data_type, argument.usage, "__FUZZABLE__")
                    new_arguments[arg_key] = scalable_arg


            # Create a new FunctionBlock with the filtered arguments and append it to filtered_args_dict[function]
            if new_arguments:
                new_function_block = FunctionBlock(new_arguments, function_block.function)
                filtered_args_dict[function].append(new_function_block)
                break

    return filtered_args_dict


def generate_code(function_dict: Dict[str, List[FunctionBlock]], types_dict: Dict[str, List[FieldInfo]]):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('Templates/code_template.jinja')
    code = template.render(function_dict=function_dict)
    with open("output_code.c", 'w') as f:
        f.write(code)

def write_to_file(data: Dict[str, Dict[str, List[Argument]]], file_path: str):
    serializable_data = {k: {arg_key: [object_to_dict(arg) for arg in arg_list] for arg_key, arg_list in v.items()} for k, v in data.items()}
    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)

def print_filtered_args_dict(filtered_args_dict: Dict[str, List[FunctionBlock]]) -> None:
    for function, function_blocks in filtered_args_dict.items():
        print(f'Function: {function}')
        for idx, function_block in enumerate(function_blocks, 1):
            for arg_key, argument in function_block.arguments.items():
                print(f'    Argument Key: {arg_key}')
                print(f'      Arg Dir: {argument.arg_dir}')
                print(f'      Arg Type: {argument.arg_type}')
                print(f'      Assignment: {argument.assignment}')
                print(f'      Data Type: {argument.data_type}')
                print(f'      Usage: {argument.usage}')
                print(f'      Variable: {argument.variable}')

def merge_fuzzable_known(
        known_inputs: Dict[str, Dict[str, List[Argument]]],
        directly_fuzzable: Dict[str, List[FunctionBlock]]
    ) -> Dict[str, List[FunctionBlock]]:

    merged_data = defaultdict(lambda: defaultdict(list))

    # Process known_inputs data
    for function, arguments_dict in known_inputs.items():
        for arg_key, arguments_list in arguments_dict.items():
                merged_data[function][arg_key] = arguments_list

    # Process directly_fuzzable data
    for function, function_blocks in directly_fuzzable.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if arg_key not in merged_data[function].keys():
                    merged_data[function][arg_key].append(argument)

    return merged_data



def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('-d', '--data-file', dest='data_file', default='tmp/call-database.json', help='Path to the data file (default: tmp/call-database.json)')
    parser.add_argument('-g', '--generator-file', dest='generator_file', default='tmp/generator-database.json', help='Path to the generator file (default: tmp/generator-database.json)')
    parser.add_argument('-t', '--types-file', dest='types_file', default='tmp/types.json', help='Path to the types file (default: tmp/types.json)')
    parser.add_argument('-o', '--output-file', dest='output_file', default='output.json', help='Path to the output file (default: output.json)')

    args = parser.parse_args()

    generators = load_data(args.generator_file)
    data = load_data(args.data_file)
    pre_processed_data = pre_process_data(data)
    directly_fuzzable = get_fuzzable(data)
    merged_data = merge_fuzzable_known(pre_processed_data, directly_fuzzable)
    # print_filtered_args_dict(directly_fuzzable)
    types = load_types(args.types_file)
    write_to_file(merged_data, args.output_file)

    generate_code(data, types)

if __name__ == '__main__':
    main()
