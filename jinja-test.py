import json
import argparse
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
from typing import List, Dict, Any


scalable_params = [
    "INT",
    "CHAR"
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

    return filtered_function_dict

class FieldInfo:
    def __init__(self, name, type):
        self.name = name
        self.type = type

def object_to_dict(obj):
    if isinstance(obj, str):
        return obj 
    return obj.__dict__


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

# def pre_process_data(function_dict: Dict[str, List[FunctionBlock]]) -> Dict[str, Dict[str, List[Argument]]]:
#     filtered_args_dict = defaultdict(lambda: defaultdict(list))
#     usage_seen = defaultdict(lambda: defaultdict(set))  # Keeps track of arg.usage values seen for each function and arg_key

#     for function, function_blocks in function_dict.items():
#         for function_block in function_blocks:
#             for arg_key, argument in function_block.arguments.items():
#                 if argument.arg_dir == "IN" and (argument.variable == "__CONSTANT_STRING__" or argument.variable == "__CONSTANT_INT__"):
#                     # Check if arg.usage is already in the set for this function and arg_key
#                     if argument.usage not in usage_seen[function][arg_key]:
#                         filtered_args_dict[function][arg_key].append(argument)
#                         usage_seen[function][arg_key].add(argument.usage)  # Update the set with the new arg.usage value

#     return filtered_args_dict

def pre_process_data(function_dict: Dict[str, List[FunctionBlock]]) -> Dict[str, Dict[str, List[Argument]]]:
    filtered_args_dict = defaultdict(lambda: defaultdict(list))
    collected_args_dict = defaultdict(lambda: defaultdict(list))  # Temporary storage for collected arguments
    usage_seen = defaultdict(lambda: defaultdict(set))  # Keeps track of arg.usage values seen for each function and arg_key

    # Step 1: Collect all arguments, respecting the unseen filter
    for function, function_blocks in function_dict.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if argument.arg_dir == "IN" and (argument.variable == "__CONSTANT_STRING__" or argument.variable == "__CONSTANT_INT__"):
                    # Check if arg.usage is already in the set for this function and arg_key
                    if argument.usage not in usage_seen[function][arg_key]:
                        collected_args_dict[function][arg_key].append(argument)
                        usage_seen[function][arg_key].add(argument.usage)  # Update the set with the new arg.usage value

    # Step 2: Filter arguments based on type consistency
    for function, arg_keys_dict in collected_args_dict.items():
        for arg_key, arguments in arg_keys_dict.items():
            # Check if all arguments have the same type
            type_set = {argument.variable for argument in arguments}
            if len(type_set) == 1:  # All arguments have the same type
                filtered_args_dict[function][arg_key] = arguments  # Keep these arguments

    return filtered_args_dict


def generate_code(function_dict: Dict[str, List[FunctionBlock]], types_dict: Dict[str, List[FieldInfo]]):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.jinja')
    code = template.render(function_dict=function_dict)
    print(code)

def write_to_file(data: Dict[str, Dict[str, List[Argument]]], file_path: str):
    serializable_data = {k: {arg_key: [object_to_dict(arg) for arg in arg_list] for arg_key, arg_list in v.items()} for k, v in data.items()}
    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('-d', '--data-file', dest='data_file', default='tmp/call-database.json', help='Path to the data file (default: tmp/call-database.json)')
    parser.add_argument('-t', '--types-file', dest='types_file', default='tmp/types.json', help='Path to the types file (default: tmp/types.json)')
    parser.add_argument('-o', '--output-file', dest='output_file', default='output.json', help='Path to the output file (default: output.json)')

    args = parser.parse_args()

    data = load_data(args.data_file)
    pre_processed_data = pre_process_data(data)
    types = load_types(args.types_file)
    write_to_file(pre_processed_data, args.output_file)

    # generate_code(data)

if __name__ == '__main__':
    main()
