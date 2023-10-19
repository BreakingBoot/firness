import json
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict, Counter
from typing import List, Dict, Any


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

def pre_process_data(function_dict: Dict[str, List[FunctionBlock]]) -> Dict[str, List[Argument]]:
    filtered_args_dict = defaultdict(list)

    for function, function_blocks in function_dict.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if argument.arg_dir == "IN" and (argument.variable == "__CONSTANT_STRING__" or argument.variable == "__CONSTANT_INT__"):
                    filtered_args_dict[function].append(argument)

    return filtered_args_dict

def generate_code(function_dict: Dict[str, List[FunctionBlock]], types_dict: Dict[str, List[FieldInfo]]):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.jinja')
    code = template.render(function_dict=function_dict)
    print(code)

def write_to_file(data: Dict[str, List[Argument]], file_path: str):
    serializable_data = {k: [object_to_dict(arg) for arg in v] for k, v in data.items()}
    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)

# Usage:
data = load_data('call-database.json')
pre_processed_data = pre_process_data(data)
types = load_types('types.json')
write_to_file(pre_processed_data, 'output.json')
#generate_code(data)
