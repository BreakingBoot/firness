import json
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict
from typing import List, Dict, Any

class Argument:
    def __init__(self, assignment: str, assignment_type: str, data_type: str, usage: str, variable: str):
        self.assignment = assignment
        self.assignment_type = assignment_type
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

    return function_dict

def generate_code(function_dict: Dict[str, List[FunctionBlock]]):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.jinja')
    code = template.render(function_dict=function_dict)
    print(code)

# Usage:
data = load_data('hardware-output.json')
generate_code(data)
