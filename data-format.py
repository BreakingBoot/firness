import json
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

def load_data(json_file: str) -> List[FunctionBlock]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    data = []
    for raw_function_block in raw_data:
        arguments = {
            arg_key: Argument(**raw_argument)
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get('Function'))
        data.append(function_block)

    return data

# Usage:
data = load_data('hardware-output.json')
print(data[0].arguments["Arg_1"].assignment)  # Output: CopyMem
