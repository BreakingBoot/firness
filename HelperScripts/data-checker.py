import json

def check_argument_count(json_file):
    # Load the JSON data from file
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Define a dictionary to hold the correct argument counts for each function
    correct_arg_counts = {
        'CopyMem': 3,
        'SetVariable': 5,
        'GetVariable': 5
    }

    # Iterate through each function block in the data
    with open('data-error.txt', 'w') as f:
        for function_block in data:
            function_name = function_block.get('Function')
            arguments = function_block.get('Arguments')

            # If the function name or arguments are missing, or the argument count is incorrect, print the function block
            if function_name not in correct_arg_counts or arguments is None or len(arguments) != correct_arg_counts[function_name]:
                f.write(json.dumps(function_block, indent=4))

# Usage:
check_argument_count('output-database.json')
