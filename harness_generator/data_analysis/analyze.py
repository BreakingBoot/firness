import json
from collections import defaultdict, Counter
from typing import List, Dict, Tuple
from common.types import FunctionBlock, FieldInfo, Argument, Macros, scalable_params, services_map, type_defs, known_contant_variables, ignore_constant_keywords, default_includes
from common.utils import remove_ref_symbols, write_data, write_data, get_union, is_whitespace, contains_void_star, contains_usage, get_stripped_usage, contains_void_star, contains_usage, get_stripped_usage, is_fuzzable, get_intersect


current_args_dict = defaultdict(list)

#
# load in the functions to be harnessed
#


def load_functions(function_file: str) -> Dict[str, List[str]]:
    # Load in the functions to be harnessed from the txt file
    # They are classified into 3 categories: OtherFunctions, BootServices, and RuntimeServices
    with open(function_file, 'r') as file:
        data = file.readlines()
    function_dict = defaultdict(list)
    current_service = ""
    for line in data:
        if line.strip() != "":
            if line.startswith("["):
                current_service = line.strip().replace("[", "").replace("]", "")
            else:
                function_dict[current_service].append(line.strip())
    return function_dict


def sort_data(input_data: Dict[str, List[FunctionBlock]],
              harness_functions: Dict[str, List[str]],
              best_guess: bool) -> Dict[str, List[FunctionBlock]]:
    sorted_data = {}
    # Determine the most common number of parameters for each function
    most_common_param_counts = {}
    for function, function_blocks in input_data.items():
        param_counts = Counter(len(fb.arguments) for fb in function_blocks)
        most_common_param_counts[function] = param_counts

    # group the data based on the number of parameters
    # and TODO: add a check for the parameters themselves
    # i.e. if there are multiple functions with the same number of parameters
    # then the arg_dir and arg_type must match
    # Also, if the most common param count isn't at least 50% of the total number of the different param counts
    # then don't keep any of the functions
    for function, param_counts in most_common_param_counts.items():
        if param_counts.most_common(1)[0][1] < len(input_data[function]) / 2:
            continue
        sorted_data[function] = {}
        if len(param_counts) != 1:
            for function_block in input_data[function]:
                sorted_data[function].setdefault(
                    len(function_block.arguments), []).append(function_block)
        else:
            sorted_data[function].setdefault(param_counts.most_common(1)[
                                             0][0], []).extend(input_data[function])

    # now loop through the sorted data and keep the groups of elements that have a corresponding service
    # in the harness_functions dictionary
    filtered_data = defaultdict(list)
    for function, arg_num_pairs in sorted_data.items():
        for _, function_blocks in arg_num_pairs.items():
            if not any(function in harness_functions[function_type] for function_type in harness_functions.keys()):
                continue
            arg_num_match = False
            for function_block in function_blocks:
                if any(keys in function_block.service for keys in services_map.keys()):
                    arg_num_match = True
                    break
            if arg_num_match:
                filtered_data.setdefault(function, []).extend(function_blocks)
            elif function in harness_functions["OtherFunctions"]:
                filtered_data.setdefault(function, []).extend(function_blocks)
    if best_guess:
        for function, arg_num_pairs in sorted_data.items():
            for _, function_blocks in arg_num_pairs.items():
                if not any(function in harness_functions[function_type] for function_type in harness_functions.keys()):
                    continue
                if function in filtered_data.keys():
                    break
                filtered_data.setdefault(function, []).extend(function_blocks)
                
    return filtered_data

#
# Load in the function call database and perform frequency analysis across
# the function calls to make sure to only keep the function calls that have
# the same type of input args
#


def load_data(json_file: str,
              harness_functions: Dict[str, List[str]],
              macros: Dict[str, Macros],
              random: bool,
              best_guess: bool) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**raw_argument)]
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        if random:
            for arg_key, argument in arguments.items():
                if argument[0].variable in known_contant_variables:
                    argument[0].variable = ""
        function_block = FunctionBlock(arguments, raw_function_block.get(
            'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
        function_dict[function_block.function].append(function_block)

    # Check if there is a single most common number of parameters for each function
    # and if not then take the one which has a service matching the harness_functions.keys()
    # note that if RT is in the service name, then it is a runtime service and BS is a boot service
    filtered_function_dict = sort_data(function_dict, harness_functions, best_guess)

    void_star_data_type_counter = defaultdict(Counter)
    function_template = {}

    # Collect data_type statistics for arg_type of "void *"
    for function, function_blocks in filtered_function_dict.items():
        if function not in function_template:
            function_template[function] = function_blocks[0]
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if remove_ref_symbols(function_template[function].arguments.get(arg_key)[0].arg_type) in type_defs.values():
                    function_template[function].arguments.get(
                        arg_key)[0].arg_type = argument[0].arg_type
                if argument[0].assignment in macros.keys():
                    argument[0].usage = macros[argument[0].assignment].name
                    argument[0].assignment = macros[argument[0].assignment].name
                elif argument[0].usage in macros.keys():
                    argument[0].assignment = macros[argument[0].usage].name
                    argument[0].usage = macros[argument[0].usage].name
                if contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])

                # Add a check for the services and if there is no service in the template add it
                if is_whitespace(function_template[function].service) and not is_whitespace(function_block.service):
                    function_template[function].service = function_block.service
            if len(function_block.arguments) > 0:
                if "protocol" in function_block.arguments["Arg_0"][0].arg_type.lower():
                    function_template[function].service = "protocol"
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                argument[0].arg_type = function_template[function].arguments.get(arg_key)[
                    0].arg_type

    return filtered_function_dict, function_template


def load_generators(json_file: str,
                    macros: Dict[str, Macros]) -> Dict[str, List[FunctionBlock]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**raw_argument)]
            for arg_key, raw_argument in raw_function_block.get('Arguments', {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get(
            'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
        function_dict[function_block.function].append(function_block)

    # Determine the most common number of parameters for each function
    most_common_param_counts = {}
    for function, function_blocks in function_dict.items():
        param_counts = Counter(len(fb.arguments) for fb in function_blocks)
        most_common_param_counts[function] = param_counts.most_common(1)[0][0]

    # Filter the function_dict to only include FunctionBlock instances with the most common number of parameters
    filtered_function_dict = {function: [fb for fb in function_blocks if len(fb.arguments) == most_common_param_counts[function]]
                              for function, function_blocks in function_dict.items()}

    for function, function_blocks in filtered_function_dict.items():
        for function_block in function_blocks:
            for _, argument in function_block.arguments.items():
                if argument[0].assignment in macros.keys():
                    argument[0].usage = macros[argument[0].assignment].name
                    argument[0].assignment = macros[argument[0].assignment].name
                elif argument[0].usage in macros.keys():
                    argument[0].assignment = macros[argument[0].usage].name
                    argument[0].usage = macros[argument[0].usage].name

    return filtered_function_dict


def load_aliases(json_file: str) -> Dict[str, str]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    return raw_data


#
# Load Macros
#
def load_macros(json_file: str) -> Tuple[Dict[str, Macros], Dict[str, Macros]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    macros_val = defaultdict()
    macros_name = defaultdict()
    for macro in raw_data:
        macros_val[macro["Value"]] = Macros(**macro)
        macros_name[macro["Name"]] = Macros(**macro)
    return macros_val, macros_name

#
# Load in the type structures
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


def variable_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                      types: Dict[str, List[FieldInfo]],
                      pre_processed_data: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      random: bool) -> Dict[str, FunctionBlock]:
    # for all of the functionblock argument data_types, check the types structure for the matching type
    # if the type is found and all of the fields are scalars, then add it to the create a new argument
    # and have the variable be __FUZZABLE_STRUCT__ and add it to the list

    # Add a check to not add an argument if the is already an argument of the variable name __FUZZABLE__
    # and a check to make sure that the variable name isn't __FUZZABLE_ARG_STRUCT__
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                contains_fuzzable_arg = any("__FUZZABLE_ARG_STRUCT__" in arg.variable
                                            or "__FUZZABLE__" in arg.variable
                                            or "__ENUM" in arg.variable
                                            or 'guid' in arg.arg_type.lower() for arg in pre_processed_data[function].arguments.setdefault(arg_key, []))
                added_struct = False
                if len(pre_processed_data[function].arguments.setdefault(arg_key, [])) > 0:
                    if (pre_processed_data[function].arguments.get(arg_key)[0].variable in known_contant_variables and not random) or contains_fuzzable_arg:
                        continue

                if argument[0].arg_dir == "IN":
                    if not contains_void_star(argument[0].arg_type):
                        if is_fuzzable(remove_ref_symbols(argument[0].arg_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_ARG_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            added_struct = True
                    if not contains_void_star(argument[0].data_type) and not added_struct:
                        if is_fuzzable(remove_ref_symbols(argument[0].data_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_DATA_STRUCT__", argument[0].potential_outputs)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)

    return pre_processed_data


#
# Filters out any arguments that are not IN and CONSTANT values, but making sure
# to not keep duplicates
#
def collect_known_constants(input_data: Dict[str, List[FunctionBlock]],
                            pre_processed_data: Dict[str, FunctionBlock],
                            macros: Dict[str, Macros],
                            aliases: Dict[str, str]) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Keeps track of arg.usage values seen for each function and arg_key
    usage_seen = defaultdict(lambda: defaultdict(set))
    matched_macros = defaultdict(list)
    protocol_guids = set()
    driver_guids = set()

    # Step 1: Collect all arguments
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                should_ignore_constant = any(
                    keyword in argument[0].usage.lower() for keyword in ignore_constant_keywords)
                for arg in argument:
                    if 'guid' in arg.arg_type.lower() and arg.variable.startswith('g') and arg.variable.endswith('Guid'):
                        if 'protocolguid' in arg.variable.lower():
                            # Add to the protocol_guids set
                            protocol_guids.add(arg.variable)
                        else:
                            # Add to the driver_guids set
                            driver_guids.add(arg.variable)

                if not should_ignore_constant and (((argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and
                                                    ((argument[0].variable in known_contant_variables)
                                                     and not contains_void_star(argument[0].arg_type))) or
                                                   ("guid" in argument[0].arg_type.lower() and argument[0].assignment == "" and argument[0].variable.startswith("g"))):

                    # Check if arg.usage is already in the set for this function and arg_key
                    if len(argument[0].potential_outputs) > 1:
                        for argument_value in argument[0].potential_outputs:
                            if not contains_usage(argument_value, usage_seen[function][arg_key], macros, aliases):
                                new_arg = Argument(argument[0].arg_dir, argument[0].arg_type, argument[0].assignment,
                                                   argument[0].data_type, argument_value, argument[0].variable, [])
                                pre_processed_data[function].arguments.setdefault(
                                    arg_key, []).append(new_arg)
                                if argument[0].assignment in macros.keys():
                                    matched_macros[macros[argument[0].assignment]
                                                   .name] = macros[argument[0].assignment].value
                                current_args_dict[function].append(arg_key)
                                usage_seen[function][arg_key].update(
                                    get_stripped_usage(argument_value, macros, aliases))
                    elif not contains_usage(argument[0].usage, usage_seen[function][arg_key], macros, aliases):
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(argument[0])
                        if argument[0].assignment in macros.keys():
                            matched_macros[macros[argument[0].assignment]
                                           .name] = macros[argument[0].assignment].value
                        current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].update(get_stripped_usage(
                            argument[0].usage, macros, aliases))  # Update the set with the new arg.usage value
    # Step 2: Filter out arguments with less than 3 different values
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) < 3:
                for arg in argument:
                    argument.remove(arg)
                current_args_dict[function].remove(arg_key)
    return pre_processed_data, matched_macros, protocol_guids, driver_guids


#
# Get fuzzable saves the arguments that take scalar inputs and also saves void * inputs that vary argument type
# by more than 5 since the assumption is that means the function is most likely manipulating data, not structures
# themselves.
#
def get_directly_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                          pre_processed_data: Dict[str, FunctionBlock],
                          aliases: Dict[str, str],
                          random: bool) -> Dict[str, FunctionBlock]:

    for function, function_blocks in input_data.items():
        void_star_data_type_counter = defaultdict(Counter)

        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
                if contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower()):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                arg_type = argument[0].arg_type.lower()
                is_scalable = any(param.lower() in arg_type or param.lower() in aliases.get(
                    arg_type, "").lower() for param in scalable_params)
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and is_scalable and (arg_key not in current_args_dict[function]):
                    scalable_arg = Argument(
                        argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                    current_args_dict[function].append(arg_key)
                    pre_processed_data[function].arguments.setdefault(
                        arg_key, []).append(scalable_arg)
                    continue
                elif (contains_void_star(argument[0].arg_type) or contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower())) and (arg_key not in current_args_dict[function]) and (len(void_star_data_type_counter[arg_key]) > 5 or random):
                    scalable_arg = Argument(
                        argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                    current_args_dict[function].append(arg_key)
                    pre_processed_data[function].arguments.setdefault(
                        arg_key, []).append(scalable_arg)
                    continue
                elif (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]) and any(param.lower() in argument[0].data_type or param.lower() in aliases.get(argument[0].data_type, "").lower() for param in scalable_params):
                    scalable_arg = Argument(
                        argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__")
                    current_args_dict[function].append(arg_key)
                    pre_processed_data[function].arguments.setdefault(
                        arg_key, []).append(scalable_arg)
                    continue

    return pre_processed_data


def get_generators(pre_processed_data: Dict[str, FunctionBlock],
                   generators: Dict[str, List[FunctionBlock]],
                   function_template: Dict[str, FunctionBlock],
                   aliases: Dict[str, str],
                   types: Dict[str, List[FieldInfo]]) -> Dict[str, FunctionBlock]:

    matching_generators = {}  # Dictionary to store the matching generators
    for func_name, generator_blocks in generators.items():
        for generator_block in generator_blocks:
            for argument in generator_block.arguments.values():
                # Check if argument direction is OUT
                if argument[0].arg_dir == "OUT":
                    # Look for a matching argument in function_template
                    for func_temp_name, func_temp_block in function_template.items():
                        for ft_arg_key, ft_argument in func_temp_block.arguments.items():
                            # Check if argument types match and the argument is missing from known_inputs
                            if (argument[0].arg_type == ft_argument[0].arg_type and
                                    ft_arg_key not in current_args_dict[func_temp_name] and
                                    ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                # Add a check to make sure all of the input arguments are fuzzable
                                all_fuzzable = True
                                for ft_arg_key, ft_argument in func_temp_block.arguments.items():
                                    if ft_argument[0].arg_dir == "IN" and ft_arg_key not in current_args_dict[func_temp_name]:
                                        if not is_fuzzable(remove_ref_symbols(ft_argument[0].arg_type), aliases, types, 0):
                                            all_fuzzable = False
                                            break
                                # If matching generator is found, add it to the matching_generators dictionary
                                if all_fuzzable:
                                    matching_generators.setdefault(
                                        func_temp_name, []).append(func_name)
                                    generator_arg = Argument(
                                        ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__")
                                    # current_args_dict[func_temp_name].append(ft_arg_key)
                                    pre_processed_data[func_temp_name].arguments.setdefault(
                                        ft_arg_key, []).append(generator_arg)

    return pre_processed_data


def write_to_file_output(data: Dict[str, List[FunctionBlock]], file_path: str):
    serializable_data = {}
    for function, function_blocks in data.items():
        serializable_data.setdefault(function, []).extend(
            [function_block.to_dict() for function_block in function_blocks])

    with open(file_path, 'w') as file:
        json.dump(serializable_data, file, indent=4)


def initialize_data(function_template: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    initial_data = {}
    current_args_dict.clear()
    for func, func_block in function_template.items():
        initial_data[func] = FunctionBlock(
            {}, func, func_block.service, {}, func_block.return_type)
    return initial_data

# Now add the output variables because we aren't trying to fuzz those


def add_output_variables(function_template: Dict[str, FunctionBlock],
                         pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if (argument[0].arg_dir == "OUT" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                pre_processed_data[function].arguments.setdefault(
                    arg_key, []).append(argument[0])
                current_args_dict[function].append(arg_key)

    return pre_processed_data


def collect_all_function_arguments(input_data: Dict[str, List[FunctionBlock]],
                                   function_template: Dict[str, FunctionBlock],
                                   types: Dict[str, List[FieldInfo]],
                                   input_generators: Dict[str, List[FunctionBlock]],
                                   aliases: Dict[str, str],
                                   macros: Dict[str, Macros],
                                   random: bool) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Collect all of the arguments to be passed to the template
    pre_processed_data = initialize_data(function_template)
    pre_processed_data = get_intersect(input_data, pre_processed_data)
    matched_macros = {}

    if not random:
        # Step 1: Collect the constant arguments
        pre_processed_data, matched_macros, protocol_guids, driver_guids = collect_known_constants(
            input_data, pre_processed_data, macros, aliases)
    else:
        protocol_guids = set()
        driver_guids = set()

    # Step 2: Collect the fuzzable arguments
    pre_processed_data = get_directly_fuzzable(
        input_data, pre_processed_data, aliases, random)

    if not random:
        # Step 3: collect the generator functions
        pre_processed_data = get_generators(
            pre_processed_data, input_generators, function_template, aliases, types)

    # Step 4: Collect the fuzzable structs
    pre_processed_data = variable_fuzzable(
        input_data, types, pre_processed_data, aliases, random)

    # Step 5: Add the output variables
    pre_processed_data = add_output_variables(
        function_template, pre_processed_data)

    # If there are still arguments missing then extend the level for fuzzable structs
    # continue recursively until all arguments have at least one input
    missing_arg = True
    while missing_arg:
        missing_arg = False
        for function, function_block in pre_processed_data.items():
            if len(pre_processed_data[function].arguments) < len(function_template[function].arguments):
                pre_processed_data = variable_fuzzable(
                    input_data, types, pre_processed_data, aliases, random)
                missing_arg = True

    # Step 6: add the includes for constants/macro definitions
    for function, function_block in pre_processed_data.items():
        for arg_key, arguments in function_block.arguments.items():
            for arg in arguments:
                if arg.assignment in macros.keys():
                    function_block.includes.append(macros[arg.assignment].file)
                elif arg.usage in macros.keys():
                    function_block.includes.append(macros[arg.usage].file)

    # Step 6: Sort the arguments
    for key, function_block in pre_processed_data.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys())}
        function_block.arguments = sorted_arguments

    return pre_processed_data, matched_macros, protocol_guids, driver_guids


def initialize_generators(input_generators: Dict[str, List[FunctionBlock]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    generators = {}
    generators_template = {}
    current_args_dict.clear()
    for function, function_blocks in input_generators.items():
        if function not in generators.keys():
            generators_template[function] = function_blocks[0]
            generators[function] = FunctionBlock(
                {}, function, function_blocks[0].service, {}, function_blocks[0].return_type)
        elif generators_template[function].service == "":
            generators_template[function].service = function_blocks[0].service
            generators[function].service = function_blocks[0].service
    return generators, generators_template


def analyze_generators(input_generators: Dict[str, List[FunctionBlock]],
                       input_template: Dict[str, FunctionBlock],
                       aliases: Dict[str, str],
                       types: Dict[str, List[FieldInfo]]) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # just like for normal functions we want to determine the fuzzable arguments and fuzzable structs
    # for the generator functions
    output_template = input_template.copy()

    # Step 1: Collect the constant arguments
    # generators = collect_known_constants(generators, generators)
    generators, generators_tempalate = initialize_generators(input_generators)
    generators = get_intersect(input_generators, generators)

    # Step 2: Collect the fuzzable arguments
    generators = get_directly_fuzzable(input_generators, generators, aliases, True)

    # Step 3: Collect the fuzzable structs
    generators = variable_fuzzable(
        input_generators, types, generators, aliases, False)

    # Step 4: Add the output variables
    generators = add_output_variables(generators_tempalate, generators)

    # Step 5: Sort the arguments
    for key, function_block in generators.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys())}
        function_block.arguments = sorted_arguments

    # Step 6: remove the generators that are missing arguments from both
    # the input_generators and the generators_template
    incomplete_generators = []
    for function, function_block in generators.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) == 0:
                incomplete_generators.append(function)
                break

    for function in incomplete_generators:
        del generators[function]
        del input_generators[function]
        del generators_tempalate[function]

    # Step 7: Combine generators template with the function template
    for function, function_block in generators_tempalate.items():
        if function not in output_template.keys():
            output_template[function] = function_block

    return input_generators, generators, output_template

def sanity_check(processed_data: Dict[str, FunctionBlock], harness_functions: Dict[str, List[str]]):
    for _, input_functions in harness_functions.items():
        for function in input_functions:
            if function not in processed_data.keys():
                print(f"WARNING: {function} was not able to be harnessed!!")



def analyze_data(macro_file: str,
                 generator_file: str,
                 input_file: str,
                 data_file: str,
                 types_file: str,
                 alias_file: str,
                 random: bool,
                 harness_folder: str,
                 best_guess: bool) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, List[FieldInfo]], List[str], Dict[str, str], Dict[str, str], set, set]:

    macros_val, macros_name = load_macros(macro_file)
    generators = load_generators(generator_file, macros_val)
    harness_functions = load_functions(input_file)
    data, function_template = load_data(
        data_file, harness_functions, macros_val, random, best_guess)
    types = load_types(types_file)
    aliases = load_aliases(alias_file)
    if not random:
        generators, processed_generators, template = analyze_generators(
            generators, function_template, aliases, types)
    else:
        processed_generators = {}
        template = function_template

    # These two are treated together because we want to use generators to handle any
    # input argument that isn't either directly fuzzable or of a known input
    # we will primarily use generators to handle the more compilicated structs
    # (i.e. more than one level of integrated structs) and the basic structs
    # that have all scalable fields will be directly generated with random input
    processed_data, matched_macros, protocol_guids, driver_guids = collect_all_function_arguments(
        data, function_template, types, generators, aliases, macros_name, random)

    # all_includes = get_union(processed_data, processed_generators)
    # all_includes = get_union(processed_data, {})
    all_includes = get_union({}, {})
    all_includes = list(set(all_includes) | default_includes)
    if not random:
        write_data(processed_generators,
                   f'{harness_folder}/processed_generators.json')
    write_data(processed_data, f'{harness_folder}/processed_data.json')

    sanity_check(processed_data, harness_functions)

    return processed_data, processed_generators, template, types, all_includes, matched_macros, aliases, protocol_guids, driver_guids
