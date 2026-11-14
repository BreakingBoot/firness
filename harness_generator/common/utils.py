import re
import os
import json
from itertools import permutations
from typing import List, Dict, Set
from common.types import FunctionBlock, FieldInfo, Macros, TypeInfo, scalable_params, type_defs

def is_whitespace(s: str) -> bool:
    if s is None:
        return True
    return len(s.strip()) == 0

def remove_ref_symbols(type_str: str) -> str:
    return re.sub(r" *\*| *&", "", type_str)


# The call site records a type in whatever spelling the expression had, so a wide string
# literal reaches the analysis as "unsigned short *" rather than "CHAR16 *". type_defs maps
# the EDK2 name to that raw spelling and reading it backwards recovers the name -- but two
# of its entries share a spelling, "unsigned short" for both UINT16 and CHAR16 and
# "unsigned char" for both BOOLEAN and UINT8, so the reverse of it is a choice and not a
# lookup. These are the names that win when nothing better is known; they are the ones a
# plain loop over type_defs settles on today, so a lookup with nothing to disambiguate it
# keeps answering what it answered before.
AMBIGUOUS_TYPEDEF_PREFERENCE = ('UINT16', 'BOOLEAN')

# What the analyser records in data_type when the pointee really is a character, which is
# the one thing that separates CHAR16 from UINT16 at a call site with no declaration.
CHARACTER_DATA_TYPES = {
    'wchar_t': 'CHAR16',
    'char': 'CHAR8',
}

# Suffixes of a parameter that names an address on a BUS rather than an index into the
# caller's own memory.
#
# The blanket arm in harnesses_template reads "this call takes a raw buffer, so its
# integer arguments are the sizes and offsets into it". That is true of a size and of an
# offset and it is not true of an address: EFI_CPU_IO2_PROTOCOL.Read takes
# (This, Width, Address, Count, Buffer), and bounding Address by the size of Buffer put
# every access into 0x0000-0x1000 -- which, through the Io arm of that protocol, is the
# legacy I/O page: the PIC at 0x20/0xA0, the PIT at 0x40-0x43, CMOS/RTC at 0x70/0x71 and
# the keyboard controller at 0x60/0x64. The EfiCpuIo2 campaign of sweep 43454245046
# managed 111 iterations of an 1800s budget, 0.065 exec/s, and reported nothing for its
# last 27 minutes: it had wedged the guest it was fuzzing.
#
# "No bound" is what the generator already does with this same parameter everywhere else.
# Across the 142 cached campaigns of runs 43454245046 and 43452927684 there are 62
# address-named argument positions and only six carried the buffer bound -- Read and Write
# of EFI_CPU_IO2_PROTOCOL, EFI_MM_CPU_IO_PROTOCOL and EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL, the
# three raw-bus accessors. EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.PollMem and .PollIo take the
# same UINT64 Address, do not carry a raw buffer beside it, were never bounded, and that
# campaign ran 2830 iterations: the unbounded form is the one with the evidence behind it.
#
# Shared with analyze.py, which asks the same question of a recorded constant, so it lives
# here rather than beside DIMENSION_NAME_SUFFIXES in the template -- an address table in
# the template would make the analysis import the harness writer.
ADDRESS_NAME_SUFFIXES = ('ADDRESS', 'ADDR')


def is_address_name(name: str) -> bool:
    """Whether this parameter names a bus address rather than a size or an offset."""
    if not name:
        return False
    return name.strip().upper().endswith(ADDRESS_NAME_SUFFIXES)


def edk2_typedef_for(raw_type: str, declared_type: str = "", data_type: str = "") -> str:
    """The EDK2 name for a type the analyser recorded in raw C, or "" for anything else.

    declared_type is the parameter's own spelling from its declaration and settles it
    outright, because that is the name the callee was written with. Without one, a
    recorded data_type of "wchar_t *" says the pointee is a character and chooses CHAR16
    over UINT16. The answer is the same whatever order type_defs is built in: the
    candidates are sorted and the tie is broken by name, not by iteration.

    Only the name is returned. The declarator belongs to the caller, because dropping it
    is what turned "unsigned short *" into UINT16 and fuzzed a CHAR16 * by value.
    """
    base = remove_ref_symbols(raw_type or '').replace('const ', '').strip()
    candidates = sorted(name for name, spelling in type_defs.items() if spelling == base)
    if not candidates:
        return ""
    if len(candidates) == 1:
        return candidates[0]
    declared = remove_ref_symbols(declared_type or '').replace('const ', '').strip()
    if declared in candidates:
        return declared
    character = CHARACTER_DATA_TYPES.get(
        remove_ref_symbols(data_type or '').replace('const ', '').strip())
    if character in candidates:
        return character
    for preferred in AMBIGUOUS_TYPEDEF_PREFERENCE:
        if preferred in candidates:
            return preferred
    return candidates[0]

def remove_prefix(type: str) -> str:
    return remove_ref_symbols(remove_casts(type))

def remove_quotes(string: str) -> str:
    if string is None:
        return None
    
    return string.replace("\"", "")

def clean_harnesses(clean: bool, dir: str) -> None:
    if clean:
        os.system(f'rm -rf {dir}/GeneratedHarnesses')

def write_sorted_data(sorted_data: Dict[str, Dict[int, List[FunctionBlock]]], filename: str) -> None:
    output_dict = {
        function: {
            arg_num: [function_block.to_dict()
                      for function_block in function_blocks]
            for arg_num, function_blocks in arg_num_pairs.items()
        }
        for function, arg_num_pairs in sorted_data.items()
    }

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

# write the template to a file
def write_template(template: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = {
        function: function_block.to_dict()
        for function, function_block in template.items()
    }

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

def add_indents(output: List[str], indent: bool) -> List[str]:
    if not indent:
        return output
    
    indented_output = []
    for line in output:
        indented_output.append(f"    {line}")
    return indented_output

def gen_file(filename: str, output: List[str]):
    with open(filename, 'w') as f:
        f.writelines([line + '\n' for line in output])

def write_data(filtered_args_dict: Dict[str, FunctionBlock], filename: str) -> None:
    output_dict = [function_block.to_dict()
                   for function_block in filtered_args_dict.values()]

    with open(filename, 'w') as f:
        json.dump(output_dict, f, indent=4)

def compile(harness_folder: str):
    os.system(f'clang -w -g -o {harness_folder}/firness_decoder {harness_folder}/FirnessMain_std.c {harness_folder}/FirnessHarnesses_std.c')

#
# This function will ignore the cast statements in the argument usage
#
def ignore_cast(usage: str) -> str:
    return re.sub(r"\(.*?\)", "", usage)

def remove_casts(input_string: str, 
                 aliases: Dict[str, str]) -> str:
    # Define a regular expression pattern to match casts within parentheses
    pattern = r'\(([^()]+)\)'

    # Define a function to replace matched casts with their content
    def replace_cast(match):
        cast_contents = match.group(1)
        check_list = scalable_params
        check_list.extend([alias.lower() for alias in aliases.keys()])
        contains_cast = any(cast in cast_contents.lower() for cast in check_list)
        if contains_cast:
            return ''
        if ' ' in cast_contents:
            return cast_contents
        return ''

    # Use re.sub() to replace the matched casts with their content
    result = re.sub(pattern, replace_cast, input_string)

    # Remove any remaining parentheses
    result = result.replace('(', '').replace(')', '')

    return result

#
# This function will return a set of all of the stripped usage values
# only handles conditional statements taht are separated by a pipe
#
def get_stripped_usage(usage: str, 
                       macros: Dict[str, Macros],
                       aliases: Dict[str, str]) -> Set[str]:
    usages = set()

    tmp = []
    for usage_value in usage.split("|"):
        tmp.append(remove_casts(usage_value.strip(), aliases))
    # loop through the tmp list and add all of the orderings of the values
    # example: if the usage is "a|b|c" then add "a|b|c", "b|a|c", "c|a|b", etc.
    permutations_list = list(permutations(tmp))

    # Convert each permutation tuple back to a list of strings
    ordered_strings = ['|'.join(perm) for perm in permutations_list]

    # Add all permutations mixed with the macro values to the set
    # Add the macro values to the set, incase the macro value is used in the conditional
    # EDK2 tends to redefine the same macro value in different files
    for permutation in permutations_list:
        permutation = list(permutation)
        for index, element in enumerate(permutation):
            if element in macros.keys():
                permutation[index] = re.sub(r'\s', '', remove_casts(macros[element].value, aliases))
                ordered_strings.append('|'.join(permutation))
    # Convert the list to a set
    usages.update(set(ordered_strings))

    return usages

def contains_usage(usage: str, 
                   current_usages: Set[str],
                   macros: Dict[str, Macros], 
                   aliases: Dict[str, str]) -> bool:
    usages = get_stripped_usage(remove_casts(usage, aliases), macros, aliases)
    for use in usages:
        if use in current_usages:
            return True
    return False

def contains_void_star(s):
    s_no_spaces = s.replace(" ", "").lower()
    return "void*" in s_no_spaces

# def contains_void_star(s: str,
#                        aliases: Dict[str, str]):
#     s_no_spaces = s.replace(" ", "").lower()
#     return "void*" in s_no_spaces or "void*" in aliases.get(remove_ref_symbols(s), "").replace(" ", "").lower()

def is_fuzzable(type: str,
                aliases: Dict[str, str],
                typemap: Dict[str, TypeInfo],
                level: int) -> bool:
    if level > 2:
        return False
    elif any(param.lower() in type.lower() for param in scalable_params):
        return True  # If the type is a scalar, then it is fuzzable
    elif type in aliases.keys():
        # If the type is an alias, then check the alias
        return is_fuzzable(aliases[type], aliases, typemap, level)
    elif type in typemap.keys():
        fuzzable = False
        for field_info in typemap[type].fields:
            # If any of the fields are scalars, then the type is fuzzable
            # one level deep
            if is_fuzzable(field_info.type, aliases, typemap, level + 1):
                fuzzable = True
            else:
                fuzzable = False
                break
        return fuzzable

    return False

def print_function_block(function_block: FunctionBlock) -> None:
    print('----------------------------------------------')
    print('Function Block:')
    print(f'\tService: {function_block.service}')
    print(f'\tFunction: {function_block.function}')
    print(f'\tReturn Type: {function_block.return_type}')
    for arg_num, arg_list in function_block.arguments.items():
        print(f'\t{arg_num}: ')
        for arg in arg_list:
            print(f'\t\tArg Dir: {arg.arg_dir}')
            print(f'\t\tArg Type: {arg.arg_type}')
            print(f'\t\tAssignment: {arg.assignment}')
            print(f'\t\tData Type: {arg.data_type}')
            print(f'\t\tUsage: {arg.usage}')
            print(f'\t\tPointer Count: {arg.pointer_count}')
            print(f'\t\tPotential Values: {arg.potential_outputs}')
            print(f'\t\tVariable: {arg.variable}')
    print('----------------------------------------------')

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
                pre_processed_data[function].includes = list(
                    set(pre_processed_data[function].includes) & set(function_block.includes))
    return pre_processed_data


#
# Get the union between all of the includes between all functions
#
def get_union(pre_processed_data: Dict[str, FunctionBlock],
              processed_generators: Dict[str, FunctionBlock]) -> List[str]:
    # sorted, not list: a set of strings iterates in a different order every run, and this
    # union feeds the harness include list
    union = []
    for function, function_block in pre_processed_data.items():
        if function_block.includes is not None:
            union = sorted(set(union) | set(function_block.includes))
    for function, function_block in processed_generators.items():
        if function_block.includes is not None:
            union = sorted(set(union) | set(function_block.includes))
    return union