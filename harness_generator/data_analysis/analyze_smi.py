import json
import os
import copy
import re
from fuzzywuzzy import fuzz
import math
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Set
from common.types import FunctionBlock, FieldInfo, TypeInfo, EnumDef, Function, Argument, Macros, scalable_params, services_map, type_defs, known_contant_variables, ignore_constant_keywords, default_includes, default_libraries, SmiInfo
from common.utils import remove_ref_symbols, write_data, get_union, is_whitespace, contains_void_star, contains_usage, get_stripped_usage, is_fuzzable, get_intersect, print_function_block
from common.generate_library_map import generate_libmap

smi_includes = {
    "Protocol/MmCommunication.h",
    "Protocol/SmmCommunication.h",
    "Guid/PiSmmCommunicationRegionTable.h"
}

all_includes = set()

def load_include_deps(json_file: str) -> Dict[str, List[str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)
        include_dict = defaultdict(list)
        for raw_include in raw_data:
            include_dict[raw_include["File"]] = raw_include["Includes"][::-1]
        return include_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

def load_libmap(edk2_dir: str, output_file: str) -> Dict[str, Dict[str, list]]:
    try:
        return generate_libmap(edk2_dir, output_file)
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

def load_aliases(json_file: str) -> Dict[str, str]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    return raw_data

#
# Load enums
#
def load_enums(json_file: str) -> Dict[str, EnumDef]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    enum_dict = defaultdict(list)
    for enum in raw_data:
        enum_def = EnumDef(enum["Name"], enum["Values"], enum["File"])
        enum_dict[enum["Name"]] = enum_def
    return enum_dict

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
def load_types(json_file: str) -> Dict[str, TypeInfo]:
    with open(json_file, 'r') as file:
        data = json.load(file)
    type_data_list = defaultdict(list)
    for type_data_dict in data:
        fields_list = []
        for field_dict in type_data_dict['Fields']:
            field_info = FieldInfo(field_dict['Name'], field_dict['Type'])
            fields_list.append(field_info)
        type_data_list[type_data_dict['TypeName']] = TypeInfo(type_data_dict['TypeName'], fields_list, type_data_dict['File'])
    return type_data_list

#
# load in the castings
#
def load_castings(json_file: str) -> Dict[str, List[str]]:
    try:
        with open(json_file, 'r') as file:
            raw_data = json.load(file)
        casting_dict = defaultdict(list)
        for raw_casting in raw_data:
            # if the type isn't a scalar, then add it to the casting_dict
            if not any(param.lower() in raw_casting["Type"].lower() for param in scalable_params):
                casts = raw_casting["Casts"]
                for cast in casts:
                    # if the cast isn't a scalar, then add it to the casting_dict
                    if not any(param.lower() in cast.lower() for param in scalable_params):
                        casting_dict[raw_casting["Type"]].append(cast)
        return casting_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

def load_smi_data(smi_file: str,
                    types: Dict[str, TypeInfo]) -> Dict[str, SmiInfo]:
    with open(smi_file, 'r') as file:
        raw_data = json.load(file)
    smi_data = {}
    for smi, data in raw_data.items():
        smi_info = SmiInfo(smi, data["Type"], data["Guid"])
        smi_data[smi] = smi_info
        if remove_ref_symbols(smi_info.type) in types.keys():
            all_includes.add(types[remove_ref_symbols(smi_info.type)].file)
    return smi_data

def cleanup_paths(includes):
    modified_includes = []
    for include in includes:
        if include.endswith(".c"):
            continue
        # Split the path into its components.
        components = include.split("/")
        # Remove the first 3 components.
        include = "/".join(components[-2:])
        if len(components) > 4 and "edk2-platforms" not in components[3].lower():
            if len(include.split("/")) == 2 and "include" in components[-3].lower():
                modified_includes.append(include)
            else:
                include = "/".join(components[-3:])
                modified_includes.append(include)
    return modified_includes

def update_inc(includes: List[str], libmap: Dict[str, Dict[str, list]]) -> List[str]:
    for include in includes:
        match = False
        if "library" in include.lower():
            for lib in libmap.keys():
                if lib in include:
                    match = True
            if not match and include not in default_includes or include not in smi_includes:
                includes.remove(include)
        if "ppi" in include.lower():
            includes.remove(include)
    return includes

def collect_all_lib_deps(libmap: Dict[str, Dict[str, List[str]]], lib: str, collected_deps: Set[str]) -> Set[str]:
    # Add the current library to the set of collected dependencies
    collected_deps.add(lib)
    
    # Iterate over the dependencies of the current library
    if lib in libmap.keys():
        for dep in libmap[lib]["dependencies"]:
            # If the dependency is not yet collected, recursively collect its dependencies
            if dep not in collected_deps:
                collect_all_lib_deps(libmap, dep, collected_deps)
    
    return collected_deps

def collect_all_deps_from_libmap(libraries: List[str], libmap: Dict[str, Dict[str, List[str]]]) -> Set[str]:
    all_libs = set()
    
    # Iterate through each library and collect all of its dependencies recursively
    for lib in libraries:
        for libdef in libmap.keys():
            if lib in libdef:
                all_libs.add(libdef)
                all_libs = collect_all_lib_deps(libmap, libdef, all_libs)
    
    return all_libs


# Function to perform topological sort on the graph
def topological_sort(graph: Dict[str, List[str]]):
    visited = set()
    temp_mark = set()
    sorted_files = []

    def visit(node):
        if node in visited:
            return
        if node in temp_mark:
            return

        temp_mark.add(node)

        for dep in graph.get(node, []):
            visit(dep)

        temp_mark.remove(node)
        visited.add(node)
        sorted_files.append(node)

    for node in graph:
        if node not in visited:
            visit(node)

    return sorted_files[::-1]

def cleanup_include_dep_paths(include_deps: Dict[str, List[str]]):
    modified_includes = dict()
    for include, deps in include_deps.items():
        if include.endswith(".c"):
            continue
        # Split the path into its components.
        components = include.split("/")
        # Remove the first 3 components.
        include = "/".join(components[-2:])
        if len(components) > 4 and "edk2-platforms" not in components[3].lower():
            if len(include.split("/")) == 2 and "include" in components[-3].lower():
                modified_includes[include] = cleanup_paths(deps)
            else:
                include = "/".join(components[-3:])
                modified_includes[include] = cleanup_paths(deps)

    return modified_includes

# Function to ensure all dependencies are resolved in the correct order
def handle_include_deps(includes: List[str], include_deps: Dict[str, List[str]]) -> List[str]:
    # Cleanup the paths in the include dependencies
    include_deps = cleanup_include_dep_paths(include_deps)

    sorted_graph = topological_sort(include_deps)
    
    # Set to store files that are already included
    included = set()

    # Final ordered list of includes
    ordered_includes = []

    for file in sorted_graph:
        if file in includes and file not in included:
            ordered_includes.append(file)
            included.add(file)
    for file in includes:
        if file not in ordered_includes and file not in included:
            ordered_includes.append(file)
            included.add(file)
    # reverse the list to ensure that the includes are in the correct order
    ordered_includes.reverse()
    mem_alloc = False
    for include in ordered_includes:
        if "MemoryAllocationLib" in include:
            mem_alloc = True
    if not mem_alloc:
        # Add the MemoryAllocationLib right after BaseLib include
        ordered_includes.insert(1, "Library/MemoryAllocationLib.h")
    return ordered_includes


def update_libs(libraries: List[str], libmap: Dict[str, Dict[str, list]]) -> Dict[str, str]:
    updated_libs = {}
    tmp_libs = collect_all_deps_from_libmap(libraries, libmap)
    for lib in tmp_libs:
        if lib in libmap.keys():
            updated_libs[lib] = libmap[lib]["path"]
    remove_libs = []
    for lib in updated_libs.keys():
        if "unittest" in lib.lower():
            remove_libs.append(lib)

    for lib in remove_libs:
        del updated_libs[lib]

    return updated_libs

def collect_libraries(includes: List[str]) -> set[str]:
    libraries = set()
    for include in includes:
        lib = include.split("/")[-1]
        lib = lib[:-2]
        if 'Lib' in lib:
            libraries.add(lib)

    return libraries

def natural_sort_key(key):
    # Split key into a list of strings and integers
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', key)]


def analyze_smi(smi_data: Dict[str, SmiInfo],
                macros_val: Dict[str, Macros],
                macros_name: Dict[str, Macros],
                enum_map: Dict[str, EnumDef],
                cast_map: Dict[str, List[str]],
                types: Dict[str, TypeInfo],
                aliases: Dict[str, str],
                include_deps: Dict[str, List[str]]) -> Dict[str, FunctionBlock]:
    protocol_guids = set()
    driver_guids = set()
    for smi in smi_data.values():
        # Perform analysis on each SMI
        if "protocol" in smi.guid.lower():
            protocol_guids.add(smi.guid)
        elif smi.guid:
            driver_guids.add(smi.guid)
    driver_guids.add("gEdkiiPiSmmCommunicationRegionTableGuid")
    protocol_guids.add('gEfiSmmCommunicationProtocolGuid')
    return smi_data, protocol_guids, driver_guids

priority_order = {"Library": 0, "Protocol": 1, "Guid": 2}

def sort_key(path):
    first_part = path.split("/")[0]
    priority = priority_order.get(first_part, 3)  # 3 = default lowest priority
    return (priority, natural_sort_key(path))

def analyze_smi_data(macro_file: str,
                    enum_file: str,
                    smi_file: str,
                    types_file: str,
                    alias_file: str,
                    cast_file: str,
                    random: bool,
                    harness_folder: str,
                    best_guess: bool,
                    edk2_dir: str,
                    include_deps_file: str):
    

    macros_val, macros_name = load_macros(macro_file)
    cast_map = load_castings(cast_file)
    enum_map = load_enums(enum_file)
    libmap = load_libmap(edk2_dir, os.path.join('/'.join(smi_file.split("/")[:-1]), 'libmap.json'))
    types = load_types(types_file)
    smi_data = load_smi_data(smi_file, types)
    include_deps = load_include_deps(include_deps_file)
    aliases = load_aliases(alias_file)

    # Analyze the SMI data
    analyzed_data, protocol_guids, driver_guids = analyze_smi(smi_data, macros_val, macros_name, enum_map, cast_map, types, aliases, include_deps)

    update_includes = cleanup_paths(all_includes)
    # all_includes = get_union(processed_data, {})
    # all_includes = get_union({}, {})
    collected_includes = list(set(update_includes))
    # collected_includes = update_inc(collected_includes, libmap)
    libraries = update_libs(list(collect_libraries(collected_includes) | default_libraries), libmap)
    collected_includes = list(set(handle_include_deps(collected_includes, include_deps)) | smi_includes | default_includes)
    # sort includes based off of the first word in the path: Library, Protocol, Guid
    collected_includes.sort(key=sort_key)


    return analyzed_data, collected_includes, libraries, types, enum_map, aliases, protocol_guids, driver_guids, {}