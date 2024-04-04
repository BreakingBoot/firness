from typing import Dict, List
import argparse
import os
import uuid
from datetime import datetime
from common.types import FunctionBlock, FieldInfo
from common.utils import clean_harnesses, gen_file, compile
from data_analysis.analyze import analyze_data
import path_trace.header_template as tracer_header
import path_trace.harnesses_template as tracer_harnesses
import path_trace.main_template as tracer_main
import uefi_harness.harnesses_template as uefi_harnesses
import uefi_harness.main_template as uefi_main
import uefi_harness.inf_template as uefi_inf
import uefi_harness.headers_template as uefi_header

def generate_main_std(function_dict: Dict[str, FunctionBlock], harness_folder):
    code = tracer_main.gen_firness_main(function_dict)
    gen_file(f'{harness_folder}/FirnessMain_std.c', code)


def generate_code_std(function_dict: Dict[str, FunctionBlock],
                      data_template: Dict[str, FunctionBlock],
                      types_dict: Dict[str, List[FieldInfo]],
                      generators_dict: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      harness_folder):
    code = tracer_harnesses.harness_generator(
        data_template, function_dict, types_dict, aliases, generators_dict)
    gen_file(f'{harness_folder}/FirnessHarnesses_std.c', code)


def generate_header_std(function_dict: Dict[str, FunctionBlock],
                        all_includes: List[str],
                        types: Dict[str, List[FieldInfo]],
                        aliases: Dict[str, str],
                        harness_folder):
    code = tracer_header.harness_header(all_includes, function_dict, types, aliases)
    gen_file(f'{harness_folder}/FirnessHarnesses_std.h', code)


def generate_harness_debugger(merged_data: Dict[str, FunctionBlock],
                              template: Dict[str, FunctionBlock],
                              types: Dict[str, List[FieldInfo]],
                              all_includes: List[str],
                              generators: Dict[str, FunctionBlock],
                              aliases: Dict[str, str],
                              harness_folder: str):

    generate_main_std(merged_data, harness_folder)
    generate_code_std(merged_data, template, types, generators, aliases, harness_folder)
    generate_header_std(merged_data, all_includes, types, aliases, harness_folder)
    compile(harness_folder)

def generate_main(function_dict: Dict[str, FunctionBlock], harness_folder):
    code = uefi_main.gen_firness_main(function_dict)
    gen_file(f'{harness_folder}/FirnessMain.c', code)


def generate_code(function_dict: Dict[str, FunctionBlock],
                  data_template: Dict[str, FunctionBlock],
                  types_dict: Dict[str, List[FieldInfo]],
                  generators_dict: Dict[str, FunctionBlock],
                  aliases: Dict[str, str],
                  harness_folder,
                  enums: Dict[str, List[str]]):
    code = uefi_harnesses.harness_generator(
        data_template, function_dict, types_dict, generators_dict, aliases, enums)
    gen_file(f'{harness_folder}/FirnessHarnesses.c', code)


def generate_header(function_dict: Dict[str, FunctionBlock],
                    matched_macros: Dict[str, str],
                    harness_folder):
    code = uefi_header.harness_header(function_dict, matched_macros)
    gen_file(f'{harness_folder}/FirnessHarnesses.h', code)


def generate_inf(harness_folder: str, libraries: str, driver_guids: set = None, protocol_guids: set = None):
    code = uefi_inf.gen_firness_inf(uuid.uuid4(), driver_guids, protocol_guids, libraries)
    gen_file(f'{harness_folder}/FirnessHarnesses.inf', code)

def generate_includes(all_includes: List[str], harness_folder: str):
    code = uefi_header.harness_includes(all_includes)
    gen_file(f'{harness_folder}/FirnessIncludes.h', code)


def generate_harness(merged_data: Dict[str, FunctionBlock],
                     template: Dict[str, FunctionBlock],
                     types: Dict[str, List[FieldInfo]],
                     enums: Dict[str, List[str]],
                     all_includes: List[str],
                     libraries: List[str],
                     generators: Dict[str, FunctionBlock],
                     aliases: Dict[str, str],
                     matched_macros: Dict[str, str],
                     protocol_guids: set,
                     driver_guids: set,
                     harness_folder: str,
                     output_dir: str):

    generate_main(merged_data, harness_folder)
    generate_code(merged_data, template, types, generators, aliases, harness_folder, enums)
    generate_header(merged_data, matched_macros, harness_folder)
    generate_includes(all_includes, harness_folder)
    generate_inf(harness_folder, libraries, protocol_guids, driver_guids)
    # generate_harness_debugger(merged_data, template,
                            #   types, all_includes, generators, aliases, harness_folder)
    output_dir = os.path.join(output_dir, 'Firness')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    os.system(f'cp {harness_folder}/* {output_dir}')

def generate_harness_folder(dir: str):
    # Define the outer directory name
    outer_dir = f'{dir}/GeneratedHarnesses'

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
    os.system(f'cp /workspace/HarnessHelpers/* {full_path}')

    # Return the full path of the inner directory
    return full_path


def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('-d', '--data-file', dest='data_file', default='/output/tmp/call-database.json',
                        help='Path to the data file (default: /output/tmp/call-database.json)')
    parser.add_argument('-g', '--generator-file', dest='generator_file', default='/output/tmp/generator-database.json',
                        help='Path to the generator file (default: /output/tmp/generator-database.json)')
    parser.add_argument('-t', '--types-file', dest='types_file', default='/output/tmp/types.json',
                        help='Path to the types file (default: /output/tmp/types.json)')
    parser.add_argument('-a', '--alias-file', dest='alias_file', default='/output/tmp/aliases.json',
                        help='Path to the typedef aliases file (default: /output/tmp/aliases.json)')
    parser.add_argument('-m', '--macro-file', dest='macro_file', default='/output/tmp/macros.json',
                        help='Path to the macros file (default: /output/tmp/macros.json)')
    parser.add_argument('-e', '--enum-file', dest='enum_file', default='/output/tmp/enums.json',
                        help='Path to the enums file (default: /output/tmp/enums.json)')
    parser.add_argument('-i', '--input-file', dest='input_file',
                        default='/input/input.txt', help='Path to the input file (default: /input/input.txt)')
    parser.add_argument('-f', '--function-file', dest='function_file',
                        default='/output/tmp/functions.json', help='Path to the function file (default: /output/tmp/functions.json)')
    parser.add_argument('-o', '--output', dest='output',
                        default='/output', help='Path to the output directory (default: /output)')
    parser.add_argument('-c', '--clean', dest='clean', action='store_true',
                        help='Clean the generator database (default: False)')
    parser.add_argument('-r', '--random', dest='random', action='store_true',
                        help='Use random input instead of structured input data (default: False)')
    parser.add_argument('-b', '--best-guess', dest='best_guess', action='store_true',
                        help='Choose the function match with the highest frequency even if it might not be the right one (default: False)')

    args = parser.parse_args()

    clean_harnesses(args.clean, args.output)
    harness_folder = generate_harness_folder(args.output)
    processed_data, processed_generators, template, types, all_includes, libraries, matched_macros, aliases, protocol_guids, driver_guids, enums = analyze_data(args.macro_file, args.enum_file, args.generator_file, args.input_file,
                                                  args.data_file, args.types_file, args.alias_file, args.random, harness_folder, args.best_guess, args.function_file)
    generate_harness(processed_data, template, types, enums,
                     all_includes, libraries, processed_generators, aliases, matched_macros, protocol_guids, driver_guids, harness_folder, args.output)


if __name__ == '__main__':
    main()