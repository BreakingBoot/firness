import argparse
import json
import os
from typing import Dict

def parse_inf_file(file_path):
    libclasses = set()
    with open(file_path, 'r') as file:
        inside_library_classes = False
        for line in file:
            # Check if we are inside the [LibraryClasses] section
            if 'LibraryClasses' in line:
                inside_library_classes = True
                continue  # Skip the [LibraryClasses] line itself

            # Stop if another section starts
            if inside_library_classes and (line.startswith('[') or line.startswith('<')):
                break

            # If inside [LibraryClasses] and not an empty line, split by '|'
            if inside_library_classes and line.strip():
                # Split the line based on '|'
                if not line.strip().startswith('#'):
                    libclasses.add(line.strip())
    return list(libclasses)

def is_uefi_app_lib(lib_name):
    if os.path.exists(lib_name) and os.path.isfile(lib_name):
        with open(lib_name, 'r') as file:
            for line in file:
                if 'LIBRARY_CLASS' in line and "|" not in line:
                    return True
                elif 'LIBRARY_CLASS' in line and 'UEFI_APPLICATION' in line:
                    return True
    return False

# return the LIBRARY_CLASS an .inf actually provides, or None. a DSC line reads
# <Class>|<path/to/Instance.inf>, but the left-hand side is not always a real class --
# RedfishPkg/RedfishLibs.dsc.inc says BaseSortLib|.../BaseSortLib.inf even though that
# .inf declares LIBRARY_CLASS = SortLib. harvesting it verbatim puts two instances of
# the same class in the generated DSC and the harness fails to link
def declared_library_class(inf_path):
    if not (os.path.exists(inf_path) and os.path.isfile(inf_path)):
        return None
    with open(inf_path, 'r', errors='ignore') as file:
        for line in file:
            line = line.split('#')[0].strip()
            if line.startswith('LIBRARY_CLASS') and '=' in line:
                value = line.split('=', 1)[1].strip()
                return value.split('|')[0].strip() or None
    return None


def parse_library_classes_section(file_path: str, root: str, lib_map: Dict[str, Dict[str, list]]) -> Dict[str, Dict[str, list]]:
    with open(file_path, 'r') as file:
        inside_library_classes = False
        for line in file:
            # Check if we are inside the [LibraryClasses] section
            if 'LibraryClasses' in line:
                inside_library_classes = True
                continue  # Skip the [LibraryClasses] line itself

            # Stop if another section starts
            if inside_library_classes and (line.startswith('[') or line.startswith('<')):
                break

            # If inside [LibraryClasses] and not an empty line, split by '|'
            if inside_library_classes and line.strip():
                # Split the line based on '|'
                parts = line.split('|')
                if len(parts) > 1 and not line.strip().startswith('#'):
                    # Remove extra spaces from each part
                    parts = [part.strip() for part in parts]
                    inf_path = os.path.join(root, parts[1])
                    if "pei" in parts[1].lower() or not is_uefi_app_lib(inf_path):
                        continue
                    # Only trust the DSC's left-hand side if the instance really
                    # provides that class; otherwise a DSC typo becomes a duplicate
                    # library class in the generated harness DSC.
                    provided = declared_library_class(inf_path)
                    if provided is not None and provided != parts[0]:
                        continue
                    # First writer wins. Which DSC that turns out to be is an
                    # os.walk ordering accident, so any class the harness genuinely
                    # depends on is pinned in uefi_harness/dsc_template.py rather
                    # than left to this lottery.
                    if parts[0] in lib_map:
                        continue
                    lib_map[parts[0]] = {"path": parts[1], "dependencies": parse_inf_file(inf_path)}
    return lib_map

def parse_edk2(folder_path: str) -> Dict[str, Dict[str, list]]:
    libmap = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.dsc') or file.endswith('.inc'):
                libmap.update(parse_library_classes_section(os.path.join(root, file), folder_path, libmap))
    return libmap

def clean_libmap(lib_map: dict) -> dict:
    # Remove any library that has dependencies that are not in the library map
    for lib in list(lib_map.keys()):
        for dep in lib_map[lib]["dependencies"]:
            if dep not in lib_map.keys():
                print(f"Removing {lib} because it depends on {dep} which is not in the library map")
                del lib_map[lib]
                break
    return lib_map

def save_libmap_json(file_path: str, lib_map: dict):
    with open(file_path, 'w') as file:
        json.dump(lib_map, file, indent=4)


def generate_libmap(edk2_path: str, output_file: str) -> Dict[str, Dict[str, list]]:
    lib_map = parse_edk2(edk2_path)
    lib_map = clean_libmap(lib_map)
    print(len(lib_map), "libraries found")
    save_libmap_json(output_file, lib_map)
    return lib_map

