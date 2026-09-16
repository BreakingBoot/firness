from typing import Dict, List
import argparse
import os
import re
import uuid
import json
from datetime import datetime
from common.types import FunctionBlock, FieldInfo, EnumDef, scalable_params, SmiInfo
from common.utils import clean_harnesses, gen_file, compile
from data_analysis.analyze import analyze_data
from linux_harness import guid_values as linux_guid_values
from linux_harness import smi_driver_template as linux_smi_driver
from data_analysis.analyze_smi import analyze_smi_data
import path_trace.header_template as tracer_header
import path_trace.harnesses_template as tracer_harnesses
import path_trace.main_template as tracer_main
import uefi_harness.harnesses_template as uefi_harnesses
import uefi_harness.main_template as uefi_main
import uefi_harness.inf_template as uefi_inf
import uefi_harness.dsc_template as uefi_dsc
import uefi_harness.headers_template as uefi_header
import uefi_harness.smi_harness_template as uefi_smi_harness

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

def generate_main(function_dict: Dict[str, FunctionBlock], harness_folder, max_steps: int = 8, precedence=()):
    code = uefi_main.gen_firness_main(function_dict, max_steps, precedence)
    gen_file(f'{harness_folder}/FirnessMain.c', code)


def generate_code(function_dict: Dict[str, FunctionBlock],
                  data_template: Dict[str, FunctionBlock],
                  types_dict: Dict[str, List[FieldInfo]],
                  generators_dict: Dict[str, FunctionBlock],
                  aliases: Dict[str, str],
                  harness_folder,
                  enums: Dict[str, List[str]],
                  random: bool = False):
    code = uefi_harnesses.harness_generator(
        data_template, function_dict, types_dict, generators_dict, aliases, enums, random)
    gen_file(f'{harness_folder}/FirnessHarnesses.c', code)

def generate_smi_code(function_dict: Dict[str, SmiInfo],
                  types_dict: Dict[str, List[FieldInfo]],
                  aliases: Dict[str, str],
                  harness_folder,
                  enums: Dict[str, List[str]],
                  random: bool = False):
    code = uefi_smi_harness.harness_generator(
        function_dict, types_dict, aliases, enums, random)
    gen_file(f'{harness_folder}/FirnessHarnesses.c', code)

def generate_header(function_dict: Dict[str, FunctionBlock],
                    matched_macros: Dict[str, str],
                    harness_folder,
                    guids=()):
    code = uefi_header.harness_header(function_dict, matched_macros, guids)
    gen_file(f'{harness_folder}/FirnessHarnesses.h', code)


# Libraries the harness needs whether or not it names them: the entry point, the tables
# the generated code dereferences, and the ones edk2 pulls in for any UEFI application.
CORE_LIBRARIES = {
    'UefiApplicationEntryPoint', 'UefiBootServicesTableLib', 'UefiRuntimeServicesTableLib',
    'UefiLib', 'BaseLib', 'BaseMemoryLib', 'MemoryAllocationLib', 'DebugLib', 'PrintLib',
    'PcdLib', 'DevicePathLib', 'UefiDriverEntryPoint', 'RegisterFilterLib',
    'StackCheckLib', 'StackCheckFailureHookLib',
}


def used_libraries(libraries, harness_folder, all_includes, edk2_dir=""):
    """Only the libraries the harness actually calls into.

    The library map is every class the platform declares, and listing all of them in the
    INF links all of them. An unused library still runs its constructor when the image
    loads, and a constructor that expects state the harness never set up faults there:
    PiDxeS3BootScriptLib alone accounted for 545 fuzz-phase reports on the Simics matrix,
    all attributed to Firness.efi, in a library nothing in the harness calls. Those are
    not firmware bugs and they crowd out the ones that are.

    Membership is decided by what the generated C calls, not by what it includes. The
    include list is a superset by construction -- that is why headers this edk2 does not
    have are dropped from it -- so "the harness includes S3BootScriptLib.h" says nothing
    about whether it ever calls S3BootScriptSaveIoWrite. Read each candidate's header,
    take the function names it declares, and keep the class only if the emitted sources
    name one of them.

    A class with no header to read is kept: unable to tell is not the same as unused, and
    the cost of keeping one is a constructor, while the cost of dropping one is a harness
    that does not link.
    """
    text = ''
    for name in ('FirnessHarnesses.c', 'FirnessMain.c', 'FirnessHelpers.c'):
        path = os.path.join(harness_folder, name)
        if os.path.isfile(path):
            text += open(path, errors='ignore').read()
    called = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', text))

    roots = [edk2_dir] if edk2_dir else []
    sibling = os.path.join(os.path.dirname(os.path.abspath(edk2_dir)), 'edk2-platforms') \
        if edk2_dir else ''
    if sibling and os.path.isdir(sibling):
        roots.append(sibling)
    headers = {}
    for root in roots:
        for base, _, files in os.walk(root):
            if os.sep + 'Build' + os.sep in base + os.sep:
                continue
            if os.path.basename(base) != 'Library':
                continue
            for name in files:
                if name.endswith('.h'):
                    headers.setdefault(name[:-2], os.path.join(base, name))

    kept, dropped = {}, []
    for cls, path in libraries.items():
        if cls == 'NULL' or cls in CORE_LIBRARIES or cls in called:
            kept[cls] = path
            continue
        header = headers.get(cls)
        if header is None:
            kept[cls] = path
            continue
        try:
            decl = open(header, errors='ignore').read()
        except OSError:
            kept[cls] = path
            continue
        exported = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', decl))
        if exported & called:
            kept[cls] = path
        else:
            dropped.append(cls)
    if dropped:
        print(f'INFO: not linking {len(dropped)} librar(ies) the harness never calls: '
              f'{", ".join(sorted(dropped))}')
    return kept


def generate_inf(harness_folder: str, libraries: Dict[str, str], driver_guids: set = None,
                 protocol_guids: set = None, all_includes: List[str] = None,
                 edk2_dir: str = ""):
    packages = packages_for_includes(all_includes or [], edk2_dir)
    priority = preferred_packages(all_includes or [], harness_folder, edk2_dir)
    code = uefi_inf.gen_firness_inf(uuid.uuid4(), driver_guids, protocol_guids, libraries,
                                    packages, priority)
    gen_file(f'{harness_folder}/FirnessHarnesses.inf', code)

# the spellings accepted on the command line, mapped to the FIRNESS_BACKEND values that
# HarnessHelpers/FirnessBackend.h compiles against
BACKENDS = {'tsffs': 1, 'qemu': 2, 'libafl_qemu': 2, 'nyx': 3, 'none': 4}


def generate_dsc(harness_folder: str, libraries: Dict[str, str], backend: int = 1):
    code = uefi_dsc.gen_firness_dsc(libraries, backend)
    gen_file(f'{harness_folder}/Firness.dsc', code)

_HEADER_INDEX = {}


def _header_index(edk2_dir: str):
    """Every header in the tree, and the package each one belongs to.

    Walked once per tree: both the "does this edk2 have it" check and the package list
    the harness inf declares are answers about the same set of files.
    """
    key = os.path.abspath(edk2_dir)
    if key in _HEADER_INDEX:
        return _HEADER_INDEX[key]
    roots = [edk2_dir]
    sibling = os.path.join(os.path.dirname(key), 'edk2-platforms')
    if os.path.isdir(sibling):
        roots.append(sibling)
    index, owner = set(), {}
    for root in roots:
        for base, _, files in os.walk(root):
            if os.sep + 'Build' + os.sep in base + os.sep:
                continue
            rel = os.path.relpath(base, root).split(os.sep)
            package = rel[0] if rel and rel[0] not in ('.', '..') else ''
            for name in files:
                if not name.endswith('.h'):
                    continue
                pair = os.path.join(os.path.basename(base), name).replace(os.sep, '/')
                index.add(pair)
                index.add(name)
                if 'Include' in rel and package:
                    owner.setdefault(pair, (root, package))
                    owner.setdefault(name, (root, package))
    _HEADER_INDEX[key] = (index, owner)
    return index, owner


def packages_for_includes(all_includes: List[str], edk2_dir: str) -> List[str]:
    """The .dec of every package whose Include/ holds a header the harness includes.

    [Packages] was a fixed list of six. A header from any other package is on disk and
    not on the include path, so the harness fails to compile with "fatal error:
    'Guid/DebugAgentGuid.h' file not found" -- naming a header that is right there in
    SourceLevelDebugPkg. The harness includes what the analysis saw it use, so the
    packages it needs are the ones those headers come from.
    """
    if not edk2_dir or not os.path.isdir(edk2_dir):
        return []
    _, owner = _header_index(edk2_dir)
    extra = []
    for entry in all_includes:
        tail = entry.strip().strip('<>"')
        found = owner.get(tail) or owner.get(os.path.basename(tail))
        if not found:
            continue
        root, package = found
        dec = f'{package}/{package}.dec'
        if dec in extra:
            continue
        if os.path.isfile(os.path.join(root, package, f'{package}.dec')):
            extra.append(dec)
    return extra


# Two packages can publish the same include path. Protocol/PlatformBootManager.h is the
# only one in edk2 master, and it is enough to lose a protocol: EmbeddedPkg declares
# PLATFORM_BOOT_MANAGER_PROTOCOL and MdeModulePkg declares EDKII_PLATFORM_BOOT_MANAGER_-
# PROTOCOL under that name. The analysis knew which file it read the protocol out of, but
# cleanup_paths keeps only the two trailing components, so by the time the include is
# written down the package is gone and [Packages] order decides -- and the fixed six are
# always emitted first, so MdeModulePkg wins and the harness fails on "unknown type name
# 'PLATFORM_BOOT_MANAGER_PROTOCOL'".
#
# The generated C is the tie-break that survived: it names the protocol type and the guid,
# and only one of the two headers declares them.
_EXTERN_GUID = re.compile(r'\bextern\s+EFI_GUID\s+(g\w*Guid)\s*;')


def _package_headers(edk2_dir: str):
    """Include path -> every package that publishes a header at it."""
    owners = {}
    if not os.path.isdir(edk2_dir):
        return owners
    for package in sorted(os.listdir(edk2_dir)):
        root = os.path.join(edk2_dir, package, 'Include')
        if not os.path.isdir(root):
            continue
        for base, _dirs, files in os.walk(root):
            for name in files:
                if not name.endswith('.h'):
                    continue
                absolute = os.path.join(base, name)
                relative = os.path.relpath(absolute, root).replace(os.sep, '/')
                owners.setdefault(relative, []).append((package, absolute))
    return owners


def preferred_packages(all_includes: List[str], harness_folder: str, edk2_dir: str) -> List[str]:
    """Packages whose .dec has to precede the rest for an ambiguous include to resolve."""
    if not edk2_dir or not os.path.isdir(edk2_dir):
        return []
    owners = _package_headers(edk2_dir)
    if not owners:
        return []
    text = ''
    for name in ('FirnessHarnesses.c', 'FirnessMain.c'):
        path = os.path.join(harness_folder, name)
        if os.path.isfile(path):
            text += open(path, errors='ignore').read()
    used = set(_IDENTIFIER.findall(text))
    priority = []
    for entry in all_includes:
        relative = entry.strip().strip('<>"')
        candidates = owners.get(relative) or []
        if len(candidates) < 2:
            continue
        scored = []
        for package, absolute in candidates:
            source = _read_header(absolute)
            declared = (set(_TYPEDEF_NAME.findall(source))
                        | set(_TYPEDEF_BRACE.findall(source))
                        | set(_TYPEDEF_FUNCTION.findall(source))
                        | set(_MACRO_NAME.findall(source))
                        | set(_EXTERN_GUID.findall(source)))
            scored.append((len(declared & used), package))
        scored.sort(reverse=True)
        # only when one of them plainly is the header the harness was written against
        if scored[0][0] == 0 or scored[0][0] == scored[1][0]:
            continue
        package = scored[0][1]
        dec = f'{package}/{package}.dec'
        if dec not in priority and os.path.isfile(os.path.join(edk2_dir, package, f'{package}.dec')):
            priority.append(dec)
            print(f'INFO: {dec} first in [Packages] -- it owns the {relative} the harness names')
    return priority


def existing_includes(all_includes: List[str], edk2_dir: str) -> List[str]:
    """Drop headers this tree does not have.

    The include list comes from the analysis, which may have run against a different edk2
    than the one the harness is built in -- a cached analysis, or a port to a newer tree.
    edk2 does remove headers: Protocol/ScsiPassThru.h is gone from mainline, and one stale
    entry fails the whole harness with "fatal error: file not found" whether or not
    anything in the harness uses that type.

    The list is a superset by construction, so a header nothing references costs nothing
    to drop. One that is genuinely needed still fails, and fails naming the type rather
    than the file, which is the more useful error.
    """
    if not edk2_dir or not os.path.isdir(edk2_dir):
        return all_includes
    index, _ = _header_index(edk2_dir)
    kept, dropped = [], []
    for entry in all_includes:
        tail = entry.strip().strip('<>"')
        if tail in index or os.path.basename(tail) in index:
            kept.append(entry)
        else:
            dropped.append(tail)
    for tail in sorted(set(dropped)):
        print(f'INFO: dropping include {tail} -- not in this edk2')
    return kept


# A header the harness includes is not required to be self contained. edk2 leaves the
# prerequisite to the caller: MdeModulePkg/Include/Protocol/MediaSanitize.h names
# EFI_BLOCK_IO_MEDIA and includes nothing, UsbEthernetProtocol.h names
# EFI_USB_DEVICE_REQUEST and includes nothing, and OvmfPkg/Include/Protocol/XenBus.h
# writes "typedef enum xenbus_state XenBusState" over an enum whose body is in
# IndustryStandard/Xen/io/xenbus.h. The driver that consumes the protocol includes the
# missing header first; the harness includes only what the analysis recorded, so the
# build stops inside the protocol header at "unknown type name".
#
# Rather than keep growing include_prerequisites by hand, read the tree: index what each
# publishable header declares, then for every header the harness includes, name the
# declarations it uses and does not have.
_DECL_INDEX = {}

# a type name is only worth chasing when the tree agrees where it comes from. UINTN is
# declared by six ProcessorBind.h and the arch include directory decides which; a name
# like that is left alone rather than guessed at
_AMBIGUOUS = object()

_COMMENT = re.compile(r'/\*.*?\*/|//[^\n]*', re.S)
_INCLUDE_DIRECTIVE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"]+)[>"]', re.M)
_IDENTIFIER = re.compile(r'[A-Za-z_]\w*')
# "struct foo" with no body is a forward declaration and legal; one the harness declares a
# variable of is not, so the tag's definition is chased the same way a typedef name is
_TAG_REFERENCE = re.compile(r'\b(?:struct|union|enum)\s+([A-Za-z_]\w*)')
_TAG_DEFINITION = re.compile(r'\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{')
_TYPEDEF_NAME = re.compile(r'\btypedef\b[^;{}]*?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;')
# a closing brace at column zero ends a top level typedef; an indented one ends a member,
# so "} Protocol;" inside EFI_UDP_IO's struct is not a type called Protocol
_TYPEDEF_BRACE = re.compile(r'^\}\s*([A-Za-z_]\w*)\s*;', re.M)
_TYPEDEF_FUNCTION = re.compile(r'\btypedef\b[^;]*?\(\s*(?:EFIAPI\s*)?\*\s*([A-Za-z_]\w*)\s*\)')
_MACRO_NAME = re.compile(r'^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)', re.M)


def _read_header(path: str) -> str:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            return _COMMENT.sub(' ', handle.read())
    except OSError:
        return ''


def _decl_index(edk2_dir: str):
    """Where each name a package publishes is declared, keyed the way an include names it.

    Only <Package>/Include counts: that is what a .dec puts on the include path, so it is
    exactly the set of headers the harness is able to write down. A driver's private
    Include directory declares plenty of types and none of them can be reached.
    """
    key = os.path.abspath(edk2_dir)
    if key in _DECL_INDEX:
        return _DECL_INDEX[key]
    paths, names, tags = {}, {}, {}
    if os.path.isdir(edk2_dir):
        for package in sorted(os.listdir(edk2_dir)):
            root = os.path.join(edk2_dir, package, 'Include')
            if not os.path.isdir(root):
                continue
            for base, _dirs, files in os.walk(root):
                for name in files:
                    if not name.endswith('.h'):
                        continue
                    absolute = os.path.join(base, name)
                    relative = os.path.relpath(absolute, root).replace(os.sep, '/')
                    paths.setdefault(relative, absolute)
        for relative, absolute in paths.items():
            source = _read_header(absolute)
            declared = (set(_TYPEDEF_NAME.findall(source))
                        | set(_TYPEDEF_BRACE.findall(source))
                        | set(_TYPEDEF_FUNCTION.findall(source))
                        | set(_MACRO_NAME.findall(source)))
            for name in declared:
                names[name] = relative if names.get(name, relative) == relative else _AMBIGUOUS
            for name in set(_TAG_DEFINITION.findall(source)):
                tags[name] = relative if tags.get(name, relative) == relative else _AMBIGUOUS
    _DECL_INDEX[key] = (paths, names, tags)
    return paths, names, tags


def _visible_headers(seeds: List[str], paths: Dict[str, str]):
    """Every header already reachable from what the harness includes.

    Deliberately generous: a header included under any spelling counts, and a name that
    only one arch's ProcessorBind.h declares counts as present because the arch include
    directory supplies one of them. Over-counting here only means a prerequisite is not
    added, which is the safe direction.
    """
    tails = {}
    for relative in paths:
        tails.setdefault(relative.rsplit('/', 1)[-1], []).append(relative)
    seen, pending = set(), list(seeds)
    while pending:
        relative = pending.pop()
        if relative in seen or relative not in paths:
            continue
        seen.add(relative)
        directory = relative.rsplit('/', 1)[0] if '/' in relative else ''
        for quoted, target in _INCLUDE_DIRECTIVE.findall(_read_header(paths[relative])):
            candidates = []
            if quoted == '"' and directory:
                candidates.append(f'{directory}/{target}')
            candidates.append(target)
            resolved = [c for c in candidates if c in paths]
            # "#include <ProcessorBind.h>" is satisfied by the arch include directory, and
            # every arch's copy declares the same names
            pending.extend(resolved or tails.get(target.rsplit('/', 1)[-1], []))
    return seen


def resolve_missing_declarations(all_includes: List[str], edk2_dir: str,
                                 limit: int = 12, rounds: int = 3) -> List[str]:
    """Add the header that declares a type an included header names but does not declare."""
    if not edk2_dir or not os.path.isdir(edk2_dir):
        return list(all_includes)
    paths, names, tags = _decl_index(edk2_dir)
    if not paths:
        return list(all_includes)
    ordered = [entry.strip().strip('<>"') for entry in all_includes]
    # AutoGen.h is force-included by the edk2 build and brings the base types with it
    scan = [entry for entry in ordered if entry in paths]
    added = []
    for _ in range(rounds):
        visible = _visible_headers(set(ordered) | {'Base.h', 'Uefi.h'}, paths)
        declared, defined_tags = set(), set()
        for relative in visible:
            source = _read_header(paths[relative])
            declared |= (set(_TYPEDEF_NAME.findall(source))
                         | set(_TYPEDEF_BRACE.findall(source))
                         | set(_TYPEDEF_FUNCTION.findall(source))
                         | set(_MACRO_NAME.findall(source)))
            defined_tags |= set(_TAG_DEFINITION.findall(source))
        wanted = []
        for relative in scan:
            source = _read_header(paths[relative])
            missing = set()
            for name in set(_IDENTIFIER.findall(source)) - declared:
                owner = names.get(name)
                if owner is not None and owner is not _AMBIGUOUS and owner not in visible:
                    missing.add(owner)
            for name in set(_TAG_REFERENCE.findall(source)) - defined_tags:
                owner = tags.get(name)
                if owner is not None and owner is not _AMBIGUOUS and owner not in visible:
                    missing.add(owner)
            for owner in sorted(missing):
                if owner not in ordered:
                    wanted.append((relative, owner))
        if not wanted:
            break
        scan = []
        for needed_by, owner in wanted:
            if owner in ordered or len(added) >= limit:
                continue
            ordered.insert(ordered.index(needed_by), owner)
            added.append(owner)
            scan.append(owner)
        if not scan:
            break
    for owner in added:
        print(f'INFO: including {owner} -- declares a type the harness includes but cannot see')
    return ordered


def generate_includes(all_includes: List[str], harness_folder: str, edk2_dir: str = ""):
    all_includes = existing_includes(all_includes, edk2_dir)
    code = uefi_header.harness_includes(all_includes)
    gen_file(f'{harness_folder}/includes.txt', all_includes)
    gen_file(f'{harness_folder}/FirnessIncludes.h', code)



# the guids the generated harness actually names. a guid reached through a generator
# function never appears in the protocol/driver sets the analysis returns, so it would be
# neither declared nor listed in the inf; collecting them from the emitted code covers
# Which inf section a guid belongs in is not a guess: every guid edk2 knows is declared in
# some package's .dec, under [Guids], [Protocols] or [Ppis]. Emitting one under the wrong
# heading fails the build ("Value of Protocol [g...] is not found under [Protocols]"), and
# emitting one whose package the harness does not include fails the same way.
DEC_GUID_DECL = re.compile(r'^(g\w*Guid)\s*=\s*(\{.*\})\s*$')


def dec_guid_index(edk2_dir):
    """Map guid name -> (section, package relative path, value) across every .dec."""
    index = {}
    roots = [edk2_dir]
    # edk2-platforms sits beside edk2 and declares guids the harness may reference even
    # though it cannot include the package
    sibling = os.path.join(os.path.dirname(os.path.abspath(edk2_dir)), 'edk2-platforms')
    if os.path.isdir(sibling):
        roots.append(sibling)
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.endswith('.dec'):
                    continue
                path = os.path.join(dirpath, name)
                package = os.path.relpath(path, root).replace(os.sep, '/')
                section = ''
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
                        for line in handle:
                            line = line.split('#')[0].strip()
                            if line.startswith('['):
                                section = line.strip('[]').split('.')[0].strip().lower()
                                continue
                            if section not in ('guids', 'protocols', 'ppis'):
                                continue
                            match = DEC_GUID_DECL.match(line)
                            if match:
                                index.setdefault(match.group(1),
                                                 (section, package, match.group(2)))
                except OSError:
                    continue
    return index


def classify_guids(names, edk2_dir):
    """Split guids into the inf's [Protocols] and [Guids] plus ones to define locally."""
    index = dec_guid_index(edk2_dir)
    available = set(uefi_inf.HARNESS_PACKAGES)
    protocols, guids, local = set(), set(), {}
    for name in sorted(set(names)):
        entry = index.get(name)
        if entry is None:
            # not declared in any .dec we can see; leave it to the linker rather than
            # inventing a section for it
            continue
        section, package, value = entry
        if package not in available:
            local[name] = value
        elif section == 'protocols':
            protocols.add(name)
        else:
            guids.add(name)
    return protocols, guids, local


# A guid from a package the harness cannot include still has a value, and the value is all
# the harness needs. Define it in the one translation unit that uses it -- the header is
# included by both FirnessMain.c and FirnessHarnesses.c, so a definition there would be a
# duplicate symbol.
def define_local_guids(harness_folder, local):
    if not local:
        return
    path = os.path.join(harness_folder, 'FirnessHarnesses.c')
    if not os.path.isfile(path):
        return
    lines = ['', '// Declared in a package this harness does not include, so the value is',
             '// carried here rather than resolved through the inf.']
    for name, value in sorted(local.items()):
        lines.append(f'EFI_GUID {name} = {value};')
    with open(path, 'a', encoding='utf-8') as handle:
        handle.write('\n'.join(lines) + '\n')


# every path and adds nothing the harness does not reference
GUID_REFERENCE = re.compile(r'\bg[A-Z]\w*Guid\b')


def referenced_guids(harness_folder):
    found = set()
    for name in ('FirnessHarnesses.c', 'FirnessMain.c'):
        path = os.path.join(harness_folder, name)
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
                found.update(GUID_REFERENCE.findall(handle.read()))
    return found


def generate_harness(merged_data: Dict[str, FunctionBlock],
                     template: Dict[str, FunctionBlock],
                     types: Dict[str, List[FieldInfo]],
                     enums: Dict[str, List[str]],
                     all_includes: List[str],
                     libraries: Dict[str, str],
                     generators: Dict[str, FunctionBlock],
                     aliases: Dict[str, str],
                     matched_macros: Dict[str, str],
                     protocol_guids: set,
                     driver_guids: set,
                     harness_folder: str,
                     output_dir: str,
                     random: bool = False,
                     backend: int = 1,
                     edk2_dir: str = "",
                     max_steps: int = 8,
                     precedence=()):

    function_list = list(merged_data.keys())
    generate_main(function_list, harness_folder, max_steps, precedence)
    generate_code(merged_data, template, types, generators, aliases, harness_folder, enums, random)
    # before the list is written out or turned into packages, so the inf declares the
    # package a pulled-in prerequisite comes from
    all_includes = resolve_missing_declarations(all_includes, edk2_dir)
    used_guids = referenced_guids(harness_folder)
    generate_header(merged_data, matched_macros, harness_folder, used_guids)
    generate_includes(all_includes, harness_folder, edk2_dir)
    inf_protocols, inf_guids, local_guids = classify_guids(
        used_guids | set(protocol_guids) | set(driver_guids), edk2_dir)
    define_local_guids(harness_folder, local_guids)
    # Filter the INF only. The INF is what edk2 links -- and so whose constructors run --
    # while the DSC is the class-to-instance map it resolves against, including for the
    # transitive dependencies of the libraries that are kept. Trimming the DSC too left
    # those unresolvable and the harness stopped compiling.
    generate_inf(harness_folder, used_libraries(libraries, harness_folder, all_includes, edk2_dir),
                 inf_guids, inf_protocols, all_includes, edk2_dir)
    generate_dsc(harness_folder, libraries, backend)
    # generate_harness_debugger(merged_data, template,
                            #   types, all_includes, generators, aliases, harness_folder)
    output_dir = os.path.join(output_dir, 'Firness')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    os.system(f'cp {harness_folder}/* {output_dir}')


BACKENDS_BY_ID = {value: name for name, value in
                  (('tsffs', 1), ('qemu', 2), ('nyx', 3), ('none', 4))}


def generate_smi_linux_driver(smi_data, harness_folder, edk2_dir, backend_name):
    """Emit the kernel module form of the SMI harness.

    Deliberately writes into the same harness folder as the UEFI form, and nothing else:
    a driver has no .dsc, no .inf and no edk2 library resolution, so none of the machinery
    the UEFI path runs afterwards applies to it.
    """
    roots = [edk2_dir] if edk2_dir else []
    guids = linux_guid_values.collect(roots)
    module = 'firness_smi'
    files = {
        f'{module}.c': linux_smi_driver.driver(smi_data, guids, module),
        'Makefile': linux_smi_driver.makefile(module),
        linux_smi_driver.FIRNESS_BACKEND_HEADER: linux_smi_driver.backend_header(),
    }
    os.makedirs(harness_folder, exist_ok=True)
    # generate_harness_folder copies HarnessHelpers in wholesale for the UEFI path. None
    # of it belongs next to a kernel module -- it is edk2 C that cannot compile here --
    # and leaving it makes it unclear which files are the harness.
    for name in os.listdir(harness_folder):
        if name not in files:
            path = os.path.join(harness_folder, name)
            if os.path.isfile(path):
                os.remove(path)
    for name, lines in files.items():
        with open(os.path.join(harness_folder, name), 'w') as handle:
            handle.write('\n'.join(lines) + '\n')
    resolved = sum(1 for info in smi_data.values() if info.guid in guids)
    print(f'Linux SMI driver: {resolved}/{len(smi_data)} handler(s) with a resolvable '
          f'GUID, backend {backend_name}, in {harness_folder}')
    return 0


def generate_smi_harness(smi_data: Dict[str, SmiInfo],
                     types: Dict[str, List[FieldInfo]],
                     enums: Dict[str, List[str]],
                     all_includes: List[str],
                     libraries: Dict[str, str],
                     aliases: Dict[str, str],
                     matched_macros: Dict[str, str],
                     protocol_guids: set,
                     driver_guids: set,
                     harness_folder: str,
                     output_dir: str,
                     random: bool = False,
                     backend: int = 1,
                     edk2_dir: str = "",
                     max_steps: int = 8,
                     precedence=(),
                     host: str = 'uefi'):
    function_list = list(smi_data.keys())
    print(harness_folder)
    if host == 'linux':
        return generate_smi_linux_driver(smi_data, harness_folder, edk2_dir,
                                         BACKENDS_BY_ID.get(backend, 'tsffs'))
    generate_main(function_list, harness_folder)
    generate_smi_code(smi_data, types, aliases, harness_folder, enums, random)
    used_guids = referenced_guids(harness_folder)
    generate_header(function_list, matched_macros, harness_folder, used_guids)
    generate_includes(all_includes, harness_folder, edk2_dir)
    inf_protocols, inf_guids, local_guids = classify_guids(
        used_guids | set(protocol_guids) | set(driver_guids), edk2_dir)
    define_local_guids(harness_folder, local_guids)
    # Filter the INF only. The INF is what edk2 links -- and so whose constructors run --
    # while the DSC is the class-to-instance map it resolves against, including for the
    # transitive dependencies of the libraries that are kept. Trimming the DSC too left
    # those unresolvable and the harness stopped compiling.
    generate_inf(harness_folder, used_libraries(libraries, harness_folder, all_includes, edk2_dir),
                 inf_guids, inf_protocols, all_includes, edk2_dir)
    generate_dsc(harness_folder, libraries, backend)
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

def calculate_statistics(merged_data: Dict[str, FunctionBlock],
                     generators: Dict[str, FunctionBlock],
                     aliases: Dict[str, str],
                     enums: Dict[str, EnumDef],
                     harness_folder: str,
                     total_generators: int):
    total_functions = len(merged_data)

    # collect total number of scalable types that aren't pointers
    total_scalable_types = 0
    total_pointer_types = 0
    total_struct_types = 0
    total_constants = 0
    enum_list = []
    for _, function_block in merged_data.items():
        for _, argument in function_block.arguments.items():
            is_scalable = any(param.lower() in argument[-1].arg_type.lower() or param.lower() in aliases.get(argument[-1].arg_type, "").lower() for param in scalable_params)
            if '*' not in argument[-1].arg_type and (is_scalable or "__FUZZABLE__" == argument[-1].variable):
                total_scalable_types += 1
            elif (is_scalable or "__FUZZABLE__" == argument[-1].variable):
                total_pointer_types += 1
            else:
                total_struct_types += 1
            for arg in argument:
                if "CONSTANT" in arg.variable and arg.arg_dir == "IN":
                    total_constants += 1
                elif "__ENUM_ARG__" in arg.variable and arg.arg_type not in enum_list:
                    total_constants += len(enums.get(arg.arg_type, EnumDef()).values)
                    enum_list.append(arg.arg_type)
    
    print(f"Total Functions: {total_functions}")
    print(f"Total Generators: {total_generators}")
    print(f"Total Scalable Types: {total_scalable_types}")
    print(f"Total Pointer Types: {total_pointer_types}")
    print(f"Total Struct Types: {total_struct_types}")
    print(f"Total Constants: {total_constants}")

    # output total stats to csv file
    with open(f'{harness_folder}/stats.csv', 'w') as file:
        file.write(f"Total Functions,{total_functions}\n")
        file.write(f"Total Generators,{total_generators}\n")
        file.write(f"Total Scalable Types,{total_scalable_types}\n")
        file.write(f"Total Pointer Types,{total_pointer_types}\n")
        file.write(f"Total Struct Types,{total_struct_types}\n")
        file.write(f"Total Constants,{total_constants}\n")



def main():
    parser = argparse.ArgumentParser(description='Process some data.')
    parser.add_argument('--edk2', dest='edk2', default='/workspace/tmp/edk2', help='Path to the edk2 directory (default: /workspace/tmp/edk2)')
    parser.add_argument('-d', '--data-file', dest='data_file', default='/output/tmp/call-database.json',
                        help='Path to the data file (default: /output/tmp/call-database.json)')
    parser.add_argument('-g', '--generator-file', dest='generator_file', default='/output/tmp/generator-database.json',
                        help='Path to the generator file (default: /output/tmp/generator-database.json)')
    parser.add_argument('-gd', '--generators', dest='generators', default='/output/tmp/generators.json',
                        help='Path to the generator file (default: /output/tmp/generators.json)')
    parser.add_argument('-in', '--includes-file', dest='includes_file', default='/output/tmp/includes.json',
                        help='Path to the includes file (default: /output/tmp/includes.json)')
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
    parser.add_argument('-s', '--cast-file', dest='cast_file',
                        default='/output/tmp/cast-map.json', help='Path to the cast file (default: /output/tmp/cast-map.json)')
    parser.add_argument('-o', '--output', dest='output',
                        default='/output', help='Path to the output directory (default: /output)')
    parser.add_argument('-c', '--clean', dest='clean', action='store_true',
                        help='Clean the generator database (default: False)')
    parser.add_argument('-r', '--random', dest='random', action='store_true',
                        help='Use random input instead of structured input data (default: False)')
    parser.add_argument('-b', '--best-guess', dest='best_guess', action='store_true',
                        help='Choose the function match with the highest frequency even if it might not be the right one (default: False)')
    parser.add_argument("--smi", dest="smi_enabled", action="store_true", help="Enable SMI generation")
    parser.add_argument('--max-steps', dest='max_steps', type=int, default=8,
                        help='Calls chained per fuzzing iteration (default 8). Lower it for '
                             'protocols whose calls are slow enough to starve the fuzzer')
    parser.add_argument('--backend', dest='backend', default='tsffs', choices=sorted(BACKENDS),
                        help='Fuzzer the harness talks to (default: tsffs)')
    parser.add_argument("-sm", dest="smi", default="/ouput/tmp/smi-function-guid-map.json", 
                        help="Path to the smi file (default: /output/tmp/smi-function-guid-map.json)")
    parser.add_argument('--host', dest='host', default='uefi', choices=('uefi', 'linux'),
                        help='What the SMI harness is: a UEFI application that runs before '
                             'an OS (default), or a Linux kernel module that drives the same '
                             'handlers from ring 0 after ExitBootServices. SMI only -- a '
                             'protocol harness has no meaning once boot services are gone.')

    args = parser.parse_args()

    # FirnessBackend.h refuses to compile the Nyx backend on a host without Intel PT, and
    # that #error lands in the middle of an edk2 build log. Say it here instead.
    if args.backend == 'nyx':
        print('WARNING: the Nyx backend is not implemented -- FirnessBackend.h stops the '
              'build with an #error because Intel PT is unavailable here. The harness will '
              'generate but will not compile; use --backend qemu (libafl-qemu) instead.')

    if args.host == 'linux' and not args.smi_enabled:
        print('Error: --host linux is only for SMI handlers (--smi). A protocol harness '
              'calls boot services, which are gone by the time a kernel module runs.')
        return 1

    clean_harnesses(args.clean, args.output)
    harness_folder = generate_harness_folder(args.output)
    if args.smi_enabled:
        smi_data, includes, libraries, types, enums, aliases, protocol_guids, driver_guids, matched_macros  = analyze_smi_data(args.macro_file, args.enum_file, args.smi, args.types_file, args.alias_file, args.cast_file, args.random, harness_folder, args.best_guess, args.edk2, args.includes_file)
        generate_smi_harness(smi_data, types, enums, includes, libraries, aliases, matched_macros, protocol_guids, driver_guids, harness_folder, args.output, args.random, BACKENDS[args.backend], args.edk2, args.max_steps, host=args.host)
    else:
        processed_data, processed_generators, template, types, all_includes, libraries, matched_macros, aliases, protocol_guids, driver_guids, enums, total_generators, precedence = analyze_data(args.macro_file, args.enum_file, args.generator_file, args.input_file,
                                                    args.data_file, args.types_file, args.alias_file, args.cast_file, args.random, harness_folder, args.best_guess, args.function_file, args.generators, args.edk2, args.includes_file)
        
        main_dir = os.path.dirname(os.path.abspath(args.data_file))
        calculate_statistics(processed_data, processed_generators, aliases, enums, main_dir, total_generators)

        generate_harness(processed_data, template, types, enums,
                        all_includes, libraries, processed_generators, aliases, matched_macros, protocol_guids, driver_guids, harness_folder, args.output, args.random, BACKENDS[args.backend], args.edk2, args.max_steps, precedence)
    

if __name__ == '__main__':
    main()