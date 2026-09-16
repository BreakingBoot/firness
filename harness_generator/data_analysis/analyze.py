import json
import os
import re
import copy
from fuzzywuzzy import fuzz
import math
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Set
from common.types import FunctionBlock, FieldInfo, TypeInfo, EnumDef, Function, Argument, Macros, scalable_params, services_map, type_defs, known_contant_variables, ignore_constant_keywords, default_includes, default_libraries, include_prerequisites, unusable_includes
from common.utils import remove_ref_symbols, write_data, get_union, is_whitespace, contains_void_star, contains_usage, get_stripped_usage, is_fuzzable, get_intersect, print_function_block
from common.generate_library_map import generate_libmap

current_args_dict = defaultdict(list)
all_includes = set()
# a string or character literal, with any of the edk2/C prefixes it may carry
STRING_LITERAL = re.compile(r'(?:u8|[LuU])?(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')
total_generators = set()


# Doesn't take into account if multiple function definitions are found with the same
# name but different number of params
# Analyses produced before the OPTIONAL pass have no is_optional key at all. Everything
# would then default to "not optional", and the harness would silently stop passing NULL
# anywhere rather than passing it only where it is allowed. Notice the difference and keep
# the old behaviour for old caches instead of quietly losing coverage.
OPTIONAL_INFO_AVAILABLE = False


def note_optional_info(raw_argument):
    global OPTIONAL_INFO_AVAILABLE
    if isinstance(raw_argument, dict) and 'is_optional' in raw_argument:
        OPTIONAL_INFO_AVAILABLE = True
    return raw_argument


def load_generator_declares(json_file: str) -> Dict[str, Tuple[str, str]]:
    try:
        with open(json_file, 'r') as file:
            # a bare "null" is written when nothing was recorded
            raw_data = json.load(file) or []

        function_dict = defaultdict(list)
        for raw_function in raw_data:
            # per entry, not around the loop: a single record with "Parameters": null used
            # to abort the whole load and return nothing, which silently removed every
            # generator from the run
            try:
                arguments = {
                    arg_key: [Argument(**note_optional_info(raw_argument))] 
                    # "Parameters": null reaches get() as None, past the default
                    for arg_key, raw_argument in (raw_function.get('Parameters') or {}).items()
                }
                function = Function(raw_function.get('Function'), arguments, raw_function.get('ReturnType'),
                                    raw_function.get('Service'), raw_function.get('Includes'), raw_function.get('File'))
                function_dict[function.function] = function
            except Exception as e:
                print(f'ERROR: {e}')

        return function_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}


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

# Doesn't take into account if multiple function definitions are found with the same
# name but different number of params
def load_function_declares(json_file: str) -> Dict[str, Tuple[str, str]]:
    try:
        with open(json_file, 'r') as file:
            # a bare "null" is written when nothing was recorded
            raw_data = json.load(file) or []

        function_dict = defaultdict(list)
        for raw_function in raw_data:
            # per entry, not around the loop, for the same reason as the generator loader
            try:
                arguments = {
                    arg_key: [Argument(**note_optional_info(raw_argument))] 
                    for arg_key, raw_argument in (raw_function.get('Parameters') or {}).items()
                }
                function = Function(raw_function.get('Function'), arguments, raw_function.get('ReturnType'),
                                    raw_function.get('Service'), raw_function.get('Includes'))
                function_dict[function.function] = function
            except Exception as e:
                print(f'ERROR: {e}')

        return function_dict
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

def load_libmap(edk2_dir: str, output_file: str) -> Dict[str, Dict[str, list]]:
    try:
        return generate_libmap(edk2_dir, output_file)
    except Exception as e:
        print(f'ERROR: {e}')
        return {}

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


#
# load in the functions to be harnessed
#
# turn a protocol GUID variable into the struct tag it names, so a requested
# gEfiKmsProtocolGuid:GetServiceStatus can be checked against a call-site whose first
# parameter is EFI_KMS_PROTOCOL *. without this the match is on the method name alone
# and any protocol that happens to have a method of that name can be picked up --
# which is how EfiKms ended up generating against _EFI_IPN_PROTOCOL

# guid variable name -> the struct names declared in the same header. deriving the struct
# from the guid name cannot work in general: the name is camel case, so it does not say
# where an acronym ends (gEdkiiIoMmuProtocolGuid vs EDKII_IOMMU_PROTOCOL), and it is often
# an abbreviation of the struct (gEfiSimpleTextOutProtocolGuid vs
# EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL). the header that declares the guid is authoritative
guid_struct_map = {}
# guid -> the real spelling of the protocol struct declared beside it
guid_protocol_name = {}
# guid -> the header that declares it, as an absolute path
guid_header = {}

GUID_DECL = re.compile(r'extern\s+EFI_GUID\s+(g\w+)\s*;')

# EDK2 marks a parameter that accepts NULL with OPTIONAL, in the declaration:
#
#   typedef EFI_STATUS (EFIAPI *EFI_ABSOLUTE_POINTER_GET_STATE)(
#     IN EFI_ABSOLUTE_POINTER_PROTOCOL  *This,
#     IN OUT EFI_ABSOLUTE_POINTER_STATE *State
#     );
#
# Nothing there accepts NULL, so a harness that passes one is breaking the caller's side
# of the contract and the fault it provokes says nothing about the firmware. The analyser
# is supposed to record this per argument and does not, so every pointer got a NULL arm:
# EFI_ABSOLUTE_POINTER_PROTOCOL.GetState was reported faulting on "State->CurrentX = 0"
# after the harness freed State and passed NULL, which is exactly what the declaration
# says will happen.
#
# The declarations are in the headers this pass already reads, so read them here.
FUNC_TYPEDEF = re.compile(r'\(\s*EFIAPI\s*\*\s*(\w+)\s*\)\s*\(([^;]*?)\)\s*;', re.S)
STRUCT_MEMBER = re.compile(r'^\s*(\w+)\s+(\w+)\s*;\s*$', re.M)
# guid -> {member function name: {parameter name: accepts NULL}}
optional_params = {}


def split_params(text: str):
    """The parameters of a declaration, one string each."""
    parts, depth, current = [], 0, []
    for ch in text:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append(''.join(current))
    return [p.strip() for p in parts if p.strip()]


def parse_optional(params_text: str):
    """[(parameter name, whether the declaration lets it be NULL)], in order.

    In order because that is how they are matched: the analyser records an argument as
    Arg_0, Arg_1 and so on and leaves param_name empty, so position is the only thing the
    two sides share.

    OPTIONAL follows the name -- "IN VOID *Context OPTIONAL" -- so the name is the last
    identifier that is not one of edk2's own markers.
    """
    markers = {'IN', 'OUT', 'OPTIONAL', 'CONST', 'EFIAPI', 'VOID'}
    found = []
    for param in split_params(params_text):
        words = re.findall(r'[A-Za-z_]\w*', param)
        names = [w for w in words if w not in markers]
        if not names:
            continue
        found.append((names[-1], 'OPTIONAL' in words))
    return found
STRUCT_NAMES = re.compile(r'\}\s*([A-Za-z_]\w*)\s*;|struct\s+([A-Za-z_]\w*)\s*\{'
                          r'|typedef\s+(?:struct\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;')


def normalize_struct(name: str) -> str:
    return (name or '').strip().lstrip('_').replace('_', '').upper()


def build_guid_struct_map(edk2_dir: str):
    if guid_struct_map or not edk2_dir or not os.path.isdir(edk2_dir):
        return
    for package in sorted(os.listdir(edk2_dir)):
        for section in ('Protocol', 'Guid', 'Ppi'):
            root = os.path.join(edk2_dir, package, 'Include', section)
            if not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    if not name.endswith('.h'):
                        continue
                    try:
                        with open(os.path.join(dirpath, name), 'r',
                                  encoding='utf-8', errors='ignore') as handle:
                            source = handle.read()
                    except OSError:
                        continue
                    guids = GUID_DECL.findall(source)
                    if not guids:
                        continue
                    typedefs = {who: parse_optional(params)
                                for who, params in FUNC_TYPEDEF.findall(source)}
                    members = {member: typedefs[kind]
                               for kind, member in STRUCT_MEMBER.findall(source)
                               if kind in typedefs}
                    for guid in guids:
                        guid_header.setdefault(guid, os.path.join(dirpath, name))
                        if members:
                            optional_params.setdefault(guid, {}).update(members)
                    structs = {normalize_struct(part)
                               for match in STRUCT_NAMES.findall(source)
                               for part in match if part}
                    structs.discard('')
                    real = {part for match in STRUCT_NAMES.findall(source)
                            for part in match if part}
                    for guid in guids:
                        guid_struct_map.setdefault(guid, set()).update(structs)
                        if guid in guid_protocol_name:
                            continue
                        want = guid_to_struct(guid).replace('_', '')
                        named = [r for r in sorted(real)
                                 if normalize_struct(r).endswith('PROTOCOL')]
                        # "typedef struct _X X;" yields both spellings, and only the
                        # typedef is usable as a type on its own -- naming the tag emits
                        # "_X *ProtocolVariable", which is not a declared type
                        typedefs = [r for r in named if not r.startswith('_')]
                        for pool in (typedefs, named):
                            exact = [r for r in pool if normalize_struct(r) == want]
                            if exact:
                                guid_protocol_name[guid] = exact[0]
                                break
                        else:
                            if typedefs or named:
                                guid_protocol_name[guid] = (typedefs or named)[0]


def guid_to_struct(guid: str) -> str:
    if not guid:
        return ""
    name = guid[1:] if guid.startswith('g') else guid
    if name.endswith('Guid'):
        name = name[:-4]
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out.append('_')
        out.append(ch.upper())
    return ''.join(out)


# the call-site's first parameter type, stripped to a bare struct tag
def arg0_struct(function_info) -> str:
    args = getattr(function_info, 'arguments', None)
    if not args:
        return ""
    first = args.get('Arg_0') if isinstance(args, dict) else None
    if not first:
        return ""
    entry = first[0] if isinstance(first, list) else first
    t = getattr(entry, 'arg_type', '') or ''
    for junk in ('const', 'CONST', '*', 'struct'):
        t = t.replace(junk, ' ')
    # edk2 spells a protocol as "typedef struct _EFI_X_PROTOCOL EFI_X_PROTOCOL", so a call
    # site records the tag with its leading underscore while the guid gives the plain name
    return t.strip().lstrip('_').upper()


# a requested (method, guid) matches a call-site name when the names are equal and,
# when both sides know their protocol struct, the structs agree
def harness_match(function: str, pair, function_info=None) -> bool:
    name, guid = pair[0], (pair[1] if len(pair) > 1 else "")
    if function != name:
        return False
    known = guid_struct_map.get(guid)
    want = guid_to_struct(guid)
    if (not want and not known) or function_info is None:
        return True
    got = arg0_struct(function_info)
    if not got:
        return True
    # the header that declares the guid is authoritative when it is known; the name
    # derived from the guid is only a fallback for a guid that was never found
    if known:
        return normalize_struct(got) in known
    # compared without the separators: the guid name is split on camel case, which cannot
    # know where an acronym ends, so gEdkiiIoMmuProtocolGuid yields EDKII_IO_MMU_PROTOCOL
    # for a struct actually called EDKII_IOMMU_PROTOCOL. dropping the underscores still
    # tells two different protocols apart
    return got.replace('_', '') == want.replace('_', '')



# the number of parameters a protocol member really takes, read from the header that
# declares the protocol. a declaration found elsewhere can share a member's name and have a
# different signature -- MdeModulePkg/Bus/Pci/PciBusDxe/PciIo.h declares a six parameter
# CopyMem while EFI_PCI_IO_PROTOCOL.CopyMem takes seven -- and calling through the protocol
# with the wrong count does not compile
# the parameter list of a protocol member, taken from the header that declares the
# protocol. a member is a function pointer inside the struct rather than a free function,
# so the declaration pass never records one, and for a protocol with no call sites the only
# same-named declarations belong to unrelated drivers. the header is authoritative
def protocol_member_arity(header_path: str, protocol_name: str, member: str):
    params = protocol_member_params(header_path, protocol_name, member)
    return None if params is None else len(params)



# edk2 tags a protocol struct as _EFI_X_PROTOCOL, tdEFI_X_PROTOCOL or just EFI_X_PROTOCOL,
# and sometimes leaves it anonymous with the name only on the closing brace
def protocol_struct_body(source: str, protocol_name: str):
    match = re.search(r'struct\s+\w*?' + re.escape(protocol_name) + r'\s*\{(.*?)\n\}',
                      source, re.S)
    if match:
        return match.group(1)
    # the closing name carries the same optional tag prefix as the opening one
    match = re.search(r'typedef\s+struct\s*\{(.*?)\n\}\s*\w*?' + re.escape(protocol_name) + r'\s*;',
                      source, re.S)
    return match.group(1) if match else None


# The members are not always declared in the protocol's own body. EFI_CPU_IO2_PROTOCOL
# declares no Read: it holds Mem and Io, each an EFI_CPU_IO_PROTOCOL_ACCESS that declares
# Read and Write, and a call site writes CpuIo->Mem.Read(...) -- so the name that reaches
# here is the leaf. Searching only the protocol's own body finds nothing for such a member
# and the caller then concludes it is not a member of this protocol at all: no signature
# to build a block from, which is why EFI_MM_CPU_IO_PROTOCOL, whose whole surface is
# nested, produced no harness whatsoever. Sub-structures held by value are part of the
# protocol's own storage, so they are searched too. A pointer member is a separate object
# the protocol may leave NULL and is deliberately not followed.
def protocol_member_access(source: str, protocol_name: str, member: str,
                           depth: int = 3) -> list:
    """[(access path, the field's typedef)] for every way the protocol reaches `member`.

    The path is what the call has to be written through: "Read" for a member of the
    protocol itself, "Mem.Read" for one the protocol reaches through a sub-structure.
    A member held by value is part of the protocol's own storage and is searched; a
    pointer member is a separate object the protocol may leave NULL, is not part of this
    protocol's surface, and is deliberately not followed.
    """
    body = protocol_struct_body(source, protocol_name)
    if not body:
        return []
    found = []
    direct = re.search(r'\b([A-Za-z_]\w*)\s+' + re.escape(member) + r'\s*;', body)
    if direct:
        found.append((member, direct.group(1)))
    if depth > 0:
        for kind, name in re.findall(r'^\s*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;\s*$',
                                     body, re.M):
            if kind == protocol_name or name == member:
                continue
            for path, leaf in protocol_member_access(source, kind, member, depth - 1):
                found.append((f'{name}.{path}', leaf))
    return found


def protocol_member_kind(source: str, protocol_name: str, member: str, depth: int = 3):
    """The typedef name the protocol declares `member` with, or None."""
    found = protocol_member_access(source, protocol_name, member, depth)
    return found[0][1] if found else None


_header_source = {}


def header_source(header_path: str) -> str:
    if header_path not in _header_source:
        try:
            with open(header_path, 'r', encoding='utf-8', errors='ignore') as handle:
                _header_source[header_path] = handle.read()
        except OSError:
            _header_source[header_path] = ''
    return _header_source[header_path]


def nested_member_paths(header_path: str, protocol_name: str, member: str) -> list:
    """The access paths of a member the protocol does not declare at its top level.

    Empty for a member the protocol declares itself, so a block only carries this when
    the harness would otherwise emit a member access that does not exist. The types
    database cannot answer this on its own: a protocol with no call sites has no entry
    in it at all, which is every member built from its header below.
    """
    paths = protocol_member_access(header_source(header_path), protocol_name, member)
    if not paths or any(path == member for path, _kind in paths):
        return []
    return paths


def protocol_member_return(header_path: str, protocol_name: str, member: str) -> str:
    try:
        with open(header_path, 'r', encoding='utf-8', errors='ignore') as handle:
            source = handle.read()
    except OSError:
        return 'EFI_STATUS'
    kind = protocol_member_kind(source, protocol_name, member)
    if not kind:
        return 'EFI_STATUS'
    # the return type can be a pointer -- DuplicateDevicePath is declared
    # "typedef EFI_DEVICE_PATH_PROTOCOL * (EFIAPI *EFI_DEVICE_PATH_UTILS_DUPLICATE...)"
    # and an identifier-only pattern never matched it, so every such member looked like it
    # returned EFI_STATUS and the harness assigned a pointer to Status
    # the return type can be more than one word: EFI_SHELL_GET_MAP_FROM_DEVICE_PATH
    # returns CONST CHAR16 *, and a single-identifier pattern missed it, so the member
    # looked like it returned EFI_STATUS and the harness assigned a pointer to Status
    typed = re.search(r'typedef\s+((?:[A-Za-z_]\w*\s+)*[A-Za-z_]\w*(?:\s*\*)*)\s*'
                      r'\(\s*EFIAPI\s*\*\s*'
                      + re.escape(kind) + r'\s*\)', source)
    if not typed:
        return 'EFI_STATUS'
    return re.sub(r'\s*\*', ' *', typed.group(1).strip()).strip()


def protocol_member_signature(header_path: str, protocol_name: str, member: str):
    raw = protocol_member_params(header_path, protocol_name, member)
    if raw is None:
        return None
    parsed = []
    for index, param in enumerate(raw):
        # a variadic member has nothing to generate for the "..." and cannot be called
        # through a fixed argument list
        if '...' in param:
            return None
        text = ' '.join(param.replace('*', ' * ').split())
        # an array parameter is a pointer at the call boundary; keeping "[N]" in the type
        # emitted "UINT8 Csn[SIZE] GetCsn_Arg_2"
        # the extent is dropped here and the pointer added after the parameter name has
        # been removed, or "UINT8 Csn[SIZE]" becomes the type "UINT8 Csn *"
        array = re.search(r'\[[^\]]*\]', text)
        if array:
            text = text[:array.start()].strip()
        direction = 'IN'
        if 'OPTIONAL' in text:
            direction = 'OPTIONAL'
        elif re.search(r'\bIN\b', text) and re.search(r'\bOUT\b', text):
            direction = 'IN_OUT'
        elif re.search(r'\bOUT\b', text):
            direction = 'OUT'
        # CONST is dropped so the variable stays assignable, except on a nested pointer:
        # passing EFI_GUID ** where CONST EFI_GUID ** is wanted is an error C does not
        # forgive, while a single CONST X * converts silently and needs no qualifier here
        keep_const = text.count('*') >= 2
        dropped = ('IN', 'OUT', 'OPTIONAL') if keep_const else ('IN', 'OUT', 'OPTIONAL', 'CONST', 'const')
        words = [w for w in text.split() if w not in dropped]
        if not words:
            return None
        # the trailing identifier is the parameter name unless the whole thing is a type
        name = ''
        if len(words) > 1 and re.match(r'^[A-Za-z_]\w*$', words[-1]):
            name = words[-1]
            words = words[:-1]
        arg_type = ' '.join(words).replace(' *', ' *').strip()
        if array:
            arg_type = (arg_type + ' *').strip()
        if not arg_type:
            return None
        parsed.append((f'Arg_{index}', arg_type, direction, name))
    return parsed


PARAM_DIRECTION = re.compile(r'\b(IN|OUT|OPTIONAL|CONST)\b')


def param_name(spec: str) -> str:
    """The name a protocol typedef gives one parameter, or '' if it names only a type."""
    text = PARAM_DIRECTION.sub(' ', spec).strip()
    text = re.sub(r'\[.*?\]', '', text).strip()
    match = re.match(r'^(.*?)([A-Za-z_]\w*)\s*$', text)
    if match and match.group(1).strip():
        return match.group(2)
    return ''


def param_type_qualified(spec: str) -> str:
    """param_type, but keeping CONST, for casting at the call site."""
    text = re.sub(r'\b(IN|OUT|OPTIONAL)\b', ' ', spec).strip()
    array = '[' in text
    text = re.sub(r'\[.*?\]', '', text).strip()
    match = re.match(r'^(.*?)([A-Za-z_]\w*)\s*$', text)
    if match and match.group(1).strip():
        text = match.group(1).strip()
    if array:
        text += ' *'
    return re.sub(r'\s+', ' ', re.sub(r'\s*\*', ' *', text)).strip()


def param_type(spec: str) -> str:
    """The type of one parameter from a protocol typedef, without its name."""
    text = PARAM_DIRECTION.sub(' ', spec).strip()
    # an array parameter decays to a pointer, but only after the name is stripped
    array = '[' in text
    text = re.sub(r'\[.*?\]', '', text).strip()
    match = re.match(r'^(.*?)([A-Za-z_]\w*)\s*$', text)
    if match and match.group(1).strip():
        text = match.group(1).strip()
    if array:
        text += ' *'
    return re.sub(r'\s*\*', ' *', text).strip()


def protocol_member_params(header_path: str, protocol_name: str, member: str):
    try:
        with open(header_path, 'r', encoding='utf-8', errors='ignore') as handle:
            source = handle.read()
    except OSError:
        return None
    kind = protocol_member_kind(source, protocol_name, member)
    if not kind:
        return None
    signature = re.search(r'\(\s*EFIAPI\s*\*\s*' + re.escape(kind) +
                          r'\s*\)\s*\((.*?)\)\s*;', source, re.S)
    if not signature:
        return None
    params = signature.group(1).strip()
    # "(IN VOID)" is how edk2 spells a member that takes nothing -- EmbeddedPkg's
    # PLATFORM_VIRTUAL_KBD_REGISTER and PLATFORM_VIRTUAL_KBD_RESET are both declared that
    # way. Testing the text against "VOID" alone missed it, so the member looked like it
    # took one parameter of type VOID: the harness declared a variable of an incomplete
    # type and passed "(VOID){0}" to a member whose parameter list is empty.
    bare = PARAM_DIRECTION.sub(' ', params).strip()
    if not bare or bare.upper() == 'VOID':
        return []
    pieces, depth, current = [], 0, ''
    for character in params:
        if character in '([':
            depth += 1
        elif character in ')]':
            depth -= 1
        if character == ',' and depth == 0:
            pieces.append(current)
            current = ''
        else:
            current += character
    pieces.append(current)
    return [p.strip() for p in pieces if p.strip()]


def load_functions(function_file: str) -> Dict[str, List[Tuple[str, str]]]:
    # Load in the functions to be harnessed from the txt file
    # They are classified into 3 categories: OtherFunctions, BootServices, and RuntimeServices
    with open(function_file, 'r') as file:
        data = file.readlines()
    function_dict = defaultdict(list)
    current_service = ""
    for line in data:
        if line.strip() != "":
            if line.strip().startswith("["):
                current_service = line.strip().replace("[", "").replace("]", "")
            # if the line is a comment, then skip it
            elif line.strip().startswith("//"):
                continue
            else:
                if ':' in line:
                    function_dict[current_service].append(
                        (line.split(':')[1].strip(), line.split(':')[0].strip()))
                else:
                    function_dict[current_service].append((line.strip(), ""))
    return function_dict


ARG_INDEX = re.compile(r'^Arg_(\d+)$')


def apply_declarations(data, harness_functions):
    """Put what the declarations say onto the arguments.

    The analyser is meant to record a parameter's name and EDK2's OPTIONAL marker and
    records neither -- every param_name comes back empty and no argument carries
    is_optional at all. Two things go quiet when that happens, and neither says so:

    Passing NULL. Without the marker every pointer argument gets a NULL arm, and passing
    NULL to a parameter the declaration does not mark OPTIONAL is the caller breaking the
    contract. EFI_ABSOLUTE_POINTER_PROTOCOL.GetState was reported faulting on
    "State->CurrentX = 0" after the harness freed State and passed NULL, which is what
    that declaration says will happen.

    Pairing a size with its buffer. buffer_for_size matches "BufferSize" to "Buffer" by
    name, so with no names nothing pairs, and a size argument is bounded by a blanket
    constant instead of by the allocation it describes. resize_paired_buffer then never
    runs, and the redzone that makes an overflow visible is never put where the callee
    was told the buffer ends.

    A protocol's GUID names the header its declarations live in, and the harness input
    gives the GUID for each function, so the two meet here. They are matched by position,
    because with param_name empty there is nothing else to match on.
    """
    global OPTIONAL_INFO_AVAILABLE
    owner = {}
    for entries in harness_functions.values():
        for function, guid in entries:
            if guid:
                owner[function] = guid

    named = marked = optional = 0
    for function, blocks in data.items():
        params = optional_params.get(owner.get(function, ''), {}).get(function)
        if not params:
            continue
        for block in blocks:
            for key, arguments in block.arguments.items():
                where = ARG_INDEX.match(key)
                if not where:
                    continue
                index = int(where.group(1))
                if index >= len(params):
                    continue
                name, accepts_null = params[index]
                for argument in arguments:
                    if not argument.param_name:
                        argument.param_name = name
                        named += 1
                    argument.is_optional = accepts_null
                    marked += 1
                    optional += 1 if accepts_null else 0
    if marked:
        OPTIONAL_INFO_AVAILABLE = True
        print(f'INFO: read {marked} argument(s) from their declarations -- named {named}, '
              f'{optional} of which the callee accepts NULL for')
    return marked


def sort_data(input_data: Dict[str, List[FunctionBlock]],
              harness_functions: Dict[str, List[Tuple[str, str]]],
              best_guess: bool,
              function_decl: Dict[str, Tuple[str, str]]) -> Dict[str, List[FunctionBlock]]:
    
    filtered_data = defaultdict(list)

    if len(input_data) > 0:
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
            if param_counts.most_common(1)[0][1] < math.floor(len(input_data[function]) / 2):
                print(f'WARNING: {function} has too many different parameter counts to be harnessed!!')
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
        for function, arg_num_pairs in sorted_data.items():
            # the call site carries the protocol struct in Arg_0, which separates a
            # Configure on the requested protocol from a Configure on any other one that
            # shares the name. that is a tie-breaker among same-named candidates rather
            # than an absolute gate: edk2 puts the same guid on aliased protocols
            # (FirmwareVolumeBlock and FirmwareVolumeBlock2), so when the struct rejects
            # every group for a requested function, fall back to matching on name alone
            groups = list(arg_num_pairs.values())
            strict = any(harness_match(function, pair, blocks[0] if blocks else None)
                         for blocks in groups
                         for pairs in harness_functions.values() for pair in pairs)
            for function_blocks in groups:
                observed = function_blocks[0] if function_blocks else None
                # the relaxation exists for aliased protocols, where Arg_0 is some other
                # protocol struct. it must not admit a same-named function that is not a
                # protocol member at all: BaseMemoryLib's CopyMem(dest, src, len) leads
                # with a void*, and letting it through displaced the real PCI IO member
                if not strict and normalize_struct(arg0_struct(observed)).endswith('PROTOCOL'):
                    observed = None
                if not any(harness_match(function, pair, observed) for pairs in harness_functions.values() for pair in pairs):
                    print(f'WARNING: {function} is not in the harness functions list!!')
                    continue
                arg_num_match = False
                for function_block in function_blocks:
                    for key, item in services_map.items():
                        if key in function_block.service or item in function_block.service:
                            for harness_group in harness_functions[services_map[key]]:
                                if function in harness_group:
                                        # print(f'INFO: {function} with {key} parameters has been selected for harnessing!!')
                                        arg_num_match = True
                                        break
                        if arg_num_match:
                            break
                    if arg_num_match:
                        break
                if arg_num_match:
                    filtered_data.setdefault(function, []).extend(function_blocks)
                elif any(harness_match(function, pair, observed) for pair in harness_functions["OtherFunctions"]):
                    filtered_data.setdefault(function, []).extend(function_blocks)
        if best_guess:
            for function, arg_num_pairs in sorted_data.items():
                for _, function_blocks in arg_num_pairs.items():
                    observed = function_blocks[0] if function_blocks else None
                    if not any(harness_match(function, pair, observed) for pairs in harness_functions.values() for pair in pairs):
                        continue
                    if function in filtered_data.keys():
                        break
                    filtered_data.setdefault(function, []).extend(function_blocks)
                
    # loop through the filtered data and add the function_decl function if it is not already in the filtered_data
    for function, candidates in function_decl.items():
        if function not in filtered_data.keys():
            # only a declaration the user actually asked for may become a target. this
            # used to append unconditionally, so when the analysis found no call sites
            # for the requested protocol the generator still built a harness out of
            # whatever else was declared -- which is how a request for EfiKms produced
            # code against struct _EFI_IP4_PROTOCOL
            matched_service = None
            matched_guid = ""
            function_info = None
            # every declaration sharing this name is tried: Reset is declared by many
            # protocols, and only one of them is the one being harnessed
            for key, value in harness_functions.items():
                for pair in value:
                    for candidate in (candidates if isinstance(candidates, list) else [candidates]):
                        if harness_match(function, pair, candidate):
                            function_info = candidate
                            matched_service = key
                            matched_guid = pair[1] if len(pair) > 1 else ""
                            break
                    if matched_service is not None:
                        break
                if matched_service is not None:
                    break
            if matched_service is None:
                continue
            if function_info.service == "" or function_info.service is None:
                function_info.service = matched_service

            # the declaration pass marks the first parameter of anything declared in a
            # protocol header as __PROTOCOL__, whatever its type. that is wrong for a
            # protocol whose members do not take This: EFI_SHELL_PROTOCOL declares
            # RemoveDupInFileList(EFI_SHELL_FILE_INFO **FileList), and treating the file
            # list as the protocol both mistyped the located pointer and dropped the only
            # real argument the call has
            first = function_info.arguments.get('Arg_0')
            protocol_name = guid_protocol_name.get(matched_guid)
            # a same-named declaration from somewhere else is not this protocol's member
            header = guid_header.get(matched_guid)
            if protocol_name and header:
                arity = protocol_member_arity(header, protocol_name, function)
                if arity is not None and arity != len(function_info.arguments):
                    print(f'WARNING: {function} declaration takes '
                          f'{len(function_info.arguments)} argument(s) but '
                          f'{protocol_name}.{function} takes {arity}!!')
                    continue
                # the declaration's parameter types can disagree with the protocol's own
                # typedef. EFI_EXT_SCSI_PASS_THRU_PROTOCOL.BuildDevicePath takes
                # EFI_DEVICE_PATH_PROTOCOL **DevicePath, and a declaration recording one
                # level less made the harness pass the pointer where its address is wanted.
                # only the pointer depth is corrected, so a merely differently spelled type
                # is left alone
                declared_params = protocol_member_params(header, protocol_name, function)
                if declared_params and len(declared_params) == len(function_info.arguments):
                    ordered = sorted(function_info.arguments, key=natural_sort_key)
                    for arg_name, spec in zip(ordered, declared_params):
                        true_type = param_type(spec)
                        if not true_type:
                            continue
                        qualified = param_type_qualified(spec)
                        declared_name = param_name(spec)
                        for argument in function_info.arguments[arg_name]:
                            if declared_name:
                                argument.param_name = declared_name
                            if true_type.count('*') != argument.arg_type.count('*'):
                                argument.arg_type = true_type
                                argument.pointer_count = true_type.count('*')
                            # keep CONST on the type itself: a dynamic attribute does not
                            # survive collect_all_function_arguments rebuilding the
                            # Argument, and declare_var already maps a void type to UINTN*
                            # and a const one to a const pointer, both of which are
                            # assignable through the casts the harness already emits
                            if qualified != true_type and qualified.count('*') >= 2:
                                argument.arg_type = qualified
                                argument.pointer_count = qualified.count('*')
            if first and protocol_name and first[0].variable == "__PROTOCOL__":
                if normalize_struct(remove_ref_symbols(first[0].arg_type)) != normalize_struct(protocol_name):
                    first[0].variable = ""
            block = FunctionBlock(function_info.arguments, function,
                                  function_info.service, function_info.includes,
                                  function_info.return_type)
            # the declaration's return type is not always the member's, and the protocol's
            # own typedef is the authority for what the call site can assign
            if protocol_name and header:
                block.return_type = protocol_member_return(header, protocol_name, function)
                # how the harness has to write the call: EFI_CPU_IO2_PROTOCOL reaches
                # Read through Mem and Io, and the call site it was learned from said
                # so -- "mCpuIo->Mem.Read(...)" -- but only the leaf name survives the
                # analysis, so the path is recovered from the header here
                paths = nested_member_paths(header, protocol_name, function)
                if paths:
                    block.member_paths = paths
            # remember how to reach the protocol even when no parameter carries it, so the
            # harness can still locate it for a member declared as (VOID)
            if protocol_name and matched_guid:
                block.protocol_type = f'{protocol_name} *'
                block.protocol_guid = matched_guid
                # nothing else in the harness references this protocol, so its header
                # would not otherwise be included and the type would be undeclared
                header = guid_header.get(matched_guid)
                if header:
                    all_includes.add(header)
            filtered_data[function].append(block)
            # all_includes.update(function_info.includes)

    # A protocol member is a function pointer inside the struct, so the declaration pass
    # never records it as a function. When the analysis found no call sites the only
    # same-named declarations belong to unrelated drivers -- EFI_BLOCK_IO_PROTOCOL's Reset
    # rather than EFI_USB_HC_PROTOCOL's. Build the missing ones from the header, which is
    # the authoritative description of what the member takes.
    synthesised = 0
    for service, pairs in harness_functions.items():
        for pair in pairs:
            name = pair[0]
            guid = pair[1] if len(pair) > 1 else ""
            if not guid or name in filtered_data:
                continue
            protocol_name = guid_protocol_name.get(guid)
            header = guid_header.get(guid)
            if not (protocol_name and header):
                continue
            # a header the include pipeline refuses cannot declare the protocol type
            trimmed = cleanup_paths([header])
            if not trimmed or trimmed[0] in unusable_includes:
                continue
            params = protocol_member_signature(header, protocol_name, name)
            # an empty list is a member declared (VOID) and still worth harnessing
            if params is None:
                continue
            arguments = {}
            for arg_key, arg_type, direction, declared_name in params:
                is_self = (arg_key == 'Arg_0'
                           and normalize_struct(remove_ref_symbols(arg_type))
                           == normalize_struct(protocol_name))
                arguments[arg_key] = [Argument(direction, arg_type, "", arg_type,
                                               guid if is_self else "",
                                               "__PROTOCOL__" if is_self else "",
                                               param_name=declared_name)]
            block = FunctionBlock(arguments, name, service, [header],
                                  protocol_member_return(header, protocol_name, name))
            block.protocol_type = f'{protocol_name} *'
            block.protocol_guid = guid
            paths = nested_member_paths(header, protocol_name, name)
            if paths:
                block.member_paths = paths
            filtered_data[name].append(block)
            all_includes.add(header)
            synthesised += 1
    if synthesised:
        print(f'INFO: {synthesised} protocol member(s) built from their header!!')

    return filtered_data

#
# Load in the function call database and perform frequency analysis across
# the function calls to make sure to only keep the function calls that have
# the same type of input args
#
# The order the firmware itself calls things in.
#
# Which call should open a sequence was a guess from its name -- Configure, Open, Start and
# so on. That misses anything named differently: EFI_DISK_IO2_PROTOCOL's WriteDiskEx runs
# before ReadDiskEx in FatQueueTask, and neither name looks like setup. The analyzer now
# records the body each call sits in and its position, so pairs seen in the same body give
# a real precedence instead of a naming convention.
def observed_precedence(data_file):
    """Function names ranked by how often each runs before the others."""
    try:
        with open(data_file, 'r') as handle:
            raw = json.load(handle) or []
    except (OSError, ValueError):
        return []
    bodies = defaultdict(list)
    for record in raw:
        if not isinstance(record, dict):
            continue
        body = record.get('EnclosingFunction')
        if not body:
            continue
        bodies[(record.get('EnclosingFile'), body)].append(
            (record.get('CallOrder', 0), record.get('Function')))
    score = Counter()
    for calls in bodies.values():
        calls.sort()
        for index, (_order, earlier) in enumerate(calls):
            for _later_order, later in calls[index + 1:]:
                if earlier and later and earlier != later:
                    score[earlier] += 1
                    score[later] -= 1
    if not score:
        return []
    return [name for name, _ in score.most_common()]


def arg_shape(function_block) -> Tuple[str, ...]:
    """The set of argument keys a recorded call site carries."""
    return tuple(sorted(function_block.arguments.keys()))


def is_complete_shape(shape: Tuple[str, ...]) -> bool:
    """True when the keys really are Arg_0..Arg_n-1 with nothing missing."""
    indices = []
    for key in shape:
        match = ARG_INDEX.match(key)
        if match is None:
            return False
        indices.append(int(match.group(1)))
    return sorted(indices) == list(range(len(indices)))


def member_guid(function: str, harness_functions: Dict[str, List[Tuple[str, str]]]) -> str:
    """The GUID the request file asked this member under, if it named one."""
    for pairs in harness_functions.values():
        for pair in pairs:
            if pair and pair[0] == function and len(pair) > 1 and pair[1]:
                return pair[1]
    return ""


def fill_shape_holes(function: str,
                     function_blocks: List[FunctionBlock],
                     harness_functions: Dict[str, List[Tuple[str, str]]]) -> List[FunctionBlock]:
    """Put back an argument the analysis lost, from the protocol's own prototype.

    VIRTIO_DEVICE_PROTOCOL.WriteDevice takes (This, FieldOffset, FieldSize, Value) and is
    recorded at every one of its call sites without Arg_1 -- the analyser does not keep
    the OFFSET_OF() the callers pass there. A template with a hole in it emits a call with
    one argument too few, which is a compile error at best and the wrong call at worst, so
    the missing slot is taken from the member's declaration in its own protocol header.
    That is the same source the synthesised-member path already trusts, and
    protocol_member_signature returns None for a variadic member, so nothing is invented
    for a "..." the header does not describe.
    """
    shape = arg_shape(function_blocks[0])
    if is_complete_shape(shape):
        return function_blocks
    guid = member_guid(function, harness_functions)
    protocol_name = guid_protocol_name.get(guid)
    header = guid_header.get(guid)
    if not (protocol_name and header):
        return function_blocks
    params = protocol_member_signature(header, protocol_name, function)
    if not params:
        return function_blocks
    declared = {arg_key: (arg_type, direction, declared_name)
                for arg_key, arg_type, direction, declared_name in params}
    # only fill a shape the prototype actually covers: a recorded argument the declaration
    # has no slot for means this is not the member it looks like, and the record stands
    if not set(shape) <= set(declared):
        return function_blocks
    missing = sorted(set(declared) - set(shape),
                     key=lambda key: int(ARG_INDEX.match(key).group(1)))
    if not missing:
        return function_blocks
    for block in function_blocks:
        for arg_key in missing:
            arg_type, direction, declared_name = declared[arg_key]
            is_self = (arg_key == 'Arg_0'
                       and normalize_struct(remove_ref_symbols(arg_type))
                       == normalize_struct(protocol_name))
            block.arguments[arg_key] = [Argument(direction, arg_type, "", arg_type,
                                                 guid if is_self else "",
                                                 "__PROTOCOL__" if is_self else "",
                                                 param_name=declared_name)]
        # the harness emits the call in the order this dict iterates, so a slot appended
        # after the ones that follow it would pass the arguments in the wrong order
        block.arguments = {key: block.arguments[key]
                           for key in sorted(block.arguments,
                                             key=lambda k: int(ARG_INDEX.match(k).group(1))
                                             if ARG_INDEX.match(k) else 0)}
    print(f'INFO: {function} was recorded without {", ".join(missing)}; taking '
          f'{"it" if len(missing) == 1 else "them"} from {protocol_name} in {header}')
    return function_blocks


def keep_one_arg_shape(filtered_function_dict: Dict[str, List[FunctionBlock]],
                       harness_functions: Dict[str, List[Tuple[str, str]]]) -> Dict[str, List[FunctionBlock]]:
    """One argument shape per function, so the template and its call sites agree.

    sort_data groups a function's call sites by argument count and keeps every group that
    matches the request, so one function's list can hold sites of different shapes: a
    variadic member is recorded with six arguments at one site and seven at another
    (EFI_S3_SAVE_STATE_PROTOCOL.Write), and a site whose analysis lost an argument leaves
    a hole (VIRTIO_DEVICE_PROTOCOL.ReadDevice came back as Arg_0, Arg_2, Arg_3, Arg_4).

    Everything downstream reads one template per function and indexes it by whatever key a
    call site carries. A foreign shape therefore either killed the whole campaign --
    "TypeError: 'NoneType' object is not subscriptable" out of load_data, no harness, no
    coverage -- or, when the template happened to be the larger shape, silently merged one
    site's argument into another site's slot and passed it to the firmware.

    So keep the sites that share the template's shape. The template stays the first block,
    as before, unless its keys have a hole in them: a hole is a lost record rather than a
    real overload, and harnessing it would drop an argument from the call.
    """
    for function, function_blocks in filtered_function_dict.items():
        if not function_blocks:
            continue
        shapes = {arg_shape(block) for block in function_blocks}
        if len(shapes) == 1:
            filtered_function_dict[function] = fill_shape_holes(
                function, function_blocks, harness_functions)
            continue
        chosen = arg_shape(function_blocks[0])
        if not is_complete_shape(chosen):
            for block in function_blocks:
                if is_complete_shape(arg_shape(block)):
                    chosen = arg_shape(block)
                    break
        kept = [block for block in function_blocks if arg_shape(block) == chosen]
        print(f'INFO: {function} was recorded with {len(shapes)} different argument '
              f'shapes; harnessing the {len(chosen)}-argument one, seen at {len(kept)} of '
              f'{len(function_blocks)} call site(s)')
        filtered_function_dict[function] = fill_shape_holes(
            function, kept, harness_functions)
    return filtered_function_dict


def load_data(json_file: str,
              harness_functions: Dict[str, List[Tuple[str, str]]],
              macros: Dict[str, Macros],
              random: bool,
              best_guess: bool,
              function_decl: Dict[str, Tuple[str, str]]) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock]]:

    with open(json_file, 'r') as file:
        # firness writes a bare "null" when it recorded no call sites, and the declaration
        # fallback further down still builds harnesses in that case
        raw_data = json.load(file) or []

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        # the try sits inside the loop on purpose: wrapping the loop meant a single
        # malformed entry aborted it and silently discarded every call site recorded
        # after that point
        try:
            arguments = {
                arg_key: [Argument(**note_optional_info(raw_argument))]
                # a recorded "Arguments": null reaches get() as None, which the default
                # argument does not cover
                for arg_key, raw_argument in (raw_function_block.get('Arguments') or {}).items()
            }
            if random:
                for arg_key, argument in arguments.items():
                    if argument[0].variable in known_contant_variables:
                        argument[0].variable = ""
            function_block = FunctionBlock(arguments, raw_function_block.get(
                'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
            function_dict[function_block.function].append(function_block)
        except Exception as e:
            print(f'ERROR: {e}')

    # Check if there is a single most common number of parameters for each function
    # and if not then take the one which has a service matching the harness_functions.keys()
    # note that if RT is in the service name, then it is a runtime service and BS is a boot service
    filtered_function_dict = sort_data(function_dict, harness_functions, best_guess, function_decl)
    # one shape per function before anything indexes the template by a call site's keys
    filtered_function_dict = keep_one_arg_shape(filtered_function_dict, harness_functions)

    void_star_data_type_counter = defaultdict(Counter)
    function_template = {}

    # Collect data_type statistics for arg_type of "void *"
    for function, function_blocks in filtered_function_dict.items():
        if function not in function_template:
            function_template[function] = function_blocks[0]        
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if remove_ref_symbols(function_template[function].arguments.get(arg_key)[0].arg_type) in type_defs.values():
                    for name, type_def in type_defs.items():
                        if type_def == remove_ref_symbols(function_template[function].arguments.get(arg_key)[0].arg_type):
                            function_template[function].arguments.get(
                                arg_key)[0].arg_type = name
                    # function_template[function].arguments.get(
                    #     arg_key)[0].arg_type = argument[0].arg_type
                if argument[0].variable == "__FUNCTION_PTR__":
                    for function_block2 in function_blocks:
                        function_block2.arguments.get(arg_key)[0].variable = "__FUNCTION_PTR__"
                        function_block2.arguments.get(arg_key)[0].data_type = argument[0].arg_type
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
                argument[0].arg_type = function_template[function].arguments.get(arg_key)[0].arg_type

    return filtered_function_dict, function_template

def load_generators(json_file: str,
                    macros: Dict[str, Macros]) -> Dict[str, List[FunctionBlock]]:

    if os.stat(json_file).st_size <= 4:
        print("WARNING: No generator functions were captured!!\n")
        return defaultdict(list)
    
    with open(json_file, 'r') as file:
        raw_data = json.load(file)            

    function_dict = defaultdict(list)
    for raw_function_block in raw_data:
        arguments = {
            arg_key: [Argument(**note_optional_info(raw_argument))]
            # a recorded "Arguments": null reaches get() as None, which the default does
            # not cover, and there is no handler here to absorb it
            for arg_key, raw_argument in (raw_function_block.get('Arguments') or {}).items()
        }
        function_block = FunctionBlock(arguments, raw_function_block.get(
            'Function'), raw_function_block.get('Service'), raw_function_block.get('Include'), raw_function_block.get('ReturnType'))
        if function_block.service == "protocol":
            function_dict[f'{remove_ref_symbols(function_block.arguments["Arg_0"][0].arg_type)}:{function_block.function}'].append(function_block)
        else:
            function_dict[function_block.function].append(function_block)

    # Determine the most common number of parameters for each function
    # most_common_param_counts = {}
    # for function, function_blocks in function_dict.items():
    #     param_counts = Counter(len(fb.arguments) for fb in function_blocks)
    #     most_common_param_counts[function] = param_counts.most_common(1)[0][0]

    # # Filter the function_dict to only include FunctionBlock instances with the most common number of parameters
    # filtered_function_dict = {function: [fb for fb in function_blocks if len(fb.arguments) == most_common_param_counts[function]]
    #                           for function, function_blocks in function_dict.items()}
    filtered_function_dict = function_dict

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
# "TPL_NOTIFY", "(TPL_NOTIFY)" and " TPL_NOTIFY " are all a single identifier; "16",
# "TPL_NOTIFY + 1" and "sizeof (X)" are not.
#
def is_bare_identifier(value: str) -> bool:
    value = (value or "").strip()
    while value.startswith('(') and value.endswith(')'):
        depth = 0
        for index, character in enumerate(value):
            if character == '(':
                depth += 1
            elif character == ')':
                depth -= 1
                # the opening paren closes before the end, so the parens are not a wrapper
                if depth == 0 and index != len(value) - 1:
                    return bool(re.fullmatch(r'[A-Za-z_]\w*', value))
        value = value[1:-1].strip()
    return bool(re.fullmatch(r'[A-Za-z_]\w*', value))

#
# Load Macros
#
def load_macros(json_file: str) -> Tuple[Dict[str, Macros], Dict[str, Macros]]:
    with open(json_file, 'r') as file:
        raw_data = json.load(file)
    macros_val = defaultdict()
    macros_name = defaultdict()
    for macro in raw_data:
        macros_name[macro["Name"]] = Macros(**macro)
    # macros_val is the reverse map: load_data and load_generators use it to turn a value
    # a call site was recorded passing into the name of a macro that spells it. That is
    # worth doing for a literal, and never for a value that is already a symbolic name --
    # an alias macro like "#define XHC_TPL TPL_NOTIFY" would otherwise claim the key
    # "TPL_NOTIFY" and rewrite every recorded TPL_NOTIFY into XHC_TPL. Four private driver
    # headers alias TPL_NOTIFY that way (EHC_TPL, UHCI_TPL, USB_BUS_TPL, XHC_TPL), the
    # last one loaded wins, and the harness is left naming a constant that only
    # MdeModulePkg/Bus/Pci/XhciDxe/Xhci.h defines.
    for macro in raw_data:
        if is_bare_identifier(macro["Value"]):
            continue
        macros_val[macro["Value"]] = Macros(**macro)
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


def variable_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                      types: Dict[str, TypeInfo],
                      pre_processed_data: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      macros: Dict[str, Macros],
                      random: bool) -> Dict[str, FunctionBlock]:
    # for all of the functionblock argument data_types, check the types structure for the matching type
    # if the type is found and all of the fields are scalars, then add it to the create a new argument
    # and have the variable be __FUZZABLE_STRUCT__ and add it to the list
    contains_fuzzable_struct = defaultdict(lambda: defaultdict(lambda: False))

    # Add a check to not add an argument if the is already an argument of the variable name __FUZZABLE__
    # and a check to make sure that the variable name isn't __FUZZABLE_ARG_STRUCT__
    for function, function_blocks in input_data.items():
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                added_struct = False
                if len(pre_processed_data[function].arguments.setdefault(arg_key, [])) > 0:
                    if any('__FUZZABLE__' in var.variable or '__ENUM_ARG__' in var.variable or 'EFI_EVENT' in var.arg_type or "void" in remove_ref_symbols(get_underlying_type(var.arg_type, aliases, macros)) for var in pre_processed_data[function].arguments.get(arg_key)):
                        continue

                if argument[0].arg_dir == "IN" and not contains_fuzzable_struct[function][arg_key] and (arg_key not in current_args_dict[function]):
                    if not contains_void_star(argument[0].arg_type):
                        if is_fuzzable(remove_ref_symbols(argument[0].arg_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_ARG_STRUCT__", argument[0].potential_outputs,
                                                  param_name=argument[0].param_name,
                                                  is_optional=argument[0].is_optional)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            added_struct = True
                            contains_fuzzable_struct[function][arg_key] = True
                    if not contains_void_star(argument[0].data_type) and not added_struct:
                        if is_fuzzable(remove_ref_symbols(argument[0].data_type), aliases, types, 0):
                            struct_arg = Argument(argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type,
                                                  argument[0].usage, "__FUZZABLE_DATA_STRUCT__", argument[0].potential_outputs,
                                                  param_name=argument[0].param_name,
                                                  is_optional=argument[0].is_optional)
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(struct_arg)
                            current_args_dict[function].append(arg_key)
                            contains_fuzzable_struct[function][arg_key] = True

    return pre_processed_data

#
# search the enum list for a matching type or assignment/usage
#
def find_enum(argument: Argument, enums: Dict[str, EnumDef]) -> str:
    for enum_name, enum_values in enums.items():
        if argument.arg_type.lower() in enum_name.lower():
            all_includes.add(enum_values.file)
            return enum_name
        elif any(value.lower() in argument.assignment.lower() or value in argument.usage.lower() for value in enum_values.values):
            all_includes.add(enum_values.file)
            return enum_name
    return argument.usage


#
# Filters out any arguments that are not IN and CONSTANT values, but making sure
# to not keep duplicates
#
def collect_known_constants(input_data: Dict[str, List[FunctionBlock]],
                            pre_processed_data: Dict[str, FunctionBlock],
                            macros: Dict[str, Macros],
                            aliases: Dict[str, str],
                            types: Dict[str, TypeInfo],
                            enums: Dict[str, List[str]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Keeps track of arg.usage values seen for each function and arg_key
    usage_seen = defaultdict(lambda: defaultdict(list))
    matched_macros = defaultdict(list)
    protocol_guids = set()
    driver_guids = set()

    # Step 1: Collect all arguments
    for function, function_blocks in input_data.items():
        first_sizeof = defaultdict(lambda: True)
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") :
                    # only want to add different enums once
                    if argument[0].variable == "__ENUM_ARG__": 
                        argument[0].usage = find_enum(argument[0], enums)
                        if argument[0].usage not in usage_seen[function][arg_key]:
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(argument[0])
                            # current_args_dict[function].append(arg_key)
                            usage_seen[function][arg_key].append(argument[0].usage)
                    # only want to add EFI_HANDLE once
                    elif ("EFI_HANDLE" in argument[0].arg_type or "EFI_HANDLE" in get_underlying_type(argument[0].arg_type, aliases, macros) ) and usage_seen[function][arg_key] == []:
                        argument[0].variable = "__HANDLE__"
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(argument[0])
                        # current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].append(argument[0].usage)
                    # only need to add one protocol varibale to the harness
                    elif argument[0].variable == "__PROTOCOL__":
                        # if the assignment is LocatedProtocol then find the protocol guid from the assignment:
                        # gBS->LocateProtocol ( &gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID **)&mUnicodeCollation )
                        if "locateprotocol" in argument[0].assignment.lower():
                            try:
                                protocol_guids.add(argument[0].assignment.split('->')[1].split('(')[1].split(',')[0].strip()[1:])
                            except:
                                print(f'ERROR: {function} has a protocol assignment that could not be parsed!!')
                                print(f'ERROR: {argument[0].assignment}')
                        if usage_seen[function][arg_key] == []:
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(argument[0])
                            # current_args_dict[function].append(arg_key)
                            # save the file that the protocol is defined in
                            all_includes.add(types.get(remove_ref_symbols(argument[0].arg_type), TypeInfo()).file)
                            usage_seen[function][arg_key].append(argument[0].usage)
                    # add all contant values, but only one if its a sizeof(UINTN)
                    elif ("__CONSTANT" in argument[0].variable and "__CONSTANT_" != argument[0].variable) and argument[0].usage not in usage_seen[function][arg_key]:
                        if "__CONSTANT_SIZEOF__" in argument[0].variable:
                            if not first_sizeof[arg_key]:
                                continue
                            else:
                                first_sizeof[arg_key] = False
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(argument[0])
                        # current_args_dict[function].append(arg_key)
                        usage_seen[function][arg_key].append(argument[0].usage)
                    # check if it is a guid
                    elif 'guid' in argument[0].arg_type.lower() and argument[0].variable.startswith('g') and argument[0].variable.endswith('Guid'):
                        if 'protocolguid' in argument[0].variable.lower():
                            # Add to the protocol_guids set
                            protocol_guids.add(argument[0].variable)
                        else:
                            # Add to the driver_guids set
                            if argument[0].usage != "":
                                driver_guids.add(argument[0].variable)
                        if argument[0].usage not in usage_seen[function][arg_key]:
                            guid_arg = copy.copy(argument[0])
                            guid_arg.variable = "__GUID__"
                            pre_processed_data[function].arguments.setdefault(
                                arg_key, []).append(guid_arg)
                            # current_args_dict[function].append(arg_key)
                            usage_seen[function][arg_key].append(guid_arg.usage)
                    # If there are multiple potential outputs, then add each one this would happen if there was masking
                    elif len(argument[0].potential_outputs) > 1:
                        for argument_value in argument[0].potential_outputs:
                            if not contains_usage(argument_value, usage_seen[function][arg_key], macros, aliases):
                                new_arg = Argument(argument[0].arg_dir, argument[0].arg_type, argument[0].assignment,
                                                   argument[0].data_type, argument_value, argument[0].variable, [],
                                                   param_name=argument[0].param_name,
                                                   is_optional=argument[0].is_optional)
                                pre_processed_data[function].arguments.setdefault(
                                    arg_key, []).append(new_arg)
                                if argument[0].assignment in macros.keys():
                                    matched_macros[macros[argument[0].assignment]
                                                   .name] = macros[argument[0].assignment].value
                                    all_includes.add(macros[argument[0].assignment].file)
                                # current_args_dict[function].append(arg_key)
                                usage_seen[function][arg_key].append(
                                    get_stripped_usage(argument_value, macros, aliases))
                    # elif not contains_usage(argument[0].usage, usage_seen[function][arg_key], macros, aliases):
                    #     pre_processed_data[function].arguments.setdefault(
                    #         arg_key, []).append(argument[0])
                    #     if argument[0].assignment in macros.keys():
                    #         matched_macros[macros[argument[0].assignment]
                    #                        .name] = macros[argument[0].assignment].value
                    #     current_args_dict[function].append(arg_key)
                    #     usage_seen[function][arg_key].append(get_stripped_usage(
                    #         argument[0].usage, macros, aliases))  # Update the set with the new arg.usage value
    # Step 2: Filter out arguments with less than 3 different values
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) < 3 and (argument[0].variable != "__ENUM_ARG__" and argument[0].variable != "__PROTOCOL__" and argument[0].variable != "__HANDLE__" and argument[0].variable != "__GUID__"):
                for arg in argument:
                    argument.remove(arg)
                # current_args_dict[function].remove(arg_key)
    return pre_processed_data, matched_macros, protocol_guids, driver_guids

def get_underlying_type(data_type: str, 
                        aliases: Dict[str, str], 
                        macros: Dict[str, Macros]) -> str:
    underlying_type = data_type
    while remove_ref_symbols(underlying_type) in aliases.keys() or remove_ref_symbols(underlying_type) in macros.keys():
        if remove_ref_symbols(underlying_type) in aliases.keys():
            underlying_type = aliases[remove_ref_symbols(underlying_type)]
        elif remove_ref_symbols(underlying_type) in macros.keys():
            underlying_type = macros[remove_ref_symbols(underlying_type)].value
    return underlying_type

#
# Get fuzzable saves the arguments that take scalar inputs and also saves void * inputs that vary argument type
# by more than 5 since the assumption is that means the function is most likely manipulating data, not structures
# themselves. There is another exception if both the input argument and expected argument are both void * then
# it will treat is as fuzzable since it is most likely passing in a physical address.
#
def get_directly_fuzzable(input_data: Dict[str, List[FunctionBlock]],
                          pre_processed_data: Dict[str, FunctionBlock],
                          aliases: Dict[str, str],
                          macros: Dict[str, Macros],
                          random: bool) -> Dict[str, FunctionBlock]:

    for function, function_blocks in input_data.items():
        void_star_data_type_counter = defaultdict(Counter)
        only_void_star = {}
        

        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if not only_void_star.get(arg_key, False):
                    only_void_star[arg_key] = False
                if contains_void_star(argument[0].arg_type) and contains_void_star(argument[0].data_type):
                    only_void_star[arg_key] = True
                elif contains_void_star(argument[0].arg_type) and aliases.get(remove_ref_symbols(argument[0].arg_type), "") == "":
                    only_void_star[arg_key] = True
                elif contains_void_star(argument[0].arg_type):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
                elif contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower()):
                    void_star_data_type_counter[arg_key].update(
                        [argument[0].data_type])
        for function_block in function_blocks:
            for arg_key, argument in function_block.arguments.items():
                if (argument[0].arg_dir == "IN" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                    arg_type = remove_ref_symbols(argument[0].arg_type)
                    is_scalable = any(param.lower() in arg_type.lower() or param.lower() in get_underlying_type(arg_type, aliases, macros).lower() for param in scalable_params)
                    # if the argument is a fuzzable parameter, then add it to the pre_processed_data
                    if is_scalable:
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__",
                            param_name=argument[0].param_name)
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the argument is a void * and the data_type is not a void * and the data_type is not a scalar
                    elif (contains_void_star(argument[0].arg_type) or contains_void_star(aliases.get(remove_ref_symbols(argument[0].arg_type), "").lower())) and (len(void_star_data_type_counter[arg_key]) > math.floor(len(function_blocks)/2) or random):
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__",
                            param_name=argument[0].param_name)
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the data type is scalable because the function is expecting a void so no futher an
                    elif any(param.lower() in argument[0].data_type or param.lower() in aliases.get(argument[0].data_type, "").lower() for param in scalable_params) and contains_void_star(argument[0].arg_type):
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__",
                            param_name=argument[0].param_name)
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue
                    # if the argument is a void * and the data_type is a void *
                    elif only_void_star[arg_key]:
                        scalable_arg = Argument(
                            argument[0].arg_dir, argument[0].arg_type, "", argument[0].data_type, argument[0].usage, "__FUZZABLE__",
                            param_name=argument[0].param_name)
                        current_args_dict[function].append(arg_key)
                        pre_processed_data[function].arguments.setdefault(
                            arg_key, []).append(scalable_arg)
                        continue

    return pre_processed_data



# the callee of a recorded assignment expression, e.g.
#   "PciIo->AllocateBuffer (PciIo, AllocateAnyPages, ..., &BufHost, 0)"  ->  AllocateBuffer
ASSIGNMENT_CALLEE = re.compile(r'(?:->|\.|\b)([A-Za-z_]\w*)\s*\(')


# VariableFlow already resolves, for each argument, the call that last wrote the variable
# being passed, and CallSiteAnalysis serialises it as source text in "assignment". That is
# a real producer/consumer edge observed in the firmware, and nothing downstream used it:
# generator selection is purely type based, and it skips anything void shaped, which is
# exactly the shape an OUT parameter of a buffer allocator has. This registers the observed
# producer as a generator choice for that argument.
def register_observed_producers(input_data: Dict[str, List[FunctionBlock]],
                                pre_processed_data: Dict[str, FunctionBlock],
                                generators: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    # generators for a protocol member are keyed "<STRUCT>:<Method>"
    by_name = {}
    for key in generators.keys():
        by_name.setdefault(key.split(':')[-1], key)

    # a producer that itself consumes the function it feeds would make the emitter inline
    # the pair into each other; the codegen has no depth limit, so refuse the cycle
    consumes = defaultdict(set)
    for consumer, blocks in input_data.items():
        for block in blocks:
            for arguments in block.arguments.values():
                for argument in arguments:
                    for callee in ASSIGNMENT_CALLEE.findall(argument.assignment or ''):
                        consumes[consumer].add(callee)

    added = 0
    for consumer, blocks in input_data.items():
        if consumer not in pre_processed_data:
            continue
        for block in blocks:
            for arg_key, arguments in block.arguments.items():
                for argument in arguments:
                    if argument.arg_dir != "IN":
                        continue
                    for callee in ASSIGNMENT_CALLEE.findall(argument.assignment or ''):
                        key = by_name.get(callee)
                        if key is None or callee == consumer:
                            continue
                        if consumer in consumes[callee]:
                            continue
                        producer = generators[key]
                        # only when the producer really yields this type, either directly
                        # or through one more level of indirection
                        base = remove_ref_symbols(argument.arg_type)
                        fits = any(out[0].arg_dir == "OUT"
                                   and remove_ref_symbols(out[0].arg_type) == base
                                   and out[0].pointer_count in (argument.pointer_count,
                                                                argument.pointer_count + 1)
                                   for out in producer.arguments.values())
                        if not fits:
                            continue
                        existing = pre_processed_data[consumer].arguments.get(arg_key, [])
                        if any(e.variable == "__GENERATOR_FUNCTION__" and e.assignment == key
                               for e in existing):
                            continue
                        pre_processed_data[consumer].arguments.setdefault(arg_key, []).append(
                            Argument(argument.arg_dir, argument.arg_type, key,
                                     argument.data_type, argument.usage,
                                     "__GENERATOR_FUNCTION__"))
                        all_includes.update(producer.includes or [])
                        added += 1
                        break
    if added:
        print(f'INFO: {added} observed producer edge(s) reused as generators!!')
    return pre_processed_data


def get_generators(pre_processed_data: Dict[str, FunctionBlock],
                   generators: Dict[str, FunctionBlock],
                   input_data: Dict[str, List[FunctionBlock]],
                   aliases: Dict[str, str],
                   castings: Dict[str, List[str]],
                   types: Dict[str, TypeInfo]) -> Dict[str, FunctionBlock]:
    global total_generators
    matching_generators = {}  # Dictionary to store the matching generators
    for func_name, generator_block in generators.items():
        for argument in generator_block.arguments.values():
            # Check if argument direction is OUT
            if argument[0].arg_dir == "OUT" and not any(param.lower() in argument[0].arg_type.lower() for param in scalable_params):
                # Look for a matching argument in function_template
                for func_temp_name, func_temp_blocks in input_data.items():
                    for func_temp_block in func_temp_blocks:
                        # Check if the function names are similar
                        similar = fuzz.ratio(func_name, func_temp_name)
                        if similar > 65:
                            continue
                        for ft_arg_key, ft_argument in func_temp_block.arguments.items():
                            if not contains_void_star(argument[0].arg_type):
                                # Check if argument types match and the argument is missing from known_inputs
                                if ((remove_ref_symbols(argument[0].arg_type) == remove_ref_symbols(ft_argument[0].arg_type) or remove_ref_symbols(argument[0].arg_type) in castings[remove_ref_symbols(ft_argument[0].arg_type)])and #ft_arg_key not in current_args_dict[func_temp_name] and
                                        ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                    # Add a check to make sure all of the input arguments are fuzzable
                                    all_fuzzable = True
                                    for ft_arg_key2, ft_argument2 in generator_block.arguments.items():
                                        if ft_argument2[0].arg_dir == "IN" and ft_arg_key2 not in current_args_dict[func_temp_name] and ft_argument2[0].variable != "__PROTOCOL__":
                                            if not is_fuzzable(remove_ref_symbols(ft_argument2[0].arg_type), aliases, types, 0) :
                                                all_fuzzable = False
                                                break
                                    # If matching generator is found, add it to the matching_generators dictionary
                                    if all_fuzzable:
                                        total_generators.add(func_name)
                                        matching_generators.setdefault(
                                            func_temp_name, []).append(func_name)
                                        generator_arg = Argument(
                                            ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__",
                                            param_name=ft_argument[0].param_name)
                                        # current_args_dict[func_temp_name].append(ft_arg_key)
                                        all_includes.update(generator_block.includes)
                                        pre_processed_data[func_temp_name].arguments.setdefault(
                                            ft_arg_key, []).append(generator_arg)
                                elif ((remove_ref_symbols(argument[0].arg_type) == remove_ref_symbols(ft_argument[0].data_type) or remove_ref_symbols(argument[0].arg_type) in castings[remove_ref_symbols(ft_argument[0].data_type)])and #ft_arg_key not in current_args_dict[func_temp_name] and
                                        ft_argument[0].arg_dir == "IN" and func_name not in matching_generators.setdefault(func_temp_name, [])):
                                    # Add a check to make sure all of the input arguments are fuzzable
                                    all_fuzzable = True
                                    for ft_arg_key2, ft_argument2 in generator_block.arguments.items():
                                        if ft_argument2[0].arg_dir == "IN" and ft_arg_key2 not in current_args_dict[func_temp_name]and ft_argument2[0].variable != "__PROTOCOL__":
                                            if not is_fuzzable(remove_ref_symbols(ft_argument2[0].data_type), aliases, types, 0) :
                                                all_fuzzable = False
                                                break
                                    # If matching generator is found, add it to the matching_generators dictionary
                                    if all_fuzzable:
                                        total_generators.add(func_name)
                                        matching_generators.setdefault(
                                            func_temp_name, []).append(func_name)
                                        generator_arg = Argument(
                                            ft_argument[0].arg_dir, ft_argument[0].arg_type, func_name, ft_argument[0].data_type, ft_argument[0].usage, "__GENERATOR_FUNCTION__",
                                            param_name=ft_argument[0].param_name)
                                        # current_args_dict[func_temp_name].append(ft_arg_key)
                                        all_includes.update(generator_block.includes)
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

# Now add the output variables because we aren't trying to fuzz those necessarily


def add_output_variables(function_template: Dict[str, FunctionBlock],
                         pre_processed_data: Dict[str, FunctionBlock]) -> Dict[str, FunctionBlock]:
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if (argument[0].arg_dir == "OUT" or argument[0].arg_dir == "IN_OUT") and (arg_key not in current_args_dict[function]):
                pre_processed_data[function].arguments.setdefault(
                    arg_key, []).append(argument[0])
                current_args_dict[function].append(arg_key)

    return pre_processed_data


def handle_optional_arguments(pre_processed_data: Dict[str, FunctionBlock],
                              function_template: Dict[str, FunctionBlock] = None) -> Dict[str, FunctionBlock]:
    for function, function_block in pre_processed_data.items():
        template = (function_template or {}).get(function)
        for arg_key, argument in function_block.arguments.items():
            if len(argument) == 0:
                # keep the parameter's real type. filling every unresolved argument with
                # "VOID *" made the call site pass NULL for things that are not pointers,
                # such as EFI_PCI_IO_PROTOCOL_WIDTH, which does not compile
                arg_type = "VOID *"
                if template is not None:
                    declared = template.arguments.get(arg_key)
                    if declared and declared[0].arg_type:
                        arg_type = declared[0].arg_type
                usage = "NULL" if '*' in arg_type else ""
                pre_processed_data[function].arguments[arg_key].append(
                    Argument("OPTIONAL", arg_type, usage, arg_type, usage, "__OPTIONAL__"))

    return pre_processed_data

def collect_all_function_arguments(input_data: Dict[str, List[FunctionBlock]],
                                   function_template: Dict[str, FunctionBlock],
                                   types: Dict[str, TypeInfo],
                                   input_generators: Dict[str, FunctionBlock],
                                   aliases: Dict[str, str],
                                   macros: Dict[str, Macros],
                                   enums: Dict[str, List[str]],
                                   casts: Dict[str, List[str]],
                                   random: bool,
                                   harness_functions: Dict[str, List[Tuple[str, str]]]) -> Tuple[Dict[str, FunctionBlock], Dict[str, str], set, set]:
    # Collect all of the arguments to be passed to the template
    pre_processed_data = initialize_data(function_template)
    pre_processed_data = get_intersect(input_data, pre_processed_data)
    matched_macros = {}

    if not random:
        # Step 1: Collect the constant arguments
        pre_processed_data, matched_macros, protocol_guids, driver_guids = collect_known_constants(
            input_data, pre_processed_data, macros, aliases, types, enums)
        print(f'INFO: Collecting known constants complete!!')
    else:
        protocol_guids = set()
        driver_guids = set()

    # Step 2: Collect the fuzzable arguments
    pre_processed_data = get_directly_fuzzable(
        input_data, pre_processed_data, aliases, macros, random)
    print(f'INFO: Collecting directly fuzzable arguments complete!!')

    if not random:
        # Step 3: collect the generator functions
        pre_processed_data = get_generators(
            pre_processed_data, input_generators, input_data, aliases, casts, types)
        print(f'INFO: Collecting generator functions complete!!')

        pre_processed_data = register_observed_producers(
            input_data, pre_processed_data, input_generators)

    # Step 4: Collect the fuzzable structs
    pre_processed_data = variable_fuzzable(
        input_data, types, pre_processed_data, aliases, macros, random)
    print(f'INFO: Collecting fuzzable structs complete!!')

    # Step 5: Add the output variables
    pre_processed_data = add_output_variables(
        function_template, pre_processed_data)
    print(f'INFO: Adding output variables complete!!')

    pre_processed_data = handle_optional_arguments(pre_processed_data, function_template)  
    print(f'INFO: Handling optional arguments complete!!')          

    # If there are still arguments missing then extend the level for fuzzable structs
    # continue recursively until all arguments have at least one input

    # missing_arg = True
    # while missing_arg:
    #     missing_arg = False
    #     for function, function_block in pre_processed_data.items():
    #         if len(pre_processed_data[function].arguments) < len(function_template[function].arguments):
    #             pre_processed_data = variable_fuzzable(
    #                 input_data, types, pre_processed_data, aliases, random)
    #             missing_arg = True

    # every name the harness is able to write down: the macros it can define or include,
    # the enum constants, and the type names that appear inside casts. protocol and driver
    # guids belong here too -- they are extern EFI_GUID globals rather than macros, and
    # their declaring header is already pulled in with the protocol
    # only types the harness can actually include: a driver-private struct is in the types
    # table but its header is outside any Include directory, so naming it in an expression
    # like "SNP_MEM_PAGES (sizeof (SNP_DRIVER))" does not compile
    includable_types = {name for name, info in types.items()
                        if cleanup_paths([getattr(info, 'file', '') or ''])}
    nameable = set(macros.keys()) | includable_types | set(aliases.keys()) | set(aliases.values())
    for enum_def in enums.values():
        nameable.update(getattr(enum_def, 'values', None) or [])
    nameable |= set(protocol_guids) | set(driver_guids)
    nameable.update(('sizeof', 'NULL', 'TRUE', 'FALSE', 'VOID', 'CONST', 'IN', 'OUT'))

    # Step 6: add the includes for constants/macro definitions, and drop a recorded usage
    # the harness has no way to name
    for function, function_block in pre_processed_data.items():
        for arg_key, arguments in function_block.arguments.items():
            for arg in arguments:
                # a usage that invokes a macro, "SNP_MEM_PAGES (4096)", never equals a
                # macro name, so the exact-name test below skips it and the invocation is
                # emitted with nothing declaring it. a function-like macro cannot be
                # redefined here either, since its parameter list was never recorded
                invoked = re.match(r'^\s*([A-Za-z_]\w*)\s*\(', arg.usage or '')
                if (invoked and invoked.group(1) in macros
                        and not cleanup_paths([macros[invoked.group(1)].file])):
                    arg.usage = ''
                for name in (arg.assignment, arg.usage):
                    if name not in macros.keys():
                        continue
                    macro = macros[name]
                    # the same test the include pipeline applies: a macro in a .c, or in a
                    # driver-private header outside any Include directory, cannot be
                    # reached by including its file, so define it in the harness instead
                    if cleanup_paths([macro.file]):
                        function_block.includes.append(macro.file)
                        # the per-function list is not folded into the harness include set
                        # (get_union is not called), so without this the constant is
                        # emitted with nothing declaring it
                        all_includes.add(macro.file)
                    else:
                        # a function-like macro is recorded without its parameter list, so
                        # defining it here produces
                        # "#define SNP_MEM_PAGES (((x) - 1) / 4096 + 1)" and any use of it
                        # leaves x undeclared. drop the usage and let the argument be fuzzed
                        if re.match(r'^\s*' + re.escape(macro.name) + r'\s*\(',
                                    arg.usage or ''):
                            arg.usage = ''
                        else:
                            matched_macros[macro.name] = macro.value
                    break
                # a usage recorded at a call site can name locals of the function it was
                # taken from, as in "DeltaY + EFI_GLYPH_HEIGHT". blanking it here makes the
                # argument fall back to a default value rather than to code that will not
                # compile. an edk2 guid global is spelled gFooGuid and is declared by the
                # header the protocol already brings in, so it stays nameable.
                # assignment is deliberately left alone: it keys the generator lookup
                # string and character literals are removed before tokenizing: their
                # payload is not made of identifiers, and treating L"Setup" as the names
                # L and Setup threw away every recorded string constant
                expression = STRING_LITERAL.sub(' ', arg.usage or '')
                unknown = [token for token in re.findall(r'[A-Za-z_]\w*', expression)
                           if token not in nameable]
                # an operand that went missing leaves the expression malformed, as in
                # "| | | EFI_PCI_IO_ATTRIBUTE_VGA_IO": remove_casts strips every
                # parenthesised group, so a usage written as "(UINT64)(A) | (UINT64)(B)"
                # comes back with holes where its operands were
                malformed = any(part.strip() == ""
                                for part in re.split(r'[|&^]', arg.usage or 'x'))
                if unknown or malformed:
                    arg.usage = ""
                else:
                    # a name the harness is allowed to write down still has to be declared
                    # somewhere. the macro branch above adds the header that defines a
                    # macro; a type named inside the expression brought nothing with it,
                    # so "sizeof (UDF_ANCHOR_VOLUME_DESCRIPTOR_POINTER)" -- recorded on
                    # EFI_DISK_IO_PROTOCOL.ReadDisk -- was emitted with nothing declaring
                    # it, even though MdePkg/Include/IndustryStandard/Udf.h is a public
                    # header the harness can include. cleanup_paths is the same test
                    # includable_types was built with, so a type that passed it here has a
                    # header the include pipeline will keep
                    for token in re.findall(r'[A-Za-z_]\w*', expression):
                        type_file = getattr(types.get(token), 'file', '')
                        if type_file and cleanup_paths([type_file]):
                            all_includes.add(type_file)

    # Step 6: Sort the arguments
    for key, function_block in pre_processed_data.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys())}
        function_block.arguments = sorted_arguments

    # add the protocol to Arg_0 usage
    for function, function_block in pre_processed_data.items():
        for arg_key, argument in function_block.arguments.items():
            if len(argument) > 0 and "protocol" in function_block.service.lower():
                for harness_group, functions in harness_functions.items():
                    if "protocol" in harness_group.lower():
                        for func, guid in functions:
                            if function == func:
                                argument[0].usage = guid
                                break
                break

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


def remove_unreachable_functions(input_data: Dict[str, FunctionBlock], function_template: Dict[str, FunctionBlock], generator_input_template: Dict[str, Function], protected: Set[str] = frozenset()) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # for all of the generator functions, check if they are reachable from the global scope
    # reachable means that the function is either a protocol or from a library
    # if the function is not reachable then remove it from the input_data and the function_template

    # Step 1: Collect all of the reachable functions
    reachable_functions = set()
    for function, function_block in function_template.items():
        for arg_key, argument in function_block.arguments.items():
            if argument[0].variable == "__PROTOCOL__":
                if function in generator_input_template.keys():
                    if "protocol" in generator_input_template[function].file.lower():
                        reachable_functions.add(function)
                        break
        if function in generator_input_template.keys():
            if "library" in generator_input_template[function].file.lower():
                reachable_functions.add(function)
    
    # Step 2: Remove all of the unreachable functions
    for function in list(input_data.keys()):
        if function not in reachable_functions:
            del input_data[function]
            # the template holds harness targets as well as generators, and the two
            # namespaces collide on bare names, so an unreachable generator must not take
            # a target's service entry with it
            if function not in protected:
                function_template.pop(function, None)
    
    return input_data, function_template

def is_cyclic(data_type: str, types: Dict[str, TypeInfo], aliases: Dict[str, str], macros: Dict[str, Macros], enums: Dict[str, List[str]]) -> bool:
    # check if the data_type is a scalar
    if is_fuzzable(data_type, aliases, types, 0):
        return False
    # check if the data_type is an enum
    # if is_enum(data_type, enums):
    #     return False
    # check if the data_type is a macro
    if data_type in macros.keys():
        return False
    # check if the data_type is a typedef
    if data_type in aliases.keys():
        return is_cyclic(aliases[data_type], types, aliases, macros, enums)
    # check if the data_type is a struct
    if data_type in types.keys():
        for field in types[data_type].fields:
            if data_type.lower() in field.type.lower():
                return True
    return False

def remove_cyclic_dependencies(input_data: Dict[str, FunctionBlock], 
                               function_template: Dict[str, FunctionBlock],
                               aliases: Dict[str, str],
                               macros: Dict[str, Macros],
                               enums: Dict[str, List[str]],
                               types: Dict[str, TypeInfo],
                               protected: Set[str] = frozenset()) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # for all of the generator functions check if any of the arguments are cyclic
    # if the argument is cyclic then remove the function from the input_data and the function_template
    cyclic_functions = set()
    for function, function_block in input_data.items():
        for arg_key, argument in function_block.arguments.items():
            if "ARG_LIST" in argument[0].arg_type:
                print(f'ERROR: {function} has an argument that is an ARG_LIST!!')
                print(is_cyclic(remove_ref_symbols(argument[0].arg_type), types, aliases, macros, enums))
            if is_cyclic(remove_ref_symbols(argument[0].arg_type), types, aliases, macros, enums):
                cyclic_functions.add(function)

    for function in cyclic_functions:
        del input_data[function]
        # same collision as above: a cyclic generator named CopyMem must not remove the
        # service entry for the protocol member that happens to share its name
        if function not in protected:
            function_template.pop(function, None)

    return input_data, function_template


def analyze_generators(input_generators: Dict[str, List[FunctionBlock]],
                       generator_input_template: Dict[str, Function],
                       input_template: Dict[str, FunctionBlock],
                       aliases: Dict[str, str],
                       macros: Dict[str, Macros],
                       enums: Dict[str, List[str]],
                       types: Dict[str, TypeInfo]) -> Tuple[Dict[str, List[FunctionBlock]], Dict[str, FunctionBlock], Dict[str, FunctionBlock]]:
    # just like for normal functions we want to determine the fuzzable arguments and fuzzable structs
    # for the generator functions
    output_template = input_template.copy()
    # every name already in the template is a requested harness target; step 7 below adds
    # the generators alongside them, after which the two are only distinguishable by this
    harness_targets = set(input_template.keys())

    # Step 1: Collect the constant arguments
    # generators = collect_known_constants(generators, generators)
    generators, generators_tempalate = initialize_generators(input_generators)
    generators = get_intersect(input_generators, generators)
    generators, matched_macros, protocol_guids, driver_guids = collect_known_constants(
            input_generators, generators, macros, aliases, types, enums)

    # Step 2: Collect the fuzzable arguments
    generators = get_directly_fuzzable(input_generators, generators, aliases, macros, True)

    # Step 3: Collect the fuzzable structs
    generators = variable_fuzzable(
        input_generators, types, generators, aliases, macros, False)

    # Step 4: Add the output variables
    generators = add_output_variables(generators_tempalate, generators)
    generators = handle_optional_arguments(generators, generators_tempalate)  

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

    # Step 8: Remove any generator functions that are unreachable from a global scope
    generators, output_template = remove_unreachable_functions(generators, output_template, generator_input_template, harness_targets)

    # Step 9: Remove any generator functions that have cyclic dependencies
    generators, output_template = remove_cyclic_dependencies(generators, output_template, aliases, macros, enums, types, harness_targets)

    return input_generators, generators, output_template

def sanity_check(processed_data: Dict[str, FunctionBlock], harness_functions: Dict[str, List[Tuple[str, str]]]):
    for _, input_functions in harness_functions.items():
        for function, _ in input_functions:
            if function not in processed_data.keys():
                print(f"WARNING: {function} was not able to be harnessed!!")

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
    return modified_includes

def update_inc(includes: List[str], libmap: Dict[str, Dict[str, list]]) -> List[str]:
    # building a new list rather than removing from the one being iterated: a remove
    # shifts the tail down and the loop then skips the next entry, so the includes that
    # actually got dropped depended on where in the list they happened to sit
    kept = []
    for include in includes:
        if include in unusable_includes:
            continue
        if "ppi" in include.lower():
            continue
        if "library" in include.lower():
            match = False
            for lib in libmap.keys():
                if lib in include:
                    match = True
            if not match:
                continue
        kept.append(include)
    return kept

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
    return modified_includes

# a header a listed one depends on has to be emitted ahead of it, and pulled in even when
# nothing requested it directly
def emit_include(file: str, ordered: List[str], emitted: Set[str]):
    if file in emitted:
        return
    emitted.add(file)
    for prereq in include_prerequisites.get(file, []):
        emit_include(prereq, ordered, emitted)
    ordered.append(file)

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

    # reverse the list to ensure that the includes are in the correct order
    ordered_includes.reverse()

    # a header the dependency graph never saw is absent from sorted_graph, and dropping it
    # here is what leaves the harness with an unknown type name. there is no ordering
    # information for it, so it goes last, after everything it could depend on
    for file in includes:
        if file not in included:
            ordered_includes.append(file)
            included.add(file)

    mem_alloc = False
    for include in ordered_includes:
        if "MemoryAllocationLib" in include:
            mem_alloc = True
    if not mem_alloc:
        # Add the MemoryAllocationLib right after BaseLib include
        ordered_includes.insert(1, "Library/MemoryAllocationLib.h")

    resolved = []
    emitted = set()
    for file in ordered_includes:
        emit_include(file, resolved, emitted)
    return resolved


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
    # Split the key into a prefix and a numeric suffix
    prefix, suffix = key.split("_", 1)
    return (prefix, int(suffix))

def analyze_data(macro_file: str,
                 enum_file: str,
                 generator_file: str,
                 input_file: str,
                 data_file: str,
                 types_file: str,
                 alias_file: str,
                 cast_file: str,
                 random: bool,
                 harness_folder: str,
                 best_guess: bool,
                 functions: str,
                 generator_decl: str,
                 edk2_dir: str,
                 include_deps_file: str) -> Tuple[Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, FunctionBlock], Dict[str, List[FieldInfo]], List[str], Dict[str, str], Dict[str, str], Dict[str, str], set, set, Dict[str, List[str]], int]:

    build_guid_struct_map(edk2_dir)
    macros_val, macros_name = load_macros(macro_file)
    global total_generators
    cast_map = load_castings(cast_file)
    enum_map = load_enums(enum_file)
    generators = load_generators(generator_file, macros_val)
    harness_functions = load_functions(input_file)
    libmap = load_libmap(edk2_dir, os.path.join('/'.join(data_file.split("/")[:-1]), 'libmap.json'))
    function_declares = load_function_declares(functions)
    generator_declares = load_generator_declares(generator_decl)
    include_deps = load_include_deps(include_deps_file)
    data, function_template = load_data(
        data_file, harness_functions, macros_val, random, best_guess, function_declares)
    apply_declarations(data, harness_functions)
    types = load_types(types_file)
    aliases = load_aliases(alias_file)
    if not random:
        generators, processed_generators, template = analyze_generators(
            generators, generator_declares, function_template, aliases, macros_name, enum_map, types)
    else:
        processed_generators = {}
        template = function_template

    # These two are treated together because we want to use generators to handle any
    # input argument that isn't either directly fuzzable or of a known input
    # we will primarily use generators to handle the more compilicated structs
    # (i.e. more than one level of integrated structs) and the basic structs
    # that have all scalable fields will be directly generated with random input
    processed_data, matched_macros, protocol_guids, driver_guids = collect_all_function_arguments(
        data, function_template, types, processed_generators, aliases, macros_name, enum_map, cast_map, random, harness_functions)


    # A generator is called by name, so the harness must be able to declare it: its
    # declaration has to sit in a header, and that header has to survive into the include
    # list. CreateBdsEvent is declared only in a MinPlatformPkg .c file; SerializeVariables-
    # NewInstance is in an OvmfPkg header that update_inc drops because the harness does not
    # link that library. Either way the call does not compile, so the generator goes.
    def generator_headers(name):
        declarations = generator_declares.get(name) or []
        # the map holds a single Function for some entries and a list for others
        if not isinstance(declarations, list):
            declarations = [declarations]
        headers = set()
        for declaration in declarations:
            path = getattr(declaration, 'file', None)
            if path:
                headers.update(cleanup_paths([path]))
        return headers, bool([d for d in declarations if getattr(d, 'file', None)])

    def prune_generators(includable):
        dropped = set()
        for name in list(processed_generators):
            headers, had_file = generator_headers(name)
            # nothing recorded to judge it on, so keep it
            if not had_file:
                continue
            if not headers or (includable is not None and not (headers & includable)):
                dropped.add(name)
        for name in sorted(dropped):
            print(f'INFO: dropping generator {name} -- no declaration the harness can include')
            del processed_generators[name]
        # an argument produced by a dropped generator has to come from somewhere: fuzz it
        # directly rather than leaving behind a call to a function that is gone
        if dropped:
            for block in processed_data.values():
                for arguments in block.arguments.values():
                    for argument in arguments:
                        if argument.assignment in dropped:
                            argument.variable = '__FUZZABLE__'
                            argument.assignment = ''
        return dropped

    prune_generators(None)

    # A function called directly by name needs a declaration the harness can include.
    # CreateBdsEvent is defined in a MinPlatformPkg library .c with no header anywhere in
    # the tree, so a harness that calls it fails with an implicit declaration. Protocol
    # members are reached through the protocol pointer and are declared by the protocol
    # struct itself, so they are kept whether or not a standalone declaration exists.
    undeclarable = [
        name for name, block in processed_data.items()
        if 'protocol' not in (getattr(block, 'service', '') or '').lower()
        and name not in function_declares
    ]
    for name in undeclarable:
        print(f'INFO: dropping {name} -- called directly but declared in no includable header')
        del processed_data[name]

    # Parameter names are what let a size argument be bound by the buffer it names --
    # BufferSize by Buffer, FatSize by Fat. They are set here rather than in sort_data
    # because a function reaches processed_data by several routes and only one of them
    # consults the protocol typedef, so names set there went missing for most protocols.
    named_parameters = 0
    for service, pairs in harness_functions.items():
        for pair in pairs:
            member = pair[0]
            guid = pair[1] if len(pair) > 1 else ""
            block = processed_data.get(member)
            if block is None or not guid:
                continue
            protocol_name = guid_protocol_name.get(guid)
            header = guid_header.get(guid)
            if not (protocol_name and header):
                continue
            specs = protocol_member_params(header, protocol_name, member)
            if not specs or len(specs) != len(block.arguments):
                continue
            ordered = sorted(block.arguments, key=natural_sort_key)
            for arg_name, spec in zip(ordered, specs):
                declared = param_name(spec)
                if not declared:
                    continue
                for argument in block.arguments[arg_name]:
                    argument.param_name = declared
                named_parameters += 1
    if named_parameters:
        print(f'INFO: named {named_parameters} parameter(s) from their protocol typedef!!')

    # all_includes = get_union(processed_data, processed_generators)
    update_includes = cleanup_paths(all_includes)
    # all_includes = get_union(processed_data, {})
    # all_includes = get_union({}, {})
    # sorted, not list: a set of strings iterates in a different order every run, which
    # made the include list and the resulting harness differ between identical runs
    collected_includes = sorted(set(update_includes) | default_includes)
    collected_includes = update_inc(collected_includes, libmap)
    libraries = update_libs(sorted(collect_libraries(collected_includes) | default_libraries), libmap)
    collected_includes = handle_include_deps(collected_includes, include_deps)

    # second pass, now that the include list is final: a generator whose header did not
    # survive update_inc cannot be declared, however valid its declaration looked earlier
    prune_generators(set(collected_includes))
    
    if not random:
        write_data(processed_generators,
                   f'{harness_folder}/processed_generators.json')
    write_data(processed_data, f'{harness_folder}/processed_data.json')

    sanity_check(processed_data, harness_functions)

    # sort the arguments for each function
    for _, function_block in processed_data.items():
        sorted_arguments = {k: function_block.arguments[k] for k in sorted(
            function_block.arguments.keys(), key=natural_sort_key)}
        function_block.arguments = sorted_arguments

    for _, functions in harness_functions.items():
        for _, protocol in functions:
            if protocol == "":
                continue
            protocol_guids.add(protocol)
    return processed_data, processed_generators, template, types, collected_includes, libraries, matched_macros, aliases, driver_guids, protocol_guids, enum_map, len(total_generators), observed_precedence(data_file)
