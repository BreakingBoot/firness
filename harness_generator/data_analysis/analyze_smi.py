import json
import os
import copy
from fuzzywuzzy import fuzz
import math
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Set
from common.types import FunctionBlock, FieldInfo, TypeInfo, EnumDef, Function, Argument, Macros, scalable_params, services_map, type_defs, known_contant_variables, ignore_constant_keywords, default_includes, default_libraries, include_prerequisites, unusable_includes, SmiInfo
from common.utils import remove_ref_symbols, write_data, get_union, is_whitespace, contains_void_star, contains_usage, get_stripped_usage, is_fuzzable, get_intersect, print_function_block
from common.generate_library_map import generate_libmap
from data_analysis.cross_module import report as report_cross_module
from common.vendor_types import resolve as resolve_payload, render as render_payload

smi_includes = {
    "Protocol/SmmCommunication.h",
    "Guid/PiSmmCommunicationRegionTable.h"
}

all_includes = set()

# Parameter blocks the harness has to carry itself, in dependency order. See
# common/vendor_types.py: the headers that declare them are private to their drivers.
vendored_order = []

def load_discovered(input_file: str) -> List[str]:
    """Handler names from the file discover_smi.py wrote, one per line.

    Tolerates the `--with-source` form, which appends `  // path/to/file.c`, and the
    software SMI form, which puts the registered command byte between the two --
    `B2SmiDispatchHandle  0xB4  // OvmfPkg/.../B2SmiDispatch.c:238`. A handler name never
    contains a space, so the first field is the name in every form of the file.
    """
    if not input_file or not os.path.isfile(input_file):
        return []
    names = []
    try:
        for line in open(input_file, errors='ignore'):
            fields = line.split('//')[0].split()
            if fields:
                names.append(fields[0])
    except OSError:
        return []
    return names


def load_sw_discovered(input_file: str) -> Dict[str, dict]:
    """The software SMI request file: handler -> the command byte it is registered for.

    The command byte is the address of a software SMI handler the way a GUID is the
    address of a comm-buffer one, so a line without one names a handler this channel
    cannot reach and is not a target. Those lines are skipped rather than defaulted: a
    default here would be a command byte nothing registered, which reaches no handler and
    -- on the shared port 0xB2 -- can reach the platform's own.
    """
    found = {}
    if not input_file or not os.path.isfile(input_file):
        return found
    try:
        for line in open(input_file, errors='ignore'):
            body, _, note = line.partition('//')
            fields = body.split()
            if len(fields) < 2:
                continue
            try:
                value = int(fields[1], 0)
            except ValueError:
                continue
            note = note.strip()
            spelling = ''
            if note.endswith(')') and '(' in note:
                spelling = note[note.rindex('(') + 1:-1].strip()
                note = note[:note.rindex('(')].strip()
            found[fields[0]] = {'value': value, 'file': note, 'spelling': spelling}
    except OSError:
        return {}
    return found


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

def load_smi_call_edges(smi_file: str) -> List[dict]:
    """The calls each SMI handler makes, from smi-call-edges.json.

    Written beside smi-function-guid-map.json by the analyzer. Absent when the tree was
    analysed by an older build, which is not an error -- the cross-module section is simply
    not reported.
    """
    path = os.path.join(os.path.dirname(smi_file), 'smi-call-edges.json')
    try:
        with open(path, 'r') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def load_smi_inventory(smi_file: str) -> Dict[str, dict]:
    """Every registered handler and how it is dispatched, from smi-handler-inventory.json.

    smi-function-guid-map.json holds only the handlers a comm-buffer harness can drive, so
    it cannot answer "why is this one missing". The inventory can: a handler on a root
    dispatcher has no GUID and is reached by a port write or a platform event, which is a
    different channel rather than a gap in the generator.
    """
    path = os.path.join(os.path.dirname(smi_file), 'smi-handler-inventory.json')
    try:
        with open(path, 'r') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load_smi_data(smi_file: str) -> Dict[str, SmiInfo]:
    with open(smi_file, 'r') as file:
        raw_data = json.load(file)
    smi_data = {}
    for smi, data in raw_data.items():
        smi_info = SmiInfo(smi, data["Type"], data["Guid"],
                           buffer_protocol=data.get("BufferProtocol", ""),
                           field_constants=data.get("FieldConstants", {}))
        smi_data[smi] = smi_info
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


# A handler definition and the parameter list that goes with it. edk2 spells these over
# several lines with IN/OUT/OPTIONAL decorations, so match the name followed by a
# parenthesised list and a brace rather than trying to describe the whole signature.
#
# The parameter group may not cross a comment terminator. Under re.S, `[^;{}]*?` runs
# across newlines, so a DOC COMMENT satisfied the whole pattern: measured on edk2 master,
# FpdtSmiHandler matched in THREE files, and the two that came first in the walk were both
# comments -- "FpdtSmiHandler() will receive untrusted input and do basic validation." --
# whose `(` paired with a `)` far below, past the `**/` and inside real code. So
# _handler_source returned a header comment as the definition, the GUID search that
# follows found nothing in it, and the handler was reported as "no GUID-keyed registration
# call found" although its registration sits beside its real definition.
#
# A real parameter list never contains `*/`, so forbidding that is enough and costs
# nothing. Anchoring at the start of a line was the other candidate and is WRONG: edk2
# usually puts the name in column 0, but `EFI_STATUS EFIAPI Name (` on one line is just as
# valid and appears in real drivers, so the anchor dropped definitions it should keep.
_DEFN = r'\b{name}\s*\((?P<params>(?:(?!\*/)[^;{{}}])*?)\)\s*{{'


def _handler_source(name: str, edk2_dir: str):
    """The file and body text of `name`'s definition, or (None, None).

    One walk per call is acceptable: this runs only for handlers the analyser could not
    type, which is a handful even on a large tree.
    """
    import re as _re
    pattern = _re.compile(_DEFN.format(name=_re.escape(name)), _re.S)
    for base, dirs, files in os.walk(edk2_dir or '.'):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
        for entry in files:
            if not entry.endswith('.c'):
                continue
            path = os.path.join(base, entry)
            try:
                text = open(path, errors='ignore').read()
            except OSError:
                continue
            if name not in text:
                continue
            match = pattern.search(text)
            if match:
                return path, text[match.start():]
    return None, None


def payload_from_source(handler: str, edk2_dir: str, types: Dict[str, TypeInfo]):
    """The type a handler casts its own comm buffer to.

    The PI signature is (DispatchHandle, Context, CommBuffer, CommBufferSize) and a handler
    that takes CommBuffer as VOID * casts it to its parameter block on the way in --
    `SPI_COMM_HEADER *ReturnComms = (SPI_COMM_HEADER *)CommBuffer;`. That cast is the
    handler's own statement of what the block is, which is better evidence than anything
    the caller side offers: cast-map.json is keyed by type rather than by function, so it
    cannot say which of the 1448 recorded types belongs to this buffer.

    Returns a type name present in `types` with fields, or None.
    """
    import re as _re
    path, body = _handler_source(handler, edk2_dir)
    if not body:
        return None
    match = _re.compile(_DEFN.format(name=_re.escape(handler)), _re.S).search(body)
    params = match.group('params') if match else ''
    # the buffer parameter, not the size one next to it
    names = [_re.sub(r'.*?([A-Za-z_]\w*)\s*$', r'\1', p.replace('*', ' ').strip())
             for p in params.split(',')]
    buffers = [n for n in names if 'commbuffer' in n.lower() and 'size' not in n.lower()]
    if not buffers:
        return None
    param = buffers[0]
    # stop at the end of this function so a later function's casts cannot leak in
    depth, end = 0, len(body)
    for index, char in enumerate(body):
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                end = index
                break
    for candidate in _payload_casts(handler, edk2_dir):
        info = types.get(candidate)
        if info and getattr(info, 'fields', None):
            return candidate
    return None


def _payload_casts(handler: str, edk2_dir: str):
    """Every type name the handler casts its own comm buffer to, recorded or not.

    payload_from_source answers only with a type it can build fields for, which is right
    for generating a harness and wrong for explaining a handler it cannot generate. The two
    outcomes look identical from there and are not the same thing:

        no cast at all                 -- a root handler, which has no comm buffer
        a cast to a type nobody parsed -- a driver absent from the platform DSC, so the
                                          header declaring its payload reached no
                                          translation unit

    TpmNvsCommunciate was reported as "its comm buffer is never cast to a recorded type"
    while the cast sits plainly in Tcg2Smm.c -- the type is simply unknown here, because
    Tcg2Smm is in no OvmfPkg DSC. The reason sent a reader looking for something that was
    already there.
    """
    import re as _re
    path, body = _handler_source(handler, edk2_dir)
    if not body:
        return []
    match = _re.compile(_DEFN.format(name=_re.escape(handler)), _re.S).search(body)
    params = match.group('params') if match else ''
    names = [_re.sub(r'.*?([A-Za-z_]\w*)\s*$', r'\1', q.replace('*', ' ').strip())
             for q in params.split(',')]
    buffers = [n for n in names if 'commbuffer' in n.lower() and 'size' not in n.lower()]
    if not buffers:
        return []
    param = buffers[0]
    depth, end = 0, len(body)
    for index, char in enumerate(body):
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                end = index
                break
    out = []
    for cast in _re.finditer(rf'\(\s*([A-Za-z_]\w*)\s*\*\s*\)\s*\(?\s*{_re.escape(param)}\b',
                             body[:end]):
        if cast.group(1) not in out:
            out.append(cast.group(1))
    return out


def _body_of(name: str, text: str):
    """The balanced { ... } body of `name`'s definition inside `text`, or ''."""
    import re as _re
    match = _re.compile(_DEFN.format(name=_re.escape(name)), _re.S).search(text)
    if not match:
        return ''
    start = text.index('{', match.start())
    depth = 0
    for index in range(start, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def lifecycle_gate(handler: str, edk2_dir: str):
    """A file-scope flag the handler tests that something else in its driver sets.

    Several handlers switch themselves off once boot has moved on, and a harness that runs
    as a UEFI application runs after all of it. SmmSpiHandler returns EFI_ACCESS_DENIED
    whenever mEndOfDxe is set, and MmEndOfDxeCallback sets it from the SMM EndOfDxe notify
    -- the same GUID value PiSmmCore installs during DXE -- so by the time the harness is
    loaded from the shell the handler refuses every input before it reaches any of its own
    logic. QueryVariableInfoHandler is the same shape with the sense reversed: its body is
    wrapped in `if (inDxe)` and its entry point clears inDxe on the way out.

    Fuzzing one of those is not wrong, it is just uninformative, and a campaign cannot say
    so from the outside: full budget, no findings, exactly like a handler that validates
    everything correctly. So name the flag.

    Two shapes, and the difference decides whether there is anything to do about it:

      * the flag is set by a protocol notify -- MmEndOfDxeCallback on
        gEfiMmEndOfDxeProtocolGuid -- so the guarded body is reachable up to that event
        and not after. A UEFI application is always after it; a DXE driver harness would
        not be. Worth saying, because it names a way to reach the code.
      * the flag is set by the same function that registers the handler, which is
        QueryVariableInfoHandler's shape: `inDxe` is cleared at the end of
        QueryVariableInfoEntryPoint, after SmiHandlerRegister. The gate is therefore shut
        before any SMI can arrive, and the guarded body is dead code for every caller
        forever. Nothing reaches it, so there is nothing to aim at.

    Also report how much of the handler runs BEFORE the gate, because that part is
    reachable whatever the flag says. SmmSpiHandler checks its size, validates the buffer
    is outside SMRAM and makes an attacker-sized AllocateRuntimeZeroPool followed by a
    CopyMem of that length, all before it consults mEndOfDxe -- so "a clean result means
    nothing" was too pessimistic there, and flatly wrong for a handler whose gate is shut
    at registration.

    Returns (flag, setter_description) or (None, None).
    """
    import re as _re
    path, text = _handler_source(handler, edk2_dir)
    if not text:
        return None, None
    whole = open(path, errors='ignore').read()
    body = _body_of(handler, whole)
    if not body:
        return None, None
    # file-scope BOOLEANs, which is how edk2 spells this kind of latch
    flags = dict(_re.findall(r'^\s*(?:STATIC\s+|static\s+)?BOOLEAN\s+(\w+)\s*(?:=\s*([^;]+))?;',
                             whole, _re.M))
    for flag, initial in flags.items():
        # tested in the handler, as a bare condition rather than as part of an expression
        if not _re.search(rf'\bif\s*\(\s*!?\s*{_re.escape(flag)}\s*\)', body):
            continue
        # and written somewhere that is not the handler
        writes = [m.start() for m in _re.finditer(rf'\b{_re.escape(flag)}\s*=\s*[^=]', whole)]
        outside = [w for w in writes if whole.find(body) > w or w > whole.find(body) + len(body)]
        if not outside:
            continue
        where = os.path.basename(path)
        detail = (f'{where} sets it outside the handler (initially '
                  f'{(initial or "unset").strip()})')

        # Who shuts it, and when. The enclosing function of a write outside the handler is
        # the answer; edk2 puts a function's name in column 0, so the nearest one above the
        # write is its owner.
        #
        # The declaration's own initialiser is a write by this regex -- "BOOLEAN inDxe =
        # TRUE;" -- and being at file scope it has no enclosing function, so taking the
        # first write found the declaration and gave up. That is why only the one flag
        # declared WITHOUT an initialiser was ever classified.
        setter = ''
        for where_at in outside:
            if _re.search(r'BOOLEAN\s+$', whole[max(0, where_at - 24):where_at]):
                continue
            setter = _enclosing_function(whole, where_at)
            if setter:
                break
        if setter:
            registers = _re.search(
                rf'\b(?:Smi|Mmi)HandlerRegister\s*\(\s*{_re.escape(handler)}\b',
                _body_of(setter, whole) or '')
            if registers:
                detail += (f'. {setter} clears it after registering the handler, so the '
                           f'gate is shut before any SMI can arrive and the guarded body '
                           f'is unreachable from every caller, not merely from a late one')
            else:
                notify = _re.search(
                    rf'RegisterProtocolNotify\s*\(\s*&?\s*(\w+)\s*,\s*{_re.escape(setter)}\b',
                    whole)
                if notify:
                    detail += (f'. {setter} sets it from the {notify.group(1)} notify, so '
                               f'the guarded body is reachable only before that event -- '
                               f'a DXE driver could, a UEFI application cannot')
                else:
                    detail += f'. {setter} sets it'

        # What runs before the gate is reachable no matter what the flag says.
        gate = _re.search(rf'\bif\s*\(\s*!?\s*{_re.escape(flag)}\s*\)', body)
        if gate:
            before = body[:gate.start()]
            # ';' overcounts declarations, so count only lines that call something
            calls = len(_re.findall(r'\b[A-Z]\w+\s*\(', before))
            if calls:
                detail += (f'. {calls} call(s) run before the gate and are reached '
                           f'whatever it holds')
        return flag, detail
    return None, None


def _enclosing_function(whole: str, offset: int):
    """The name of the function containing this offset, by edk2 layout, or ''.

    edk2 puts a definition's name in column 0 with its parameters on the lines below, so
    the open paren ends the line. Requiring that is what separates a definition from
    "Copyright (c) 2010 - 2018, Intel Corporation" in the file header -- which is also in
    column 0, also followed by a paren, and was being reported as the function that sets
    mEndOfDxe.
    """
    import re as _re
    best = ''
    for found in _re.finditer(r'^([A-Za-z_]\w*)\s*\(\s*$', whole, _re.M):
        if found.start() > offset:
            break
        best = found.group(1)
    return best


def recover_missing_handlers(smi_data: Dict[str, SmiInfo],
                             discovered: List[str],
                             types: Dict[str, TypeInfo],
                             edk2_dir: str) -> Dict[str, str]:
    """Add handlers the source registers that the analyser did not record.

    Returns {name: why it still could not be used} for the ones that stay out.
    """
    import re as _re
    missing = [h for h in (discovered or []) if h and h not in smi_data]
    stuck = {}
    for handler in missing:
        path, body = _handler_source(handler, edk2_dir)
        if not body:
            stuck[handler] = 'no definition found in the tree'
            continue
        # The GUID a comm-buffer handler is registered under, from its own registration
        # call. A handler registered through a dispatch protocol instead -- SwDispatch2's
        # Register, keyed on a SwSmiInputValue rather than a GUID -- cannot be driven by
        # SmmCommunication at all, and saying so is the useful answer.
        text = open(path, errors='ignore').read()
        guid = _re.search(rf'(?:Smi|Mmi)HandlerRegister\s*\(\s*{_re.escape(handler)}\s*,\s*&?\s*'
                          r'([A-Za-z_]\w*)', text, _re.S)
        if not guid:
            if _re.search(rf'->\s*Register\s*\([^;]*?{_re.escape(handler)}', text, _re.S):
                stuck[handler] = ('registered through a dispatch protocol, not a comm-buffer '
                                  'GUID, so SmmCommunication cannot reach it')
            else:
                stuck[handler] = 'no GUID-keyed registration call found'
            continue
        payload = payload_from_source(handler, edk2_dir, types)
        if not payload:
            casts = _payload_casts(handler, edk2_dir)
            if casts:
                stuck[handler] = (
                    f'it casts its comm buffer to {casts[0]}, which no module in this '
                    f'build declares -- the analyser records only types it parsed, so a '
                    f'driver absent from the platform DSC takes its payload type with it')
            else:
                stuck[handler] = 'its comm buffer is never cast to any type'
            continue
        smi_data[handler] = SmiInfo(handler, f'{payload} *', guid.group(1), path)
        print(f'INFO: recovered smi handler {handler} from source -- {guid.group(1)}, '
              f'comm buffer cast to {payload} *')
    return stuck


#
# Software SMI discovery, from the registration shape every tree writes:
#
#     mSwContext.SwSmiInputValue = B2SWSMI;
#     mSwDispatch->Register (mSwDispatch, B2SmiDispatchHandle, &mSwContext, &mSwHandle);
#
# The FIELD is the discriminator, not the name of the dispatcher variable. SwSmiInputValue
# is declared by EFI_SMM_SW_REGISTER_CONTEXT and EFI_MM_SW_REGISTER_CONTEXT and by nothing
# else, so a Register call whose context carries it IS a software dispatch registration
# however the tree spells the protocol -- SmmSwDispatch2, mSwDispatch,
# EFI_MM_SW_DISPATCH_PROTOCOL. The analyzer's C++ matches on the spelling and so has to
# know all three; this does not.
#
_SW_REGISTER = r'->\s*Register\s*\(\s*[A-Za-z_]\w*\s*,\s*&?\s*([A-Za-z_]\w*)\s*,\s*&?\s*([A-Za-z_]\w*)'
_SW_VALUE = r'\b(\w+)\s*(?:\.|->)\s*SwSmiInputValue\s*=\s*([^;]+);'
_SW_CAST = r'^\s*\(\s*(?:CONST\s+)?[A-Za-z_]\w*\s*\**\s*\)\s*'
_SW_DEFINE = r'^[ \t]*#[ \t]*define[ \t]+{name}[ \t]+(.+?)[ \t]*(?:/\*|//|$)'

# The dispatcher refuses 0 and anything above MAXIMUM_SWI_VALUE, and the handlers
# themselves read a command port of 0 as "not a software SMI" and return at once.
SW_VALUE_MIN = 1
SW_VALUE_MAX = 0xFF


def _sw_unwrap(expr: str) -> str:
    """An initialiser with its casts and wrapping parentheses taken off."""
    import re as _re
    expr = (expr or '').strip()
    while True:
        stripped = _re.sub(_SW_CAST, '', expr).strip()
        if stripped.startswith('(') and stripped.endswith(')'):
            stripped = stripped[1:-1].strip()
        if stripped == expr:
            return expr
        expr = stripped


def _sw_define_index(edk2_dir: str) -> Dict[str, str]:
    """Every object-like #define in the tree, for a constant a driver does not define itself.

    Built once and only when a file-local lookup has already failed. The same two-stage
    resolution as scripts/discover_smi.py, deliberately: these two passes are the same
    discovery written twice in two repositories, and one of them resolving a constant the
    other cannot is drift that shows up as a target silently missing.
    """
    import re as _re
    index = {}
    pattern = _re.compile(_SW_DEFINE.format(name=r'([A-Za-z_]\w*)'), _re.M)
    for base, dirs, files in os.walk(edk2_dir or '.'):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
        for entry in files:
            if not (entry.endswith('.h') or entry.endswith('.c')):
                continue
            try:
                text = open(os.path.join(base, entry), errors='ignore').read()
            except OSError:
                continue
            for found in pattern.finditer(text):
                index.setdefault(found.group(1), found.group(2).strip())
    return index


def _sw_constant(expr: str, text: str, index=None):
    """The integer an initialiser denotes, or None if this pass cannot say.

    None is the answer for `(UINTN)-1`, which is not a value: it asks the dispatcher to
    allocate the next free command byte at registration time, and which byte that is
    depends on how many drivers registered before it on that boot. Every software SMI
    registration in edk2 proper is written that way. Guessing one would put a command byte
    in the harness that addresses whichever handler happened to land in that slot -- a
    different handler after the next build -- so it is left out and counted.
    """
    import re as _re
    expr = _sw_unwrap(expr)
    try:
        return int(expr, 0)
    except ValueError:
        pass
    if not _re.fullmatch(r'[A-Za-z_]\w*', expr):
        return None
    seen = set()
    while expr not in seen:
        seen.add(expr)
        found = _re.search(_SW_DEFINE.format(name=_re.escape(expr)), text, _re.M)
        value = found.group(1) if found else (index or {}).get(expr)
        if value is None:
            return None
        value = _sw_unwrap(value)
        try:
            return int(value, 0)
        except ValueError:
            if not _re.fullmatch(r'[A-Za-z_]\w*', value):
                return None
            expr = value
    return None


def sw_smi_commands(edk2_dir: str) -> Tuple[Dict[str, dict], Dict[str, str]]:
    """Every software SMI registration in the tree: the ones with an address and the rest.

    Returns ({handler: {value, file, spelling}}, {handler: why it has no address}). The
    second half is why this exists at all beside discover_smi.py: a handler whose command
    byte the dispatcher picks at run time IS reachable on this channel, and reporting it as
    though no channel reached it is the same mistake the comm-buffer reason was making.
    """
    import re as _re
    register = _re.compile(_SW_REGISTER)
    assign = _re.compile(_SW_VALUE)
    found, stuck = {}, {}
    index = None
    for base, dirs, files in os.walk(edk2_dir or '.'):
        dirs[:] = [d for d in dirs if d not in ('.git', 'Build', 'BaseTools')]
        for entry in files:
            if not entry.endswith('.c'):
                continue
            path = os.path.join(base, entry)
            try:
                text = open(path, errors='ignore').read()
            except OSError:
                continue
            if 'SwSmiInputValue' not in text or '->Register' not in text:
                continue
            assigned = list(assign.finditer(text))
            if not assigned:
                continue
            for call in register.finditer(text):
                handler, context = call.group(1), call.group(2)
                # The assignment that reaches the call is the last one before it on that
                # context variable. Tcg2Smm registers twice off one SwContext, so taking
                # the first would give both handlers the first value.
                before = [m for m in assigned
                          if m.group(1) == context and m.start() < call.start()]
                if not before:
                    continue
                source = before[-1]
                spelling = _sw_unwrap(source.group(2))
                value = _sw_constant(source.group(2), text)
                if value is None:
                    if index is None:
                        index = _sw_define_index(edk2_dir)
                    value = _sw_constant(source.group(2), text, index)
                if value is None or not SW_VALUE_MIN <= value <= SW_VALUE_MAX:
                    stuck.setdefault(handler, spelling)
                    continue
                line = text.count('\n', 0, source.start()) + 1
                found.setdefault(handler, {'value': value, 'file': f'{path}:{line}',
                                           'spelling': spelling})
    for handler in found:
        stuck.pop(handler, None)
    return found, stuck


def report_smi_coverage(smi_data, discovered, recovered, unusable, edk2_dir='',
                        inventory=None, sw_commands=None, channel='') -> None:
    """Say what happened to every handler the source registers.

    `[PASS] discover ... 22 SMI handlers` counts registrations in source, and the number of
    harnesses can be less than half that without a word being said. A run that reports
    nothing in a tree's own drivers should be able to show whether they were clean or
    merely absent.
    """
    #
    # The inventory is in this union, not just the discovery list. discover_smi.py greps
    # for registration calls and found 22; the analyzer resolves a table-driven
    # registration and found 25, the seven SMM core handlers among them. On run 42483193618
    # those seven were in smi-handler-inventory.json and in none of the sets this report
    # reads, so the thing that found them said nothing about them.
    #
    names = sorted(set(discovered or ()) | set(smi_data) | set(unusable)
                   | set(recovered) | set(inventory or ()))
    if not names:
        return
    # Not `where`: the lifecycle loop below binds that name from lifecycle_gate, and one
    # of the two would be reading the other's value the moment either line moves.
    on_channel = f' on {channel}' if channel else ''
    print(f'SMI coverage: {len(smi_data)} of {len(names)} registered handler(s) '
          f'harnessed{on_channel}')
    for name in sorted(smi_data):
        flag, where = lifecycle_gate(name, edk2_dir)
        if flag:
            print(f'  CAVEAT: {name} is harnessed but gated on {flag} -- {where}')
    for name in names:
        if name in smi_data:
            continue
        print(f'  not harnessed: {name} -- '
              f'{not_harnessed_reason(name, unusable, recovered, inventory, sw_commands, channel)}')


def not_harnessed_reason(name: str, unusable: dict, recovered: dict,
                         inventory: dict, sw_commands=None, channel: str = '') -> str:
    """Why this handler is not in the harness set, in one sentence a reader can act on.

    A definite reason wins over a vague one. unusable/recovered carry the generator's own
    note -- "its comm buffer is never cast to a recorded type" -- which is true of a root
    handler and useless, because a root handler HAS no comm buffer to cast and no GUID to
    address it with. Run 42483193618 told a reader to go looking for a cast in
    CpuHotplugMmi that cannot exist. Where the dispatch kind settles reachability, say
    that instead.

    The coverage report prints this and the inventory stores it, from here rather than
    from two spellings of the same precedence: a file that explains a handler differently
    from the run that wrote it is a second answer to argue with.
    """
    entry = (inventory or {}).get(name) or {}
    # The channel that DOES reach a handler beats every statement about the one that does
    # not. A software SMI handler whose command byte is known is driven by the
    # DiscoveredSwSmi target, and reporting it as "there is no caller buffer to fuzz" --
    # true, and the whole of what this file used to say -- reads as a handler nothing can
    # reach. That reading is what left B2SmiDispatch the only challenge-added driver with
    # no coverage.
    reached = _sw_smi_reason(name, sw_commands)
    if reached:
        return reached
    # Two campaigns now write this file, one per channel, and each leaves the other's
    # handlers out. Saying "registered as SmiHandlerRegister, which is not a GUID
    # dispatch" about a handler the comm-buffer campaign harnesses is both false and the
    # kind of false a reader cannot catch, so a run that knows which channel it drives
    # says that instead.
    if channel:
        theirs = _channel_of(name, entry, sw_commands)
        if theirs == DISPATCH_CHANNEL['RootHandler']:
            # Not "this campaign cannot reach it": a root handler runs on every MMI,
            # including the ones this campaign raises, so it is being exercised. What it
            # has not got is an address, so no target can be named after it and nothing
            # steers the input towards its body.
            return ('a root handler: it runs on every MMI this campaign raises, so it is '
                    'exercised whatever the target, but it has no address of its own and '
                    'no buffer it reads, so there is nothing for a target to aim at')
        if theirs and theirs != channel:
            return (f'its channel is {theirs}; this campaign drives {channel}')
    why = _dispatch_reason(entry) if DEFINITE_DISPATCH(entry) else ''
    if not why:
        why = unusable.get(name) or recovered.get(name)
    if not why:
        why = _dispatch_reason(entry)
    return why


def _channel_of(name: str, entry: dict, sw_commands) -> str:
    """What raises this handler, whatever any one campaign can do about it."""
    found, stuck = (sw_commands or ({}, {}))
    if name in (found or {}) or name in (stuck or {}):
        return DISPATCH_CHANNEL['SwDispatch']
    return DISPATCH_CHANNEL.get((entry or {}).get('Dispatch') or '', '')


def _sw_smi_reason(name: str, sw_commands) -> str:
    """Why a comm-buffer run leaves a software SMI handler alone, naming what does reach it.

    sw_commands is the pair sw_smi_commands() returns: the handlers with a statically
    resolvable command byte, and the ones whose byte the dispatcher picks at registration
    time. Both are reachable on the port channel and only the first is addressable, which
    is a different sentence from either "unharnessable" or "harnessed".
    """
    found, stuck = (sw_commands or ({}, {}))
    if name in (found or {}):
        info = found[name]
        where = info.get('file') or 'its registration'
        return (f'reached by the software SMI port channel, not by a comm buffer: it is '
                f'registered for command byte 0x{int(info["value"]):02X} at {where}, '
                f'which the DiscoveredSwSmi target writes to port '
                f'0x{SW_COMMAND_PORT:02X}. This target fills comm buffers and cannot '
                f'raise it')
    if name in (stuck or {}):
        return (f'reached by the software SMI port channel, not by a comm buffer, but its '
                f'registration asks the dispatcher for the next free command byte '
                f'({stuck[name]}) instead of naming one, so no static pass can say which '
                f'byte addresses it and the DiscoveredSwSmi target leaves it out rather '
                f'than guessing')
    return ''


def DEFINITE_DISPATCH(entry) -> bool:
    """Whether the dispatch kind alone settles why a handler cannot be driven.

    True for every kind that is not a GUID-keyed comm-buffer registration: those are
    statements about how the handler is reached, which no amount of type resolution
    changes. False for SmiHandlerRegister, where the reason really is about the buffer.
    """
    kind = (entry or {}).get('Dispatch') or ''
    return bool(kind) and kind != 'SmiHandlerRegister'


DISPATCH_REASON = {
    'RootHandler': 'registered with HandlerType NULL, which makes it a root handler: '
                   'SmiManage calls it on every MMI whatever GUID the header carries, and '
                   'its CommBuffer is ignored by contract. There is no GUID to address it '
                   'with and no buffer it reads, so a comm-buffer harness has nothing to '
                   'give it -- this is not the analyser failing to resolve a type',
    'SwDispatch': 'registered on the software MMI dispatch protocol, not against a GUID. It '
                  'is raised by a write to the software MMI port and its CommBuffer is an '
                  'EFI_MM_SW_CONTEXT the dispatcher fills in with the CPU index and the port '
                  'value -- there is no caller buffer to fuzz, so a comm-buffer harness '
                  'cannot drive it and a fabricated one would not be an input the hardware '
                  'can produce. The port write does drive it: that is the DiscoveredSwSmi '
                  'target, which needs the command byte this handler registered for',
    'SxDispatch': 'registered on the Sx dispatch protocol, so it runs on an S-state '
                  'transition rather than on a call',
    'PeriodicTimer': 'registered on the periodic timer dispatch protocol, so it runs on a '
                     'timer rather than on a call',
    'UsbDispatch': 'registered on the USB dispatch protocol, so it runs on a USB event',
    'GpiDispatch': 'registered on the GPI dispatch protocol, so it runs on a pin change',
    'PowerButton': 'registered on the power button dispatch protocol',
    'StandbyButton': 'registered on the standby button dispatch protocol',
    'IoTrap': 'registered on the IO trap dispatch protocol, so it runs on a trapped access',
}


# The software SMI pair, named here because three places quote it: the reason strings
# above, the inventory's Channel field, and the generated harness.
SW_COMMAND_PORT = 0xB2
SW_DATA_PORT = 0xB3

# What RAISES each kind of handler, as opposed to why one target cannot. A record that
# says only "not harnessable" is a dead end for a reader; a record that names the channel
# says which campaign to go and look at. Every dispatch kind the analyzer records has one.
DISPATCH_CHANNEL = {
    'SmiHandlerRegister': 'the comm buffer, addressed by GUID',
    'RootHandler': 'every MMI, whatever raised it',
    'SwDispatch': f'the software SMI port 0x{SW_COMMAND_PORT:02X}',
    'SxDispatch': 'an S-state transition',
    'PeriodicTimer': 'the periodic timer',
    'UsbDispatch': 'a USB event',
    'GpiDispatch': 'a GPI pin change',
    'PowerButton': 'the power button',
    'StandbyButton': 'the standby button',
    'IoTrap': 'a trapped IO access',
}


def _dispatch_reason(entry: dict) -> str:
    """Why a registered handler is not in the harness set."""
    kind = (entry or {}).get('Dispatch') or ''
    if kind in DISPATCH_REASON:
        return DISPATCH_REASON[kind]
    if kind == 'SmiHandlerRegister' and not (entry or {}).get('Type'):
        return ('GUID-dispatched, but the type of the structure its CommBuffer carries was '
                'not resolved, so there are no fields to fill')
    if not kind:
        return 'not recorded by the analyser'
    return f'registered as {kind}, which is not a GUID dispatch'


def smi_inventory(smi_data: Dict[str, SmiInfo], discovered, recovered: dict,
                  unusable: dict, inventory: dict, sw_commands=None,
                  channel: str = '') -> Dict[str, dict]:
    """Every handler this tree registers and what this run did with it.

    The analyzer writes smi-handler-inventory.json before this module runs, so the field
    it puts there -- AnalyzerTyped -- is what the C++ could tell on its own: dispatched by
    GUID, with a payload type it parsed. The harness set is decided here and is a
    different set in both directions. recover_missing_handlers re-derives a GUID and a
    payload type from the source for handlers the analyzer recorded without one, and the
    unusable loop drops handlers whose payload cannot be carried into the harness. On
    EVAL-1 run 43452927684 SmmSpiHandler is AnalyzerTyped false and is harnessed:
    FuzzSmmSpiHandler was built from it, dispatched 5183 times and produced two of the
    run's findings, while the file this project quotes as its coverage statement said the
    handler could not be driven.

    The names are the union the coverage report walks, not the analyzer's own keys. The
    analyzer records what it parsed and discover_smi.py greps the tree, and neither is a
    superset of the other -- the file held 25 names on that run against the report's 32.
    """
    entries = {}
    for name in sorted(set(discovered or ()) | set(smi_data) | set(unusable)
                       | set(recovered) | set(inventory or ())):
        entry = dict((inventory or {}).get(name) or {})
        for field in ('Guid', 'Type', 'File', 'Dispatch', 'BufferProtocol'):
            entry.setdefault(field, '')
        entry.setdefault('AnalyzerTyped', False)
        #
        # Which channel reaches this handler, and -- where that channel has one -- the
        # address on it. Harnessable says what THIS run did; Channel says what any run
        # could do, which is the question a reader of a false Harnessable is actually
        # asking. Before this they got "cannot be driven" for a handler two bytes of IO
        # reach, and B2SmiDispatch was the only challenge-added driver with no coverage
        # because of it.
        #
        found = (sw_commands or ({}, {}))[0]
        entry['Channel'] = _channel_of(name, entry, sw_commands)
        entry['SwSmiInputValue'] = (
            f'0x{int(found[name]["value"]):02X}' if name in (found or {}) else '')
        #
        # What the generator holds wins over what the analyzer recorded, for every field
        # it resolves itself. A recovered handler has a GUID, a payload type and a
        # path that exist nowhere in the analyzer's output, and a handler the analyzer
        # typed as `void *` is harnessed against the struct its body casts to, so the
        # analyzer's answer describes the harness less well than the generator's. An empty
        # value is not an answer and never overwrites one.
        #
        info = smi_data.get(name)
        if info is not None:
            command = getattr(info, 'sw_smi_value', None)
            for field, value in (('Guid', info.guid), ('Type', info.type),
                                 ('File', info.file),
                                 ('BufferProtocol', getattr(info, 'buffer_protocol', '')),
                                 ('SwSmiInputValue',
                                  f'0x{int(command):02X}' if command is not None else '')):
                if value:
                    entry[field] = value
            if command is not None:
                entry['Channel'] = DISPATCH_CHANNEL['SwDispatch']
        entry['Harnessable'] = name in smi_data
        entry['Reason'] = '' if name in smi_data else not_harnessed_reason(
            name, unusable, recovered, inventory, sw_commands, channel)
        entries[name] = entry
    return entries


def write_smi_inventory(smi_file: str, entries: Dict[str, dict]) -> None:
    """Put the coverage statement back where the analyzer left its own.

    Beside smi-function-guid-map.json, under the name the analyzer already uses, because
    a second file would leave the first one being read. Written with sorted keys and four
    spaces, which is what nlohmann::json::dump(4) produces, so the two writers do not make
    a diff out of the formatting.
    """
    if not smi_file:
        return
    path = os.path.join(os.path.dirname(smi_file), 'smi-handler-inventory.json')
    try:
        with open(path, 'w') as handle:
            json.dump(entries, handle, indent=4, sort_keys=True)
    except OSError as exc:
        print(f'INFO: leaving {path} as the analyzer wrote it -- {exc}')


def analyze_smi(smi_data: Dict[str, SmiInfo],
                macros_val: Dict[str, Macros],
                macros_name: Dict[str, Macros],
                enum_map: Dict[str, EnumDef],
                cast_map: Dict[str, List[str]],
                types: Dict[str, TypeInfo],
                aliases: Dict[str, str],
                include_deps: Dict[str, List[str]],
                edk2_dir: str = "",
                discovered: List[str] = (),
                # Where the analyzer wrote its output. The coverage and cross-module
                # sections at the end of this function read two more files from that
                # directory; both loaders tolerate an absent file, so a caller that does
                # not pass this still gets the rest of the analysis.
                smi_file: str = "") -> Dict[str, FunctionBlock]:
    protocol_guids = set()
    driver_guids = set()
    unusable = {}
    includable = lambda info: bool(info and info.file and cleanup_paths([info.file]))

    # Handlers the source registers but the analyser never recorded. Resolving these from
    # source is the difference between a target list and a guess: SmmSpiHandler and
    # B2SmiDispatchHandle appear in DiscoveredSmi.txt and in no analysis output at all, so
    # before this they were not even dropped -- they were absent, which reads identically
    # to "this tree has no such handler".
    recovered = recover_missing_handlers(smi_data, discovered, types, edk2_dir)

    for smi in list(smi_data.values()):
        # Perform analysis on each SMI
        if smi.guid:
            protocol_guids.add(smi.guid)

        # The protocol whose buffer the handler insists on has to reach the INF too, or
        # the harness references a symbol nothing declares and does not link. It is the
        # same kind of entry as the handler's own GUID, so it goes in the same set.
        if getattr(smi, 'buffer_protocol', ''):
            protocol_guids.add(smi.buffer_protocol)

        # The harness declares a CommBuffer of the handler's own parameter type. The
        # analyser records VOID * for any handler that casts its buffer inside the body
        # instead of taking a typed parameter, and VOID * carries no fields to fuzz and no
        # size to send -- drop_one_pointer leaves "void", whose sizeof is 1 under clang, so
        # the harness would send a 1-byte message and call it the payload. The handler's
        # own cast says what the block really is, so read that.
        base = (smi.type or '').replace('*', '').strip()
        if base in ('', 'void', 'VOID') or not types.get(base):
            guessed = payload_from_source(smi.name, edk2_dir, types)
            if guessed:
                print(f'INFO: smi handler {smi.name} declares its comm buffer as '
                      f'{smi.type or "an untyped pointer"}; it casts to {guessed} *, '
                      f'using that')
                smi.type = f'{guessed} *'
                base = guessed

        info = types.get(base)
        if includable(info):
            all_includes.add(info.file)
            continue

        # Not includable. Re-emit the struct instead of dropping the handler: the headers
        # that declare comm-buffer blocks are private to their drivers by convention, so
        # dropping on this test discards precisely the vendor-specific handlers a campaign
        # exists to cover.
        order, reason = resolve_payload(base, types, aliases, includable)
        if order is None:
            print(f'INFO: dropping smi handler {smi.name} -- {reason}')
            unusable[smi.name] = reason
            continue
        for name in order:
            if name not in vendored_order:
                vendored_order.append(name)
            decl = types[name].file or 'an unrecorded header'
            print(f'INFO: smi handler {smi.name} -- carrying {name} in the harness; '
                  f'{decl} is private to its driver')

    for name in unusable:
        smi_data.pop(name, None)

    #
    # smi_data is final here -- everything source could recover is in it and everything
    # whose payload could not be carried is out -- so this is the first point at which the
    # inventory can be made a statement about the harnesses rather than a prediction of
    # them. The analyzer's file is read before it is rewritten, because the dispatch kind
    # it recorded is the reason most of the handlers that stay out stay out.
    #
    inventory = load_smi_inventory(smi_file)
    # What the OTHER channel reaches. A comm-buffer run cannot drive a software SMI
    # handler and should not pretend to, but it is the run that writes the file this
    # project quotes as its coverage statement -- so it is the run that has to stop
    # calling those handlers undrivable. The scan is one walk of the tree and only reads
    # files that mention SwSmiInputValue.
    sw_commands = sw_smi_commands(edk2_dir)
    write_smi_inventory(smi_file, smi_inventory(smi_data, discovered, recovered,
                                                unusable, inventory, sw_commands,
                                                DISPATCH_CHANNEL['SmiHandlerRegister']))

    report_smi_coverage(smi_data, discovered, recovered, unusable, edk2_dir, inventory,
                        sw_commands, DISPATCH_CHANNEL['SmiHandlerRegister'])

    #
    # What each handler does with the buffer, as opposed to what the buffer looks like.
    # Reported here rather than left for the fuzzer because an interface crossing is
    # visible in the source and a fuzzer has to guess its way to it: on EVAL-1 the two
    # findings this section names took 110255 iterations to reach and were filed against
    # the module that faulted rather than the one that handed it the arguments.
    #
    report_cross_module(load_smi_call_edges(smi_file))
    return smi_data, protocol_guids, driver_guids


def analyze_sw_smi(discovered_values: Dict[str, dict],
                   edk2_dir: str = "",
                   discovered: List[str] = (),
                   smi_file: str = "") -> Dict[str, SmiInfo]:
    """The target set for the software SMI channel: handler -> its command byte.

    Nothing of the comm-buffer analysis applies here and none of it is run. There is no
    GUID to resolve, no payload type to parse, no private header to vendor and no buffer
    protocol to wait on, because the channel hands the handler no buffer at all -- the two
    bytes the harness writes to the ports are the whole of the input. What a target needs
    is an address, and on this channel the address is the SwSmiInputValue.

    The request file is the authority, because it is what discover_smi.py wrote for the
    tree this campaign will build. The source scan runs anyway: it is how a handler the
    request file has no line for still gets into the inventory with its channel named, and
    it is the second opinion on every value the request file does carry. A disagreement is
    said out loud rather than silently resolved -- the two passes are separate code in
    separate repositories, and that is exactly the kind of drift a campaign cannot see.
    """
    found, stuck = sw_smi_commands(edk2_dir)
    smi_data = {}
    # `found` is in the union, not only the request file: this pass and discover_smi.py
    # are the same discovery written twice, in two repositories, and a handler the tree
    # registers with a resolvable command byte is a target whichever of them saw it. The
    # alternative is a target set that silently shrinks when one of the two drifts.
    for name in sorted(set(discovered_values or {}) | set(discovered or ()) | set(found)):
        asked = (discovered_values or {}).get(name)
        seen = found.get(name)
        if asked and seen and int(asked['value']) != int(seen['value']):
            print(f'INFO: sw smi handler {name} -- the request file says '
                  f'0x{int(asked["value"]):02X} and the tree says '
                  f'0x{int(seen["value"]):02X} at {seen["file"]}; using the tree')
            asked = None
        info = seen or asked
        if not info:
            if name in stuck:
                print(f'INFO: sw smi handler {name} is registered for {stuck[name]}, a '
                      f'value the dispatcher picks at registration time -- no command '
                      f'byte addresses it statically, so it is not a target')
            else:
                print(f'INFO: sw smi handler {name} has no registered command byte in '
                      f'this tree -- not a target')
            continue
        smi_data[name] = SmiInfo(name, '', '', info.get('file', ''),
                                 sw_smi_value=int(info['value']),
                                 sw_smi_spelling=info.get('spelling', ''))
        print(f'INFO: sw smi handler {name} -- command byte '
              f'0x{int(info["value"]):02X} from {info.get("file") or "the request file"}')

    #
    # `stuck` goes into the name set, not only into the narration. A handler whose command
    # byte the dispatcher picks at run time IS reached by this channel and is left out of
    # the target list for a reason that is about the registration, not about the handler
    # -- and a handler missing from the inventory altogether reads as a tree that has no
    # such handler. It was absent before: the request file has no line for it, by
    # construction, because the line would need a value.
    #
    accounted = sorted(set(discovered or ()) | set(stuck))
    inventory = load_smi_inventory(smi_file)
    write_smi_inventory(smi_file, smi_inventory(smi_data, accounted, {}, {}, inventory,
                                                (found, stuck),
                                                DISPATCH_CHANNEL['SwDispatch']))
    report_smi_coverage(smi_data, accounted, {}, {}, edk2_dir, inventory, (found, stuck),
                        DISPATCH_CHANNEL['SwDispatch'])
    return smi_data


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
                    include_deps_file: str,
                    input_file: str = ""):
    

    macros_val, macros_name = load_macros(macro_file)
    cast_map = load_castings(cast_file)
    enum_map = load_enums(enum_file)
    libmap = load_libmap(edk2_dir, os.path.join('/'.join(smi_file.split("/")[:-1]), 'libmap.json'))
    smi_data = load_smi_data(smi_file)
    include_deps = load_include_deps(include_deps_file)
    types = load_types(types_file)
    aliases = load_aliases(alias_file)

    # The handler list discover_smi.py wrote, which is the authoritative set of what this
    # tree registers. Without it the generator can only report on what the analyser
    # happened to record, and cannot tell "no such handler" from "not recorded".
    discovered = load_discovered(input_file)

    # Analyze the SMI data
    analyzed_data, protocol_guids, driver_guids = analyze_smi(
        smi_data, macros_val, macros_name, enum_map, cast_map, types, aliases, include_deps,
        edk2_dir, discovered, smi_file)


    update_includes = cleanup_paths(all_includes)
    # all_includes = get_union(processed_data, {})
    # all_includes = get_union({}, {})
    # sorted, not list: a set of strings iterates in a different order every run, which
    # made the include list and the resulting harness differ between identical runs
    collected_includes = sorted(set(update_includes) | default_includes | smi_includes)
    collected_includes = update_inc(collected_includes, libmap)
    libraries = update_libs(sorted(collect_libraries(collected_includes) | default_libraries), libmap)
    collected_includes = handle_include_deps(collected_includes, include_deps)
    

    vendored = render_payload(vendored_order, types)

    return analyzed_data, collected_includes, libraries, types, enum_map, aliases, protocol_guids, driver_guids, {}, vendored

def analyze_sw_smi_data(smi_file: str,
                        types_file: str,
                        alias_file: str,
                        enum_file: str,
                        edk2_dir: str,
                        include_deps_file: str,
                        input_file: str = ""):
    """The software SMI target set, shaped like analyze_smi_data's return.

    Returns the same ten things the comm-buffer analysis does, because main.py's emitter
    consumes them positionally and the only thing that differs between the two channels is
    what goes in the harness body. Most of them are empty here and that is not a gap: this
    channel has no payload type to parse, no macro to match and no private header to
    vendor, because it carries no payload at all.
    """
    libmap = load_libmap(edk2_dir, os.path.join('/'.join(smi_file.split("/")[:-1]),
                                                'libmap.json'))
    include_deps = load_include_deps(include_deps_file)
    types = load_types(types_file)
    aliases = load_aliases(alias_file)
    enum_map = load_enums(enum_file)

    smi_data = analyze_sw_smi(load_sw_discovered(input_file), edk2_dir,
                              load_discovered(input_file), smi_file)

    #
    # The harness itself locates nothing, so referenced_guids finds no protocol in it and
    # the INF would declare none. A DXE_DRIVER harness's depex floor is
    # gEfiSmmCommunicationProtocolGuid and a depex naming a GUID its INF does not declare
    # DOES NOT BUILD, so the declaration has to come from here.
    #
    # It is also the right floor for this channel and not only a build requirement:
    # PiSmmIpl publishes that protocol once the SMM core is up, and a port write before
    # the SMM core exists reaches nothing at all.
    #
    protocol_guids = {'gEfiSmmCommunicationProtocolGuid'}

    collected_includes = sorted(default_includes | smi_includes)
    collected_includes = update_inc(collected_includes, libmap)
    libraries = update_libs(
        sorted(collect_libraries(collected_includes) | default_libraries), libmap)
    collected_includes = handle_include_deps(collected_includes, include_deps)

    return (smi_data, collected_includes, libraries, types, enum_map, aliases,
            protocol_guids, set(), {}, [])
