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

    Tolerates the `--with-source` form, which appends `  // path/to/file.c`.
    """
    if not input_file or not os.path.isfile(input_file):
        return []
    names = []
    try:
        for line in open(input_file, errors='ignore'):
            name = line.split('//')[0].strip()
            if name:
                names.append(name)
    except OSError:
        return []
    return names


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
        smi_info = SmiInfo(smi, data["Type"], data["Guid"])
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
_DEFN = r'\b{name}\s*\((?P<params>[^;{{}}]*?)\)\s*{{'


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
    for cast in _re.finditer(rf'\(\s*([A-Za-z_]\w*)\s*\*\s*\)\s*\(?\s*{_re.escape(param)}\b',
                             body[:end]):
        candidate = cast.group(1)
        info = types.get(candidate)
        if info and getattr(info, 'fields', None):
            return candidate
    return None


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
            stuck[handler] = 'its comm buffer is never cast to a recorded type'
            continue
        smi_data[handler] = SmiInfo(handler, f'{payload} *', guid.group(1), path)
        print(f'INFO: recovered smi handler {handler} from source -- {guid.group(1)}, '
              f'comm buffer cast to {payload} *')
    return stuck


def report_smi_coverage(smi_data, discovered, recovered, unusable, edk2_dir='',
                        inventory=None) -> None:
    """Say what happened to every handler the source registers.

    `[PASS] discover ... 22 SMI handlers` counts registrations in source, and the number of
    harnesses can be less than half that without a word being said. A run that reports
    nothing in a tree's own drivers should be able to show whether they were clean or
    merely absent.
    """
    names = sorted(set(discovered or ()) | set(smi_data) | set(unusable) | set(recovered))
    if not names:
        return
    print(f'SMI coverage: {len(smi_data)} of {len(names)} registered handler(s) harnessed')
    for name in sorted(smi_data):
        flag, where = lifecycle_gate(name, edk2_dir)
        if flag:
            print(f'  CAVEAT: {name} is harnessed but gated on {flag} -- {where}')
    for name in names:
        if name in smi_data:
            continue
        why = unusable.get(name) or recovered.get(name)
        if not why:
            why = _dispatch_reason((inventory or {}).get(name) or {})
        print(f'  not harnessed: {name} -- {why}')


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
                  'can produce',
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

    report_smi_coverage(smi_data, discovered, recovered, unusable, edk2_dir,
                        load_smi_inventory(smi_file))

    #
    # What each handler does with the buffer, as opposed to what the buffer looks like.
    # Reported here rather than left for the fuzzer because an interface crossing is
    # visible in the source and a fuzzer has to guess its way to it: on EVAL-1 the two
    # findings this section names took 110255 iterations to reach and were filed against
    # the module that faulted rather than the one that handed it the arguments.
    #
    report_cross_module(load_smi_call_edges(smi_file))
    return smi_data, protocol_guids, driver_guids


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