from typing import List, Dict
import copy
import re
from common.types import FunctionBlock, Argument, TypeTracker, FieldInfo, TypeInfo, EnumDef
from common.utils import add_indents, remove_ref_symbols

aliases_map = {}
enum_map = {}
IDENTIFIER = re.compile(r'[A-Za-z_]\w*')

# this is a function that will return the underlying data type for any function
# so given EFI_PHYSICAL_ADDRESS it will return UINT64 by searching the aliases
# dictionary
def get_type(arg_type: str) -> str:
    if remove_ref_symbols(arg_type) in aliases_map.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases_map[remove_ref_symbols(arg_type)])
    else:
        return arg_type

# a parameter whose type is a function pointer cannot be declared from the recorded type,
# and there is nothing useful to fuzz in it: a random value is a jump to an address that
# is not code, so it is passed as NULL instead
def is_function_pointer(arg_type: str) -> bool:
    return "(*)" in arg_type.replace(" ", "")

# StrDuplicate takes a CHAR16 *, so only a real string literal can be passed to it
STRING_LITERAL_USAGE = re.compile(r'^\s*L?["\']')


# The only field types that can be declared as a bit field, and so the only ones that need
# to be read through a temporary rather than filled in place.
SCALAR_FIELD_TYPES = {
    'UINT8', 'UINT16', 'UINT32', 'UINT64', 'UINTN',
    'INT8', 'INT16', 'INT32', 'INT64', 'INTN',
    'BOOLEAN', 'CHAR8', 'CHAR16',
}


# How large a raw buffer argument gets. A VOID * or UINT8 * parameter is a buffer, and the
# size the callee is told to use is a separate, fuzzed argument. Allocating sizeof(UINTN)
# for it means any fuzzed size above 8 sends the driver past the end of the allocation:
# EfiBlockIo2's ReadBlocksEx was told to read a fuzzed 64 bit BufferSize into 8 bytes.
# A page absorbs the sizes worth exercising without pretending the pairing is understood.
FIRNESS_BUFFER_BYTES = 4096


# How many characters a fuzzed string argument gets. A callee walks a string to its
# terminator, so a one character buffer filled with fuzzed bytes has no terminator and
# sends StrLen off the end of the allocation into unmapped memory. That is a fault in the
# harness, not a finding: EdkiiVarCheck reported 914 "solutions" in 6225 iterations this way.
FIRNESS_STRING_CHARS = 32


def is_string_pointer(arg_type: str) -> bool:
    return has_pointer(arg_type) and 'CHAR' in remove_ref_symbols(arg_type).upper()


# A device path is walked node by node, and each step advances by the node's own Length.
# A zeroed EFI_DEVICE_PATH_PROTOCOL has Length 0, so NextDevicePathNode never moves and
# GetDevicePathSize runs off the allocation -- which is where the Shell's faults landed
# (DevicePathType, NextDevicePathNode, GetDevicePathSize). Give it a real End node: the
# same idea as terminating a fuzzed string, so the callee can walk it and stop.
DEVICE_PATH_TYPES = ('EFI_DEVICE_PATH_PROTOCOL', 'EFI_DEVICE_PATH')


def is_device_path(arg_type: str) -> bool:
    return remove_ref_symbols(arg_type).strip().upper() in (
        t.upper() for t in DEVICE_PATH_TYPES)


def end_device_path(variable: str) -> List[str]:
    return ['if (%s != NULL) {' % variable,
            '    %s->Type = 0x7F;' % variable,
            '    %s->SubType = 0xFF;' % variable,
            '    %s->Length[0] = 4;' % variable,
            '    %s->Length[1] = 0;' % variable,
            '}']


def set_undefined_constants(arg_type: str, array_like: bool = False) -> str:
    if has_pointer(arg_type):
        base = remove_ref_symbols(arg_type)
        if is_string_pointer(arg_type):
            # room for a string, not for one character
            return f'({arg_type})AllocateZeroPool({FIRNESS_STRING_CHARS} * sizeof({base}))'
        if array_like:
            # the call carries dimensions, so the callee walks this pointer as an array.
            # Over-allocating can never produce a false overflow; under-allocating always can
            return f'({arg_type})AllocateZeroPool({FIRNESS_BUFFER_BYTES})'
        # A raw buffer gets a page whichever direction it is. declare_var only page-sized
        # the OUT half, so an IN VOID*/UINT8* got sizeof(base) -- 8 bytes, or 1 -- while its
        # size argument was still bounded to FIRNESS_BUFFER_BYTES, telling the callee to
        # read 4096 bytes out of it. EFI_BLOCK_IO_PROTOCOL.WriteBlocks was one of ~79.
        if base.strip().upper() in ('VOID', 'UINT8', 'UINTN', 'CHAR8'):
            return f'({arg_type})AllocateZeroPool({FIRNESS_BUFFER_BYTES})'
        return "("+arg_type+")AllocateZeroPool(sizeof(" + base + "))"        
    elif "bool" in arg_type.lower():
        return "FALSE"
    else:
        return "0"
        

def generate_outputs(function: str,
                     all_args: Dict[str, List[Argument]],
                     arg_type_list: List[TypeTracker],
                     indent: bool,
                     prefix: str) -> List[str]:
    output = []
    tmp = []
    
    for arg_key, arguments in all_args.items():
        # an arg whose recorded usage is empty is indistinguishable from a normal one, and
        # cast_arg falls back to naming it, so it still needs its declaration here
        if "OUT" == arguments[0].arg_dir and not (arguments[0].variable == '__GEN_INPUT__' and arguments[0].usage):
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            tmp.extend(declare_var(function, arg_key, arguments, arg_type_list, False, False, False, False))
            # This is being used to handle the case where the output is a pointer ( so randomly create a pointer)
            tmp.append(f"UINT8* {function}_{arg_key}_OutputChoice = AllocateZeroPool(sizeof(UINT8));")
            tmp.append(f"ReadBytes(Input, sizeof(*{function}_{arg_key}_OutputChoice), (VOID *){function}_{arg_key}_OutputChoice);")
            tmp.append(f"if(*{function}_{arg_key}_OutputChoice % 2)")
            tmp.append("{")
            if arguments[0].pointer_count > 0:
                tmp.append(f"    ReadBytes(Input, sizeof(*{function}_{arg_key}), (VOID *){function}_{arg_key});")
            else:
                tmp.append(f"    ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});")
            tmp.append("}") 
    
    if len(tmp) > 0:
        output.append("/*")
        output.append("    Output Variable(s)")
        output.append("*/")
        output.extend(tmp)
     
    return add_indents(output, indent)


# properly add casts to the arguments based off the difference
# between the argument type and the type tracker type along with
# the pointer count
def cast_arg(function: str, 
             arg_key:str,
             arguments: List[Argument],
             arg_type_list: List[TypeTracker]) -> str:
    
    # a __GEN_INPUT__ arg is spelled by the expression the analysis recorded for it, but
    # that expression is empty whenever the analysis saw the argument without being able
    # to attribute a value to it, which leaves a hole in the call
    if arguments[0].variable == '__GEN_INPUT__' and arguments[0].usage:
        operand = arguments[0].usage
    else:
        operand = f'{function}_{arg_key}'

    update_arg = ""
    for arg in arg_type_list:
        if arg.name == arg_key:
            # cast_type carries the qualifier the declaration had to drop, when there is one
            cast_type = getattr(arguments[0], 'cast_type', '') or arguments[0].arg_type
            if arg.arg_type != arguments[0].arg_type:
                update_arg += f'({cast_type})'
            if arguments[0].pointer_count > arg.pointer_count:
                # only a named variable has an address to take. a recorded usage can be a
                # literal, and &0 is not an expression
                if IDENTIFIER.fullmatch(operand):
                    update_arg += f'&'
                elif arg.arg_type == arguments[0].arg_type:
                    update_arg += f'({arguments[0].arg_type})'
            # elif arg.fuzzable and arg.pointer_count > 0:
            #     update_arg += f'*'
            break

    return update_arg + operand
    

def call_function(function: str, 
                  function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str,
                  arg_type_list: List[TypeTracker],                    
                  indent: bool,
                  prefix: str,
                  types: Dict[str, TypeInfo] = None) -> List[str]:
    output = []
    lookup_function = function
    if prefix != "":
        lookup_function = f'{prefix}:{function}'
    # lowered: the service reads "protocol" when it came from a call site and "Protocols"
    # when it came from the requested service, and the capitalised form failed this test,
    # which emitted a bare call to a protocol member
    if "protocol" in services[lookup_function].service.lower() and protocol_variable:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[lookup_function].service or "Boot" in services[lookup_function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[lookup_function].service or "Runtime" in services[lookup_function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    elif "DS" in services[lookup_function].service or "DxeServices" in services[lookup_function].service:
        call_prefix = "gDS->"
    else:
        call_prefix = ""
    
    # a protocol member has to be called through the protocol pointer. emitting the bare
    # name only links when the implementation happens to be a non-static symbol that got
    # compiled into the harness, which is why most protocols failed with
    # "implicit declaration of function '<Member>'". a callback is handed the protocol as
    # its first argument too, so that alone does not make this a member: check the struct
    if call_prefix == "" and function_block.arguments:
        first = list(function_block.arguments.values())[0][0]
        if first.variable == "__PROTOCOL__":
            members = protocol_members(first.arg_type, types)
            if not members or function in members:
                call_prefix = "ProtocolVariable->"

    # Only the call under test should be able to report. Everything around it -- reading
    # the input, allocating buffers, filling structs -- is the harness's own work, and a
    # sanitizer report from there says something about the harness, not the firmware.
    # AsanSetFuzzingActive gates the escalation to the fuzzer, so bracketing the call with
    # it means only a fault inside the firmware counts as a solution.
    # An argument the analysis found no data for is recorded as arg_dir "OPTIONAL" with
    # usage NULL -- see the len(argument) == 0 branch in analyze.py -- and the call site
    # then passes a literal NULL. The declaration usually says nothing of the sort:
    # EBC_VM_TEST_EXECUTE takes "IN VM_CONTEXT *VmPtr", VM_CONTEXT has no public header so
    # nothing could be declared for it, and every call handed EbcDxe a NULL it is entitled
    # to dereference. That accounted for all 16 of EfiEbcVmTest's findings.
    #
    # Give the callee a valid zeroed buffer instead. It is declared VOID * because the real
    # type is exactly what could not be named; C converts void * to any object pointer
    # implicitly, so the call still compiles. Over-supplying a pointer is never a caller
    # contract violation, while passing NULL to a parameter that never allowed it always is.
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        if (argument.arg_dir == 'OPTIONAL' and has_pointer(argument.arg_type)
                and not is_function_pointer(argument.arg_type)):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            output.append(f'VOID *{function}_{name} = '
                          f'AllocateZeroPool({FIRNESS_BUFFER_BYTES});')

    # a handle the callee writes needs storage that is not the image handle. it starts
    # NULL because these are iterators: GetNextRootBridge reads the slot to decide where
    # to resume, and answers the first bridge only when it is given nothing. seeded with
    # the image handle it looks for a bridge that was never in the list and returns
    # NOT_FOUND every time, so nothing is ever produced for the rest of the sequence
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        if needs_handle_slot(argument):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            slot = handle_slot_name(function, name)
            output.append(f'{EFI_HANDLE_TYPE} {slot} = NULL;')
            if EFI_HANDLE_TYPE in live_types and 'IN' in argument.arg_dir:
                # resuming from a handle an earlier call produced walks the list
                output.extend(draw_live(EFI_HANDLE_TYPE, slot, f'{slot}_LiveChoice'))

    # an IN handle can be one an earlier call produced instead of the image handle, which
    # is what gets a sequence past the handle check at the top of most members
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        if (EFI_HANDLE_TYPE in live_types and is_efi_handle_arg(argument)
                and 'IN' in argument.arg_dir and argument.pointer_count == 0):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            slot = handle_slot_name(function, name)
            output.append(f'{EFI_HANDLE_TYPE} {slot} = ({EFI_HANDLE_TYPE})ImageHandle;')
            output.extend(draw_live(EFI_HANDLE_TYPE, slot, f'{slot}_LiveChoice'))

    # A size and the buffer it describes have to stay a pair. fuzzable_args bounds the
    # size by the allocation, and then substituting either half from the live tables
    # silently breaks that: the FVB harness clamped *NumBytes to 4096 and then replaced
    # the whole UINTN* with a live one holding 0xF20F, against a buffer that was still
    # 4096 bytes. That is a 62KB out of bounds write that belongs to the harness, and it
    # cost a matrix triage to work out. Neither half is eligible.
    pinned = set()
    all_tracked = [entry[0] for entry in function_block.arguments.values()]
    raw_buffer_call = takes_raw_buffer(all_tracked)
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        base = remove_ref_symbols(argument.arg_type).strip().upper()
        # Mirror the two conditions fuzzable_args clamps under. buffer_for_size only
        # pairs by stem (BufferSize -> Buffer); FVB spells it NumBytes/Buffer, so the
        # clamp there comes from the call simply having a raw buffer in it.
        paired = buffer_for_size(argument.param_name, function_block.arguments)
        if base in INTEGER_ARG_TYPES and (paired or raw_buffer_call):
            pinned.add(arg_key)
            if paired:
                pinned.add(paired)
        if (raw_buffer_call and argument.pointer_count > 0
                and base in ('VOID', 'UINT8', 'UINTN', 'CHAR8', 'CHAR16')):
            pinned.add(arg_key)

    # let a later call take what an earlier one produced
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        declared = declared_arg_type(argument)
        if (declared in live_types and 'IN' in argument.arg_dir
                and has_declared_variable(argument)
                and arg_key not in pinned):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            output.extend(draw_live(declared, f'{function}_{name}',
                                    f'{function}_{name}_LiveChoice'))
    output.append("FirnessSanitizer(TRUE);")
    if function_block.return_type == "EFI_STATUS":
        output.append(f"Status = {call_prefix}{function}(")
    else:
        output.append(f"{call_prefix}{function}(")

    for arg_key, arguments in function_block.arguments.items():
        original_arg_key = arg_key
        if prefix != "":
            arg_key = f'{prefix}_{arg_key}'
        # "IN" in arg_dir, not equality: the declaration loops use the substring test, so
        # an IN_OUT handle is skipped there. testing equality here let it fall through to
        # a variable name that nothing had declared
        if needs_handle_slot(arguments[0]):
            tmp = f"    &{handle_slot_name(function, arg_key)},"
        elif (EFI_HANDLE_TYPE in live_types and is_efi_handle_arg(arguments[0])
                and "IN" in arguments[0].arg_dir and arguments[0].pointer_count == 0):
            tmp = f"    {handle_slot_name(function, arg_key)},"
        elif "IN" in arguments[0].arg_dir and arguments[0].variable == "__HANDLE__":
            tmp = f"    ImageHandle,"
        elif "IN" in arguments[0].arg_dir and arguments[0].variable == "__PROTOCOL__":
            tmp = f"    ProtocolVariable,"
        elif arguments[0].arg_dir == "OPTIONAL" or is_function_pointer(arguments[0].arg_type):
            # NULL only converts to a pointer. edk2 has parameters that are unions or
            # scalars passed by value (ACPI_RESOURCE_HEADER_PTR), and those need a zero of
            # their own type instead
            if is_function_pointer(arguments[0].arg_type):
                # a garbage function pointer is a jump to nowhere, not a test
                tmp = f"    NULL,"
            elif has_pointer(arguments[0].arg_type):
                tmp = f"    {function}_{arg_key},"
            else:
                tmp = f"    ({arguments[0].arg_type}){{0}},"
        else:
            tmp = f"    {cast_arg(function, arg_key, arguments, arg_type_list)},"
        # if the last iteration remove the comma
        if original_arg_key == list(function_block.arguments.keys())[-1]:
            tmp = tmp[:-1]
        output.append(tmp)
    output.append(f");")
    output.append("FirnessSanitizer(FALSE);")
    # publish what this call produced for the rest of the sequence
    for arg_key, arguments in function_block.arguments.items():
        argument = arguments[0]
        declared = declared_arg_type(argument)
        if (declared in live_types and 'OUT' in argument.arg_dir
                and has_declared_variable(argument)):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            output.extend(register_live(declared, f'{function}_{name}'))
        produced_handle = produced_handle_type(argument)
        if produced_handle in live_types and produced_handle:
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            output.extend(register_live(produced_handle, f'{function}_{name}', deref=True))
        if EFI_HANDLE_TYPE in live_types and needs_handle_slot(argument):
            name = f'{prefix}_{arg_key}' if prefix else arg_key
            output.extend(register_live(EFI_HANDLE_TYPE,
                                        handle_slot_name(function, name)))

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def drop_one_pointer(arg_type: str) -> str:
    # the recorded type is spelled "EFI_BIS_DATA * *" as often as "EFI_BIS_DATA **", so a
    # literal replace('**', '*') leaves both stars in place. The declaration then carries one
    # more level than the type tracker records, and cast_arg adds an & on top of it, which
    # is how EFI_BIS_DATA ** reached the call site as EFI_BIS_DATA ***.
    base = arg_type.rstrip()
    if base.endswith('*'):
        base = base[:-1].rstrip()
    return base


def declare_var(function: str,
                arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool,
                fuzzable: bool,
                isStruct: bool,
                random,
                array_like: bool = False) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        arg_type = add_ptrs(arguments[0].arg_type, arguments[0].pointer_count-1) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        if arguments[0].arg_dir != "OUT":
            # not bailing out here on purpose: the call site names this variable either
            # way, so skipping the declaration only turns a bad argument into a
            # harness that does not compile
            print(f"WARNING: {function} {arg_key} has more than 2 pointers")
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count, fuzzable))
    elif arguments[0].pointer_count == 2:
        arg_type = "UINTN*" if "void" in arguments[0].arg_type.lower() else drop_one_pointer(arguments[0].arg_type)
        if random:
            arg_type = "UINTN*"
        arg_type_list.append(TypeTracker(arg_type, arg_key, 1, fuzzable))
        # output.append(f'UINT8 *{arg_key}_array = NULL;')
        # output.append(f'ReadBytes(&Input, sizeof({arg_key}_array), &{arg_key}_array);')
        # arg_type = f'{arg_type}[{arg_key}_array[0]]'
    else:
        if random:
            arg_type = "UINTN*"
        elif fuzzable:
            arg_type = "UINTN* " if "void" in arguments[0].arg_type.lower() else f'{(arguments[0].arg_type)}'
        else:
            arg_type = "UINTN* " if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
        arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count, fuzzable))
    if (arguments[0].pointer_count >= 2 and "OUT" in arguments[0].arg_dir
            and not "char" in arguments[0].arg_type.lower()):
        # An OUT X ** is the callee's to allocate: UEFI's convention is that it fills in
        # the pointer when it is NULL. Handing it a zeroed object instead means "write into
        # this one", and the object's own pointers are NULL -- HiiStringToImage took a
        # zeroed EFI_IMAGE_OUTPUT that way and drew through a NULL Image.Bitmap, which was
        # 6,130 of EfiHiiFont's faults. Start at NULL and let the callee do its job.
        output.append(f'{arg_type} {function}_{arg_key} = NULL;')
    elif (arguments[0].pointer_count > 0 and not "char" in arguments[0].arg_type.lower()) and not "IN" in arguments[0].arg_dir:
        # a raw buffer is sized by a separate argument the fuzzer also controls, so give it
        # a page rather than one element
        base = remove_ref_symbols(arg_type)
        raw_buffer = ('void' in arguments[0].arg_type.lower()
                      or base.strip().upper() in ('UINT8', 'UINTN', 'CHAR8')
                      or array_like)
        allocation = (str(FIRNESS_BUFFER_BYTES) if raw_buffer else f'sizeof({base})')
        output.append(f'{arg_type} {function}_{arg_key} = ({arg_type})AllocateZeroPool({allocation});')
    elif arguments[0].pointer_count == 0:
        # a struct passed by value has no pointer to allocate and cannot be assigned 0.
        # this is not limited to types the analysis recognised as structs: a member built
        # from its header can name one the types map never saw, such as
        # EFI_80211_MAC_ADDRESS. {0} initialises a scalar just as well as an aggregate.
        output.append(f'{arg_type} {function}_{arg_key} = {{0}};')
    else:
        output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arg_type, array_like)};")
        # if fuzzable :
        #     # output.append(f'{arg_type} {function}_{arg_key} = NULL;')
            
        # elif isStruct:
        #     output.append(f'{arg_type} {function}_{arg_key} = AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
        # else:
        #     output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arguments[0])};")
    
    # whichever branch declared it, a device path has to be walkable
    if has_pointer(arg_type) and is_device_path(arg_type):
        output.extend(end_device_path(f'{function}_{arg_key}'))
    return add_indents(output, indent)

SIZE_NAME_SUFFIXES = ('SIZE', 'LENGTH', 'LEN', 'COUNT', 'BYTES', 'NUMBEROFBYTES')

# Width/Height/Delta size a buffer just as surely as Size/Length do, but they were not in
# SIZE_NAME_SUFFIXES, so buffer_for_size never paired them and the pointer they describe was
# allocated as one element. EFI_GRAPHICS_OUTPUT_PROTOCOL.Blt got a BltBuffer of
# sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) -- four bytes -- and was then told to move
# Width * Height pixels through it, which QemuVideoDxe duly read, 32 bytes at a stride,
# straight into the redzones. That is a heap-buffer-overflow in the harness, not the driver,
# and it was the only genuine asan finding in matrix v7: 3 sites across 5 protocols.
DIMENSION_NAME_SUFFIXES = ('WIDTH', 'HEIGHT', 'DELTA', 'ROWS', 'COLUMNS', 'PIXELS')
# a dimension is squared (or cubed, with Delta) before it indexes the buffer, so it cannot be
# bounded by the buffer size the way a byte count is: 16 * 16 * 16 == FIRNESS_BUFFER_BYTES
FIRNESS_DIMENSION_MAX = 16


# Width and Height bound the extent, but the coordinates offset where that extent starts,
# and for the buffer side of a Blt they index the harness's allocation just as directly. A
# bounded Width with an unbounded DestinationY still walks off the end.
COORDINATE_PREFIXES = ('SOURCE', 'DESTINATION', 'DEST')


def optional_info_available() -> bool:
    """Whether the analysis this run was given records EDK2's OPTIONAL marker."""
    try:
        from data_analysis import analyze
        return bool(analyze.OPTIONAL_INFO_AVAILABLE)
    except Exception:
        return False


def is_optional_arg(arg, all_args, prefix: str = "") -> bool:
    if not all_args:
        return False
    entry = all_args.get(arg)
    if entry is None and prefix and arg.startswith(prefix):
        entry = all_args.get(arg[len(prefix) + 1:])
    return bool(entry and getattr(entry[0], 'is_optional', False))


def is_dimension_name(name: str) -> bool:
    if not name:
        return False
    upper = name.strip().upper()
    if upper.endswith(DIMENSION_NAME_SUFFIXES):
        return True
    # only SourceX/DestinationY and friends, never anything that merely ends in x -- Index
    # would otherwise qualify
    return upper.startswith(COORDINATE_PREFIXES) and upper.endswith(('X', 'Y'))


def has_dimension_arg(all_args) -> bool:
    """Whether this call sizes a buffer with dimensions rather than a byte count."""
    if not all_args:
        return False
    return any(is_dimension_name(args[0].param_name) for args in all_args.values())


# A field that describes the extent of its own struct. VARIABLE_POLICY_ENTRY.Size is the
# caller's statement of how long the (variable-length) entry is, and the driver copies that
# many bytes -- it has no other way to know. Fuzzing it makes the callee read past whatever
# the harness allocated, which is a caller contract violation rather than a firmware bug:
# it was every one of EdkiiVariablePolicy's 700 ASan reports, a 2,534 byte read in
# VariableSmmRuntimeDxe. Set it to the allocation instead of fuzzing it.
SELF_SIZE_FIELDS = ('SIZE', 'LENGTH', 'STRUCTSIZE', 'HEADERSIZE', 'ENTRYSIZE')


def describes_own_struct(field_name: str, fields) -> bool:
    # by suffix, not exact name: EFI_HII_PACKAGE_LIST_HEADER calls its own extent
    # PackageLength, and an exact-match rule let that through to be fuzzed
    name = (field_name or '').upper()
    suffix = next((s for s in SELF_SIZE_FIELDS if name.endswith(s)), '')
    if not suffix:
        return False
    stem = name[:-len(suffix)]
    # a size that names a buffer beside it describes that buffer, not the struct
    for other in fields or []:
        if has_pointer(other.type) and (other.name or '').upper() == stem:
            return False
    # names do not always correspond: EFI_ARP_CONFIG_DATA pairs SwAddressLength with
    # StationAddress, and reading the length as the struct's own made the driver copy
    # sizeof(struct) bytes out of an 8 byte buffer. If the struct holds any pointer at all,
    # the size may well be describing it, so only an exact size word is taken as the
    # struct's own here
    if name != suffix and any(has_pointer(o.type) for o in (fields or [])):
        return False
    return True


FIRNESS_LIST_ENTRIES = 4

def count_field_for(list_name: str, fields) -> str:
    """The field that counts the entries of a list field, e.g. OptionList -> OptionCount."""
    full = (list_name or '')
    stem = full
    for tail in ('List', 'Array', 'Buffer', 'Table'):
        if stem.endswith(tail) and len(stem) > len(tail):
            stem = stem[:-len(tail)]
            break
    # both spellings: EFI_DNS4_CONFIG_DATA counts DnsServerList with DnsServerListCount,
    # keeping the whole name, while others drop the tail and say DnsServerCount
    candidates = {full.upper(), stem.upper()}
    for other in fields or []:
        name = (other.name or '').upper()
        if has_pointer(other.type):
            continue
        for base in candidates:
            for suffix in SIZE_NAME_SUFFIXES:
                if name == base + suffix:
                    return other.name
    return ''


def buffer_for_size(size_name: str, all_args) -> str:
    """The arg_key of the buffer a size parameter names, e.g. BufferSize -> Buffer.

    UEFI spells the pair after the buffer: ReadBlocksEx takes BufferSize and Buffer,
    FatToStr takes FatSize and Fat, GetVariable takes DataSize and Data. Matching the
    stem is what lets a size be bounded by the buffer it actually describes rather than
    by a blanket constant.
    """
    upper = (size_name or '').upper()
    for suffix in SIZE_NAME_SUFFIXES:
        if not upper.endswith(suffix) or len(upper) == len(suffix):
            continue
        stem = upper[:-len(suffix)]
        prefixed = ''
        for other_key, other in (all_args or {}).items():
            name = (other[0].param_name or '').upper()
            if other[0].pointer_count == 0:
                continue
            if name == stem:
                return other_key
            # SNP spells the pair StatisticsSize/StatisticsTable, so an exact stem match
            # misses it and the size falls back to the blanket 4096 byte bound -- against
            # a buffer the harness allocated as sizeof (EFI_NETWORK_STATISTICS), 176
            # bytes. That produced two of the highest severity findings in the matrix,
            # both of them the harness. Exact still wins; this is the fallback.
            if not prefixed and name.startswith(stem):
                prefixed = other_key
        if prefixed:
            return prefixed
    return ''


def size_limit_for(paired: str, all_args) -> str:
    """The bound a size argument gets: the allocation of the buffer it names.

    Both the value and the pointer-to-value branch need this and only one of them had it.
    The pointer branch used the blanket FIRNESS_BUFFER_BYTES even when the pair was known,
    so SNP's Statistics got *StatisticsSize bounded at 4096 against a table allocated as
    sizeof (EFI_NETWORK_STATISTICS) -- 176 bytes. That is a 4KB overflow the harness asked
    for, and it came out of the matrix as a severity 5 heap-buffer-overflow write.
    """
    if not paired or not all_args or paired not in all_args:
        return str(FIRNESS_BUFFER_BYTES)
    paired_type = all_args[paired][0].arg_type
    base = remove_ref_symbols(paired_type).strip().upper()
    if is_string_pointer(paired_type):
        return f'({FIRNESS_STRING_CHARS} * sizeof({remove_ref_symbols(paired_type)}))'
    if base in ('VOID', 'UINT8', 'UINTN', 'CHAR8'):
        return str(FIRNESS_BUFFER_BYTES)
    return f'sizeof({remove_ref_symbols(paired_type)})'


# Types that are a pointer wearing an opaque name. Filling one from the input produces a
# wild pointer and nothing else: the firmware can NULL check it and then has to
# dereference, so every value except NULL and a real one is a #GP with no bug behind it.
#
# It also stops the campaign dead under libafl. Every seed crashed for EfiBlockIo2 and
# EfiAcpiSdt, so nothing was imported and the client stopped with "No entries in corpus"
# -- 1 execution against thousands on Simics, which records the crash and carries on.
#
# The live tables still supply real ones, which is the only way these should ever be
# non-NULL.
OPAQUE_HANDLE_TYPES = {'EFI_EVENT'}


def is_opaque_handle(arg_type: str) -> bool:
    """A handle: opaque by contract, a pointer in fact.

    Matched by shape rather than by a list, because edk2 keeps minting them --
    EFI_HANDLE, EFI_HII_HANDLE, EFI_ACPI_HANDLE, and every protocol that invents its own.
    Anything named *_HANDLE is one; EFI_EVENT is the same thing under a different name.
    """
    base = remove_ref_symbols(arg_type).strip().upper()
    return base in OPAQUE_HANDLE_TYPES or base.endswith('_HANDLE')


INTEGER_ARG_TYPES = {'UINT8', 'UINT16', 'UINT32', 'UINT64', 'UINTN',
                     'INT8', 'INT16', 'INT32', 'INT64', 'INTN'}


def takes_raw_buffer(arg_type_list) -> bool:
    """Whether any argument of this call is a raw buffer the fuzzer also sizes."""
    for tracked in arg_type_list:
        if tracked.pointer_count > 0 and remove_ref_symbols(
                tracked.arg_type).strip().upper() in ('VOID', 'UINT8', 'UINTN',
                                                      'CHAR8', 'CHAR16'):
            return True
    return False


def fuzzable_args(function: str,
                  arg: str, 
                  indent: bool,
                  arg_type_list: List[TypeTracker],
                  all_args=None,
                  prefix: str = "") -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    for arg_type in arg_type_list:
        if arg_type.name == arg:
            if arg_type.pointer_count == 0:
                if is_opaque_handle(arg_type.arg_type):
                    output.append(f'// {arg_type.arg_type} is a pointer behind an opaque '
                                  f'name: left NULL unless a live one is drawn below')
                else:
                    output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *)&{function}_{arg});')
                # In a call that also takes a raw buffer, the integer arguments are the
                # sizes and offsets into it. An unbounded one just tells the callee to walk
                # past the end of an allocation the harness made, which faults every time
                # and says nothing about the firmware -- EfiUnicodeCollation reported one
                # site 1089 times this way. Bound them to the buffer the harness allocates.
                if remove_ref_symbols(arg_type.arg_type).strip().upper() in INTEGER_ARG_TYPES:
                    own_name = ''
                    if all_args and arg in all_args:
                        own_name = all_args[arg][0].param_name
                    elif all_args:
                        # the key carries the prefix of an unrolled struct argument
                        bare = arg[len(prefix) + 1:] if prefix and arg.startswith(prefix) else arg
                        if bare in all_args:
                            own_name = all_args[bare][0].param_name
                    paired = buffer_for_size(own_name, all_args)
                    if is_dimension_name(own_name):
                        # bounding a dimension by the buffer size would still allow
                        # Width * Height to run far past it, so cap the dimension itself
                        output.append(f'{function}_{arg} = {function}_{arg} % '
                                      f'({FIRNESS_DIMENSION_MAX} + 1);')
                    elif paired:
                        # bound it by the allocation of the buffer it names, so the size the
                        # callee is given actually describes the memory it is handed
                        output.append(f'{function}_{arg} = {function}_{arg} % '
                                      f'({size_limit_for(paired, all_args)} + 1);')
                    elif takes_raw_buffer(arg_type_list):
                        output.append(f'{function}_{arg} = {function}_{arg} % '
                                      f'({FIRNESS_BUFFER_BYTES} + 1);')
                break
            else:
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                # case 1 frees the buffer and passes NULL. UEFI marks the parameters
                # that accept NULL with OPTIONAL, and passing one to a parameter without
                # it is a caller contract violation -- the callee is entitled to fault,
                # and the resulting NullPointerUse says nothing about the firmware. Only
                # offer the NULL arm where the declaration allows it. Analyses made
                # before the OPTIONAL pass carry no such information, and there the old
                # behaviour is kept rather than dropping NULL coverage everywhere.
                may_be_null = (not optional_info_available()
                               or is_optional_arg(arg, all_args, prefix))
                arms = 2 if may_be_null else 1
                output.append(f'UINT8 {function}_{arg}_choice = 0;')
                output.append(f'ReadBytes(Input, sizeof({function}_{arg}_choice), (VOID *)&{function}_{arg}_choice);')
                output.append(f'switch({function}_{arg}_choice % {arms})' + ' {')
                output.append(f'    case 0:')
                # everything this case emits dereferences the pointer, and the pointer can
                # be NULL: AllocateZeroPool can fail, and case 1 below deliberately frees
                # and nulls it, so a later step in the same iteration finds it gone. Six
                # NullPointerUse sites in matrix v7 were the generated harness faulting on
                # its own argument this way, not the firmware
                case0_start = len(output)
                if is_string_pointer(arg_type.arg_type):
                    # fill all but the last character and leave that one zero, so the
                    # string the callee receives is terminated inside its own allocation
                    output.append(f'        ReadBytes(Input, {FIRNESS_STRING_CHARS - 1} * '
                                  f'sizeof(*{function}_{arg}), (VOID *){function}_{arg});')
                    output.append(f'        {function}_{arg}[{FIRNESS_STRING_CHARS - 1}] = 0;')
                else:
                    output.append(f'        ReadBytes(Input, sizeof(*{function}_{arg}), (VOID *){function}_{arg});')
                    # A size handed over by pointer needs the same bound as one passed by
                    # value. UEFI spells most of these as IN OUT UINTN *BufferSize with an
                    # OUT VOID *Buffer beside it, so this was the common form and it was
                    # the unbounded one: eight fuzzed bytes made *BufferSize 2^64-1 over a
                    # 4096 byte buffer.
                    own_name = ''
                    if all_args and arg in all_args:
                        own_name = all_args[arg][0].param_name
                    elif all_args:
                        bare = arg[len(prefix) + 1:] if prefix and arg.startswith(prefix) else arg
                        if bare in all_args:
                            own_name = all_args[bare][0].param_name
                    paired = buffer_for_size(own_name, all_args)
                    # only a numeric pointee can be bounded: *p % N does not compile when p
                    # points at EFI_GUID or EFI_DEVICE_PATH_PROTOCOL
                    pointee = remove_ref_symbols(arg_type.arg_type).strip().upper()
                    if is_dimension_name(own_name) and pointee in INTEGER_ARG_TYPES:
                        output.append(f'        *{function}_{arg} = *{function}_{arg} % '
                                      f'({FIRNESS_DIMENSION_MAX} + 1);')
                    elif (paired or takes_raw_buffer(arg_type_list)) and pointee in INTEGER_ARG_TYPES:
                        output.append(f'        *{function}_{arg} = *{function}_{arg} % '
                                      f'({size_limit_for(paired, all_args)} + 1);')
                    elif is_device_path(arg_type.arg_type):
                        # the fill above overwrote the End node declare_var wrote, so the
                        # path the callee walks has Length 0 again
                        output.extend('        ' + line
                                      for line in end_device_path(f'{function}_{arg}'))
                case0_body = output[case0_start:]
                del output[case0_start:]
                if case0_body:
                    output.append(f'        if ({function}_{arg} != NULL) ' + '{')
                    output.extend('    ' + line for line in case0_body)
                    output.append('        }')
                output.append(f'        break;')
                if not may_be_null:
                    output.append('}')
                    break
                output.append(f'    case 1:')
                output.append('    {')
                output.append(f'        gBS->FreePool({function}_{arg});')
                output.append(f'        {function}_{arg} = NULL;')
                output.append(f'        break;')
                output.append('    }')
                output.append('}')
                break

    # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
    # output.append(f'UINT8 {function}_{arg}_choice = 0;')
    # output.append(f'ReadBytes(Input, sizeof({function}_{arg}_choice), (VOID *)&{function}_{arg}_choice);')
    # output.append(f'switch({function}_{arg}_choice % 2)' + ' {')
    # output.append(f'    case 0:')
    # output.append(f'        ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
    # output.append(f'        break;')
    # output.append(f'    case 1:')
    # output.append('    {')
    # output.append(f'        UINTN RandomPointer = 0;')
    # output.append(f'        ReadBytes(Input, sizeof(RandomPointer), (VOID *)&RandomPointer);')
    # for arg_type in arg_type_list:
    #     if arg_type.name == arg:
    #         output.append(f'        {function}_{arg} = ({arg_type.arg_type})RandomPointer;')
    #         break
    # output.append(f'        break;')
    # output.append('    }')
    # output.append('}')
    
    return add_indents(output, indent)

def generate_inputs(function_block: FunctionBlock, 
                    types: Dict[str, TypeInfo], 
                    services: Dict[str, FunctionBlock], 
                    protocol_variable: str, 
                    generators: Dict[str, FunctionBlock],
                    arg_type_list: List[TypeTracker],
                    indent: bool,
                    random: bool,
                    prefix: str) -> List[str]:
    output = []
    tmp = []
    for arg_key, arguments in function_block.arguments.items():
        if ("IN" in arguments[0].arg_dir and not arguments[0].variable == "__HANDLE__"
                and not arguments[0].variable == "__PROTOCOL__"
                and not is_function_pointer(arguments[0].arg_type)):
            is_struct = remove_ref_symbols(arguments[0].arg_type) in types.keys() or aliases_map.get(remove_ref_symbols(arguments[0].arg_type), "") in types.keys()
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            tmp.extend(declare_var(function_block.function, arg_key, arguments, arg_type_list, False, arguments[0].variable == "__FUZZABLE__", is_struct, random,
                                   has_dimension_arg(function_block.arguments)))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        # the same exclusions the declaration loop above applies. a handle or protocol
        # argument is spelled directly at the call site and never gets a variable, so
        # assigning to one emits a name that was never declared
        if ("IN" in arguments[0].arg_dir and not arguments[0].variable == "__HANDLE__"
                and not arguments[0].variable == "__PROTOCOL__"
                and not is_function_pointer(arguments[0].arg_type)):
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            total_elements = len(arguments)
            if total_elements > 1:
                output.append(f'UINT8* {function_block.function}_{arg_key}_choice = AllocateZeroPool(sizeof(UINT8));')
                output.append(f'ReadBytes(Input, sizeof(*{function_block.function}_{arg_key}_choice), (VOID *){function_block.function}_{arg_key}_choice);')
                output.append(f'switch(*{function_block.function}_{arg_key}_choice % {total_elements})' + ' {')
            for arg in arguments:
                if total_elements > 1:
                    output.append(f'    case {arguments.index(arg)}:')
                    output.append('    {')
                if arg.variable == "__FUZZABLE__" or random:
                    output.extend(fuzzable_args(function_block.function, arg_key, total_elements > 1, arg_type_list, function_block.arguments, prefix))
                elif "__CONSTANT" in arg.variable or "__ENUM_ARG__" in arg.variable:
                    output.extend(constant_args(function_block.function, arg_key, arg, total_elements > 1))
                elif "__FUNCTION_PTR__" in arg.variable:
                    output.extend(function_ptr_args(function_block.function, arg_key, arg, total_elements > 1))
                elif "__GUID__" in arg.variable:
                    output.extend(guid_args(function_block.function, arg_key, arg, total_elements > 1))
                elif (
                    arg.variable.startswith('__FUZZABLE_')
                    and arg.variable.endswith('_STRUCT__')
                ) or "__GENERATOR_FUNCTION__" in arg.variable:
                    output.extend(generator_struct_args(function_block.function, arg_key, arg, types, services, protocol_variable, generators, total_elements > 1))
                        
                output.append("")
                if total_elements > 1:
                    output.append(f'        break;')
                    output.append('    }')
            if total_elements > 1:
                output.append('}')

    return add_indents(output, indent)

def constant_args(function: str,
                  arg_key: str, 
                  arg: Argument,
                  indent: bool) -> List[str]:
    output = []
    output.append("// Constant Variable Initialization")
    if arg.variable == "__ENUM_ARG__":
        output.append(f'UINT8* {function}_{arg_key}_choice = AllocateZeroPool(sizeof(UINT8));')
        output.append(f'ReadBytes(Input, sizeof(*{function}_{arg_key}_choice), (VOID *){function}_{arg_key}_choice);')
        usages = []
        matched_enum = enum_map.get(remove_ref_symbols(arg.arg_type), None)
        if matched_enum is None:
            matched_enum = enum_map.get(remove_ref_symbols(arg.data_type), EnumDef())
        # an enum declared in a driver's own header cannot be named from the harness:
        # TerminalTypeLinux lives in MdeModulePkg/Universal/Console/TerminalDxe/Terminal.h,
        # outside any Include directory, so the constants are dropped and the argument is
        # read from the input instead
        values = matched_enum.values if is_nameable_enum(matched_enum) else []
        for enum in values:
            tmp = copy.copy(arg)
            tmp.usage = enum
            usages.append(tmp)
        output.append(f'switch(*{function}_{arg_key}_choice % {len(usages)+1})' + ' {')
        for index, argument in enumerate(usages):
            output.append(f'    case {index}:')
            if argument.usage == "":
                output.append(f'        {function}_{arg_key} = {set_undefined_constants(argument.arg_type)};')
            elif ("char" in argument.arg_type.lower()
                  and STRING_LITERAL_USAGE.match(argument.usage or '')):
                output.append(f'        {function}_{arg_key} = StrDuplicate({argument.usage});')
            elif "char" in argument.arg_type.lower():
                # a recorded usage that is not a string literal cannot be handed to
                # StrDuplicate, which takes a CHAR16 *; read the buffer from the input
                if has_pointer(argument.arg_type):
                    output.append(f'        ReadBytes(Input, sizeof(*{function}_{arg_key}), (VOID *){function}_{arg_key});')
                else:
                    output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});')
            elif has_pointer(argument.arg_type):
                # an OUT enum arrives as a pointer, and the declaration above already
                # allocated it. the enumerator is a value, so it belongs in the pointee --
                # assigning it to the pointer itself does not compile
                output.append(f'        *{function}_{arg_key} = {argument.usage};')
            else:
                output.append(f'        {function}_{arg_key} = {argument.usage};')
            output.append(f'        break;')
        output.append(f'    case {len(usages)}:')
        if has_pointer(arg.arg_type):
            output.append(f'        ReadBytes(Input, sizeof(*{function}_{arg_key}), (VOID *){function}_{arg_key});')
        else:
            output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});')
        output.append(f'        break;')
        output.append('}')
    else:
        if arg.usage == "":
            output.append(f'{function}_{arg_key} = {set_undefined_constants(arg.arg_type)};')
        elif "char" in arg.arg_type.lower() and STRING_LITERAL_USAGE.match(arg.usage or ''):
            output.append(f'{function}_{arg_key} = StrDuplicate({arg.usage});')
        elif "char" in arg.arg_type.lower():
            if has_pointer(arg.arg_type):
                output.append(f'ReadBytes(Input, sizeof(*{function}_{arg_key}), (VOID *){function}_{arg_key});')
            else:
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});')
        else:
            output.append(f'{function}_{arg_key} = {arg.usage};')

    return add_indents(output, indent)

def function_ptr_args(function:str, 
                      arg_key: str, 
                      arg: Argument,
                      indent: bool) -> List[str]:
    output = []
    output.append("// Function Pointer Variable Initialization")
    output.append(f'{function}_{arg_key} = {arg.usage};')
    
    # VOID* {{ arg_key }};

    return add_indents(output, indent)

def guid_args(function:str, 
              arg_key: str, 
              arg: Argument,
              indent: bool) -> List[str]:
    output = []
    output.append("// EFI_GUID Variable Initialization")
    # the recorded name is dropped when the harness cannot reference it, and an empty
    # usage here would emit "X = ;"
    if arg.usage:
        output.append(f'{function}_{arg_key} = {arg.usage};')
    else:
        output.append(f'{function}_{arg_key} = {set_undefined_constants(arg.arg_type)};')

    return add_indents(output, indent)

# the fields of the protocol struct behind this argument type, empty when it cannot be
# resolved -- callers treat that as "no opinion" rather than as "not a member"
def protocol_members(arg_type: str, types: Dict[str, TypeInfo]) -> set:
    if not types:
        return set()
    name = remove_ref_symbols(arg_type)
    struct = types.get(name) or types.get(aliases_map.get(name, ""))
    fields = getattr(struct, 'fields', None)
    return {field.name for field in fields} if fields else set()

# only a header under some package's Include directory can be pulled into the harness, so
# only the constants declared in one can be written by name
def is_nameable_enum(enum_def) -> bool:
    path = (getattr(enum_def, 'file', '') or '').replace('\\', '/').lower()
    return '/include/' in path


def has_pointer(arg_type: str) -> bool:
    return arg_type.count('*') > 0

def generator_struct_args(function: str, 
                          arg_key: str, 
                          arg: Argument, 
                          types: Dict[str, TypeInfo], 
                          services: Dict[str, FunctionBlock], 
                          protocol_variable: str,
                          generators: Dict[str, FunctionBlock],
                          indent: bool) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    # if len(arguments) > 1:
    #     output.append(f'UINT8 {function}_{arg_key}_choice = 0;')
    #     output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), &{function}_{arg_key}_choice);')
    #     output.append(f'switch({function}_{arg_key}_choice % {len(arguments)})' +' {')
    #     for index, argument in enumerate(arguments):
    #         output.append(f'    case {index}: ' + '{')
    #         if argument.variable.startswith('__FUZZABLE_') and argument.variable.endswith('_STRUCT__'):
    #             for field in types[remove_ref_symbols(argument.arg_type)]:
    #                 output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}->{field.name}), &({function}_{arg_key}->{field.name}));')
    #         elif "__GENERATOR_FUNCTION__" in argument.variable:
    #             generator_outputs = function_body(generators[argument.assignment], services, protocol_variable, generators, types, True)
    #             for line in generator_outputs:
    #                 output.append(f'    {line}')
    #             for generator_arg_key, generator_arguments in generators[argument.assignment].arguments.items():
    #                 if "OUT" in generator_arguments[0].arg_dir and not "IN" in generator_arguments[0].arg_dir:
    #                     if argument.arg_type in generator_arguments[0].arg_type:
    #                         output.append(f'        {function}_{arg_key} = {argument.assignment}_{generator_arg_key};')
    #         output.append(f'        break;')
    #         output.append('    }')
    #     output.append('}')
    # else:
    if arg.variable.startswith('__FUZZABLE_') and arg.variable.endswith('_STRUCT__'):
        struct_type = remove_ref_symbols(arg.arg_type) if len(types.get(remove_ref_symbols(arg.arg_type), TypeInfo()).fields) > 0 else (aliases_map.get(remove_ref_symbols(arg.arg_type), None))
        # a struct passed by value is reached through '.', and taking the address of a
        # member of a pointer that was never declared as one does not compile
        accessor = '->' if arg.pointer_count > 0 else '.'
        # types is a defaultdict(list), so indexing a struct name it does not know returns
        # a list rather than a TypeInfo and inserts the junk entry as a side effect
        struct_fields = types.get(struct_type, TypeInfo()).fields
        for field in struct_fields:
            # only a plainly nameable type can back a temporary. an array carries its
            # extent in the type and is not assignable, and an anonymous union is reported
            # as "union (unnamed union at ...)", which is not a declaration. both have a
            # size and an address, so they are filled in place
            nameable = re.fullmatch(r'[A-Za-z_]\w*', field.type.strip()) is not None
            # the temporary below exists for bit fields, which have neither a size nor an
            # address. only the integer types can be bit fields, and copying anything larger
            # through a temporary makes clang emit a memcpy -- which does not exist in UEFI
            # and fails at link time with "undefined reference to memcpy"
            scalar = field.type.strip().upper() in SCALAR_FIELD_TYPES
            # a random function pointer is not an input worth generating: the first call
            # through it jumps to an arbitrary address and everything reported afterwards
            # is noise. the field keeps the zero AllocateZeroPool gave it
            if is_function_pointer(field.type):
                continue
            field_ref = f'{function}_{arg_key}{accessor}{field.name}'
            # a scalar only: EFI_DEVICE_PATH_PROTOCOL.Length is UINT8[2], an array that
            # carries the node's length and is not assignable
            if (not has_pointer(field.type)
                    and field.type.strip().upper() in SCALAR_FIELD_TYPES
                    and describes_own_struct(field.name, struct_fields)):
                output.append(f'{field_ref} = sizeof({struct_type});')
                continue
            # Pointer fields are decided before the nameable test on purpose. A type like
            # "EFI_DHCP6_PACKET_OPTION **" is not a bare identifier, so it used to fall to
            # the fill-in-place branch, which writes random bytes into the pointer itself
            # and hands the driver a wild address to dereference. That was the largest
            # remaining source of faults: Dhcp6Impl.c dereferences OptionList[Index]->OpCode.
            if has_pointer(field.type):
                if field.type.count('*') >= 2 and 'VOID' not in field.type.upper():
                    # a list of pointers, counted by a sibling field. One zeroed entry is
                    # worse than none, since each entry is dereferenced: allocate the
                    # entries, point each at a zeroed object, and hold the count to what
                    # was actually built
                    counter = count_field_for(field.name, struct_fields)
                    output.append(f'{field_ref} = ({field.type})AllocateZeroPool('
                                  f'{FIRNESS_LIST_ENTRIES} * sizeof(*{field_ref}));')
                    output.append(f'if ({field_ref} != NULL) ' + '{')
                    output.append(f'    for (UINTN FirnessEntry = 0; FirnessEntry < '
                                  f'{FIRNESS_LIST_ENTRIES}; FirnessEntry++) ' + '{')
                    output.append(f'        {field_ref}[FirnessEntry] = AllocateZeroPool('
                                  f'sizeof(**{field_ref}));')
                    output.append('    }')
                    output.append('}')
                    if counter:
                        counter_ref = f'{function}_{arg_key}{accessor}{counter}'
                        output.append(f'{counter_ref} = {counter_ref} % '
                                      f'({FIRNESS_LIST_ENTRIES} + 1);')
                else:
                    # the struct came from AllocateZeroPool, so this field is NULL: give it
                    # something to point at before writing through it. A raw buffer gets a
                    # page, because a sibling field states its length and the callee copies
                    # that many bytes -- EFI_ARP_CONFIG_DATA.StationAddress with an 8 byte
                    # allocation and SwAddressLength saying more is a read off the end
                    base_type = remove_ref_symbols(field.type).strip().upper()
                    counter = count_field_for(field.name, struct_fields)
                    if counter and base_type not in ('VOID', 'UINT8', 'UINTN', 'CHAR8'):
                        # a plain array counted by a sibling: EFI_DNS4_CONFIG_DATA pairs
                        # DnsServerList with DnsServerListCount, and one element against an
                        # unbounded count is the same read off the end, one indirection
                        # shallower than the pointer-list case above
                        field_size = f'({FIRNESS_LIST_ENTRIES} * sizeof(*{field_ref}))'
                        counter_ref = f'{function}_{arg_key}{accessor}{counter}'
                        pending_count_bound = (f'{counter_ref} = {counter_ref} % '
                                               f'({FIRNESS_LIST_ENTRIES} + 1);')
                    elif base_type in ('VOID', 'UINT8', 'UINTN', 'CHAR8'):
                        field_size = str(FIRNESS_BUFFER_BYTES)
                        pending_count_bound = ''
                    else:
                        field_size = f'sizeof(*{field_ref})'
                        pending_count_bound = ''
                    output.append(f'{field_ref} = ({field.type})AllocateZeroPool({field_size});')
                    output.append(f'if ({field_ref} != NULL) ' + '{')
                    output.append(f'    ReadBytes(Input, {field_size}, (VOID *)({field_ref}));')
                    output.append('}')
                    if pending_count_bound:
                        output.append(pending_count_bound)
            elif is_opaque_handle(field.type):
                # A struct field that is a pointer behind an opaque name. Same reason as
                # the argument case: EFI_BLOCK_IO2_TOKEN.Event filled from the input is a
                # wild pointer, and CoreSignalEvent dereferences whatever it is given.
                output.append(f'// {field.type} is a pointer behind an opaque name: '
                              f'left as allocated')
            elif not nameable or not scalar:
                # an array or an anonymous union: it has a size and an address, so it is
                # filled where it sits
                output.append(f'ReadBytes(Input, sizeof({field_ref}), (VOID *)&({field_ref}));')
            else:
                # through a temporary of the field's own type: a bit field has neither a
                # size nor an address of its own, so sizeof and & on one do not compile
                output.append('{')
                output.append(f'    {field.type} Firness_{field.name};')
                output.append(f'    ReadBytes(Input, sizeof(Firness_{field.name}), (VOID *)&Firness_{field.name});')
                output.append(f'    {field_ref} = Firness_{field.name};')
                output.append('}')
    elif "__GENERATOR_FUNCTION__" in arg.variable:
        # a private copy per use: the wiring below rewrites the producer's OUT parameter to
        # name the consumer's variable, and generators are shared between consumers. when a
        # later consumer did not re-match that parameter it inherited the previous one's
        # name, so FuzzFreeBuffer referred to FuzzMap's Map_Arg_4
        producer = copy.deepcopy(generators[arg.assignment])
        # find the arg in the generator that is OUT and has the same type as the in function_arg_key
        for gen_arg_key, gen_arg in producer.arguments.items():
            if gen_arg[0].arg_dir != 'OUT':
                continue
            # an OUT parameter usually carries one more level of indirection than the
            # value it yields: AllocateBuffer writes a VOID* through a VOID**, and Map
            # then takes that VOID*. requiring the spellings to be equal meant those
            # producers were found by the analysis and then never wired to anything
            same_base = remove_ref_symbols(arg.arg_type) == remove_ref_symbols(gen_arg[0].arg_type)
            indirect = same_base and gen_arg[0].pointer_count == arg.pointer_count + 1
            # "EFI_DEVICE_PATH_PROTOCOL * *" and "EFI_DEVICE_PATH_PROTOCOL **" are the same
            # type spelled two ways, and comparing the strings missed the match
            same_type = re.sub(r'\s+', '', arg.arg_type or '') == re.sub(r'\s+', '', gen_arg[0].arg_type or '')
            if same_type or indirect:
                gen_arg[0].variable = "__GEN_INPUT__"
                # what the consumer's variable is actually declared as, which is not always
                # the argument's own depth: declare_var drops a level for a two star
                # argument, so even an identical spelling needs its address taken here
                declared_depth = arg.pointer_count - 1 if arg.pointer_count == 2 else arg.pointer_count
                gen_arg[0].usage = (f'&{function}_{arg_key}'
                                    if gen_arg[0].pointer_count > declared_depth
                                    else f'{function}_{arg_key}')
                break
        function_name = arg.assignment
        prefix = ""
        if ':' in arg.assignment:
            prefix = arg.assignment.split(':')[0]
            function_name = arg.assignment.split(':')[-1]

        producer.function = function_name
        services[arg.assignment].function = function_name
        producer_first = producer.arguments.get('Arg_0')
        if "protocol" in producer.service.lower() and producer_first:
            protocol_variable = f'{protocol_variable}_{prefix}'
            output.append(f"    {producer_first[0].arg_type} {protocol_variable} = NULL;")
            output.append(f'    Status = SystemTable->BootServices->LocateProtocol(&{producer_first[0].usage}, NULL, (VOID *)&{protocol_variable});')
            output.append('    if (EFI_ERROR(Status)) {')
            output.append('        return Status;')
            output.append('    }')
        output.extend(function_body(producer, services, protocol_variable, generators, types, indent, False, prefix))        

    return add_indents(output, indent)

def function_body(function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str, 
                  generators: Dict[str, FunctionBlock], 
                  types: Dict[str, TypeInfo],
                  indent: bool,
                  random: bool = False,
                  prefix: str = "") -> List[str]:
    output = []
    arg_type_list = []
    output.extend(generate_inputs(function_block, types, services, protocol_variable, generators, arg_type_list, False, random, prefix))
    output.extend(generate_outputs(function_block.function, function_block.arguments, arg_type_list, False, prefix))
    output.extend(call_function(function_block.function, function_block, services, protocol_variable, arg_type_list, False, prefix, types))

    return add_indents(output, indent)


# Threading what one call produces into what a later call consumes.
#
# Every Fuzz function used to build all of its arguments from scratch, so a sequence that
# called Open and then Read discarded the handle Open produced and handed Read a freshly
# zeroed one. The driver accumulated state but the objects did not flow, which is why so
# many calls returned early and why median coverage sat far below the best protocols.
#
# A type that some function yields as OUT and another takes as IN is worth carrying. Each
# such type gets a small table; a call registers what it produced, and a later call may
# draw from it. The fuzzer chooses whether to draw, so both the fresh and the threaded
# input stay reachable. tsffs restores the snapshot per iteration, so the tables reset
# with it and state never leaks between iterations.
FIRNESS_LIVE_SLOTS = 4
live_types = set()


def has_declared_variable(argument) -> bool:
    """Whether this argument actually gets a variable of its own.

    Several kinds are spelled straight into the call instead: the protocol and image
    handle, a function pointer, an OPTIONAL argument passed as NULL, and a __GEN_INPUT__
    whose recorded usage is an expression. Threading a value into one of those names emits
    an assignment to an identifier that was never declared.
    """
    if is_function_pointer(argument.arg_type):
        return False
    if argument.variable in ('__HANDLE__', '__PROTOCOL__'):
        return False
    if argument.arg_dir == 'OPTIONAL':
        return False
    if argument.variable == '__GEN_INPUT__' and argument.usage:
        return False
    return 'IN' in argument.arg_dir or argument.arg_dir == 'OUT'


def declared_arg_type(argument) -> str:
    """The type declare_var actually gives this argument's variable.

    It is not the parameter type: a two pointer argument is declared one level shallower
    and passed with &, so a table typed on the parameter would not be assignable to it.
    """
    arg_type = argument.arg_type
    if 'void' in arg_type.lower():
        return ''          # declare_var rewrites these to UINTN*, not worth threading
    if argument.pointer_count == 2:
        return drop_one_pointer(arg_type).strip()
    if argument.pointer_count > 2:
        return arg_type.strip()
    return arg_type.strip()


EFI_HANDLE_TYPE = 'EFI_HANDLE'


def is_efi_handle_arg(argument) -> bool:
    """A __HANDLE__ argument, which analyze.py stamps on anything EFI_HANDLE shaped."""
    return (argument.variable == '__HANDLE__'
            and EFI_HANDLE_TYPE in argument.arg_type)


def needs_handle_slot(argument) -> bool:
    """Whether this __HANDLE__ argument must be given a slot of its own.

    FirnessMain passes the image handle by value into a parameter declared EFI_HANDLE *,
    so inside a harness the name ImageHandle holds a handle wearing a pointer's type.
    Handing that to an IN parameter works out, but handing it to an OUT one lets the
    callee write through it: GetNextRootBridge(IN_OUT EFI_HANDLE *) stores the root bridge
    handle over the first bytes of the image handle's own object. The fault that follows
    belongs to the harness, not the firmware.
    """
    return (is_efi_handle_arg(argument) and 'OUT' in argument.arg_dir
            and argument.pointer_count >= 1)


def handle_slot_name(function: str, name: str) -> str:
    return f'{function}_{name}_Handle'


def is_handle_typedef(arg_type: str) -> bool:
    """Whether this spelling is an opaque handle: a typedef to a pointer, written bare.

    EFI_HII_HANDLE is "void *" behind the typedef, so it carries an object exactly the way
    an explicit pointer does, but it has no star to see. The alias chain is what separates
    it from the scalar handles: TPM_HANDLE resolves to UINT32 and SMBIOS_HANDLE to UINT16,
    and those are values, not objects worth threading.
    """
    name = remove_ref_symbols(arg_type).strip()
    if '*' in arg_type or not name:
        return False
    for _ in range(8):                     # bounded: aliases.json has chains, not cycles
        resolved = aliases_map.get(name)
        if resolved is None:
            return False
        if '*' in resolved:
            return True
        name = remove_ref_symbols(resolved).strip()
    return False


def produced_handle_type(argument) -> str:
    """The handle an OUT argument fills in, for a caller that passes T * to receive a T.

    NewPackageList takes OUT EFI_HII_HANDLE *, and declare_var gives it a one element
    buffer; the object the rest of the sequence wants is the EFI_HII_HANDLE inside it.
    """
    if 'OUT' not in argument.arg_dir or argument.pointer_count != 1:
        return ''
    if not has_declared_variable(argument):
        return ''
    base = drop_one_pointer(argument.arg_type).strip()
    return base if is_handle_typedef(base) else ''


def consumed_handle_type(argument) -> str:
    """The handle an IN argument takes by value."""
    if 'IN' not in argument.arg_dir or argument.pointer_count != 0:
        return ''
    if not has_declared_variable(argument):
        return ''
    base = argument.arg_type.strip()
    return base if is_handle_typedef(base) else ''


def threadable_types(functions):
    """Types produced as OUT by one call and consumed as IN by another."""
    produced, consumed = set(), set()
    for block in functions.values():
        for arguments in block.arguments.values():
            argument = arguments[0]
            if not has_pointer(argument.arg_type):
                continue
            if not has_declared_variable(argument):
                continue
            name = declared_arg_type(argument)
            if not name:
                continue
            if 'OUT' in argument.arg_dir:
                produced.add(name)
            if 'IN' in argument.arg_dir:
                consumed.add(name)
    # handles cross the seam between protocols: HiiDatabase.NewPackageList makes the
    # EFI_HII_HANDLE that HiiString.NewString and HiiFont.StringIdToImage both need, and
    # without it every one of those consumers is called on the {0} it was declared with
    for block in functions.values():
        for arguments in block.arguments.values():
            argument = arguments[0]
            produced_handle = produced_handle_type(argument)
            if produced_handle:
                produced.add(produced_handle)
            consumed_handle = consumed_handle_type(argument)
            if consumed_handle:
                consumed.add(consumed_handle)
            # EFI_HANDLE never reaches the loops above, because analyze.py replaces the
            # variable with __HANDLE__ before the generator sees it. The handle a root
            # bridge or package list lookup hands back is the one thing that makes the
            # rest of those protocols reachable, so read the flow off the direction
            if needs_handle_slot(argument):
                produced.add(EFI_HANDLE_TYPE)
            if (is_efi_handle_arg(argument) and 'IN' in argument.arg_dir
                    and argument.pointer_count == 0):
                consumed.add(EFI_HANDLE_TYPE)
    return sorted(produced & consumed)


def live_table_name(arg_type: str) -> str:
    return 'FirnessLive_' + re.sub(r'\W', '_', arg_type.strip())


def live_tables(threadable) -> List[str]:
    output = []
    if not threadable:
        return output
    output.append('//')
    output.append('// Objects produced by one call in a sequence, available to later ones.')
    output.append('// Reset every iteration, because the fuzzer restores the machine.')
    output.append('//')
    for arg_type in threadable:
        table = live_table_name(arg_type)
        output.append(f'{arg_type} {table}[{FIRNESS_LIVE_SLOTS}];')
        output.append(f'UINTN {table}_Count = 0;')
    output.append('')
    return output


def register_live(arg_type: str, variable: str, deref: bool = False) -> List[str]:
    table = live_table_name(arg_type)
    # a handle arrives through a one element out buffer, so the buffer has to be checked
    # before the handle inside it can be
    guard = f'{variable} != NULL && *{variable} != NULL' if deref else f'{variable} != NULL'
    value = f'*{variable}' if deref else variable
    return [f'if ({table}_Count < {FIRNESS_LIVE_SLOTS} && {guard}) ' + '{',
            f'    {table}[{table}_Count++] = {value};',
            '}']


def draw_live(arg_type: str, variable: str, chooser: str) -> List[str]:
    table = live_table_name(arg_type)
    return [f'UINT8 {chooser} = 0;',
            f'ReadBytes(Input, sizeof({chooser}), (VOID *)&{chooser});',
            # only draw when something has been produced, and let the fuzzer decide
            f'if ({table}_Count > 0 && ({chooser} & 1)) ' + '{',
            f'    {variable} = {table}[{chooser} % {table}_Count];',
            '}']


def harness_generator(services: Dict[str, FunctionBlock], 
                      functions: Dict[str, FunctionBlock], 
                      types: Dict[str, TypeInfo], 
                      generators: Dict[str, FunctionBlock],
                      aliases: Dict[str, str],
                      enums: Dict[str, EnumDef],
                      random: bool = False) -> List[str]:
    aliases_map.update(aliases)
    enum_map.update(enums)
    # Initialize an empty string to store the generated content
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")

    live_types.clear()
    live_types.update(threadable_types(functions))
    output.extend(live_tables(sorted(live_types)))

    # the Arg_0 of any protocol member, used for the members that declare no parameters
    protocol_arg_0 = None
    for candidate, candidate_block in functions.items():
        if candidate in services and "protocol" in services[candidate].service.lower():
            first = candidate_block.arguments.get('Arg_0')
            # it has to be the protocol itself: plenty of members take something else
            # first, and EFI_SHELL_PROTOCOL.RemoveDupInFileList leads with a file list
            if first and first[0].usage and first[0].variable == "__PROTOCOL__":
                protocol_arg_0 = first
                break
    if protocol_arg_0 is None:
        for candidate_block in functions.values():
            if getattr(candidate_block, 'protocol_type', None):
                break

    # Iterate through functions and generate harnesses
    for function, function_block in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the {services[function].service} service")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f'__attribute__((no_sanitize("address")))')
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable,")
        output.append(f"    IN EFI_HANDLE *ImageHandle")
        output.append(") {")
        output.append(f"    EFI_STATUS Status = EFI_SUCCESS;")
        protocol_variable = ""
        if "protocol" in services[function].service.lower():
            # a protocol member does not have to take the protocol: EFI_SHELL_PROTOCOL
            # declares BatchIsActive(VOID) and four others with no parameters at all, so
            # there is no Arg_0 to read the type and guid from. every method here belongs
            # to the same protocol, so borrow them from whichever sibling does have one
            first = function_block.arguments.get('Arg_0')
            if first is not None and first[0].variable != "__PROTOCOL__":
                first = None
            if first is None:
                first = protocol_arg_0
            # the analysis records the protocol type and guid on the block when no
            # parameter carries them, which is how a member declared (VOID) is reached
            template_block = services.get(function)
            declared_type = getattr(template_block, 'protocol_type', None)
            declared_guid = getattr(template_block, 'protocol_guid', None)
            if first is not None:
                protocol_variable = "ProtocolVariable"
                output.append(f"    {first[0].arg_type} {protocol_variable} = NULL;")
                output.append(f'    Status = SystemTable->BootServices->LocateProtocol(&{first[0].usage}, NULL, (VOID *)&{protocol_variable});')
                output.append('    if (EFI_ERROR(Status)) {')
                output.append('        return Status;')
                output.append('    }')
            elif declared_type and declared_guid:
                protocol_variable = "ProtocolVariable"
                output.append(f"    {declared_type} {protocol_variable} = NULL;")
                output.append(f'    Status = SystemTable->BootServices->LocateProtocol(&{declared_guid}, NULL, (VOID *)&{protocol_variable});')
                output.append('    if (EFI_ERROR(Status)) {')
                output.append('        return Status;')
                output.append('    }')

        output.extend(function_body(function_block, services, protocol_variable, generators, types, True, random))

        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output







