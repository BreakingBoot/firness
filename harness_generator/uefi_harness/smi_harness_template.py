from typing import List, Dict
import copy
import re
from common.types import FunctionBlock, Argument, TypeTracker, FieldInfo, TypeInfo, EnumDef, SmiInfo
from common.utils import add_indents, remove_ref_symbols
from uefi_harness.harnesses_template import SCALAR_FIELD_TYPES

aliases_map = {}
enum_map = {}

# this is a function that will return the underlying data type for any function
# so given EFI_PHYSICAL_ADDRESS it will return UINT64 by searching the aliases
# dictionary
def get_type(arg_type: str) -> str:
    if remove_ref_symbols(arg_type) in aliases_map.keys():
        return arg_type.replace(remove_ref_symbols(arg_type), aliases_map[remove_ref_symbols(arg_type)])
    else:
        return arg_type

def set_undefined_constants(arg_type: str) -> str:
    if has_pointer(arg_type):
        return "("+arg_type+")AllocateZeroPool(sizeof(" + remove_ref_symbols(arg_type) + "))"        
    elif "bool" in arg_type.lower():
        return "FALSE"
    else:
        return "0"   


# properly add casts to the arguments based off the difference
# between the argument type and the type tracker type along with
# the pointer count
def cast_arg(function: str, 
             arg_key:str,
             arguments: List[Argument],
             arg_type_list: List[TypeTracker]) -> str:
    
    update_arg = ""
    for arg in arg_type_list:
        if arg.name == arg_key:
            if arg.arg_type != arguments[0].arg_type:
                update_arg += f'({arguments[0].arg_type})'
            if arguments[0].pointer_count > arg.pointer_count:
                update_arg += f'&'
            # elif arg.fuzzable and arg.pointer_count > 0:
            #     update_arg += f'*'
            break
    if arguments[0].variable == '__GEN_INPUT__':
        update_arg += arguments[0].usage
    else:
        update_arg += f'{function}_{arg_key}'

    return update_arg
    

def call_function(function: str, 
                  function_block: FunctionBlock, 
                  services: Dict[str, FunctionBlock], 
                  protocol_variable: str,
                  arg_type_list: List[TypeTracker],                    
                  indent: bool,
                  prefix: str) -> List[str]:
    output = []
    lookup_function = function
    if prefix != "":
        lookup_function = f'{prefix}:{function}'
    if "protocol" in services[lookup_function].service:
        call_prefix = protocol_variable + "->"
    elif "BS" in services[lookup_function].service or "Boot" in services[lookup_function].service:
        call_prefix = "SystemTable->BootServices->"
    elif "RT" in services[lookup_function].service or "Runtime" in services[lookup_function].service:
        call_prefix = "SystemTable->RuntimeServices->"
    elif "DS" in services[lookup_function].service or "DxeServices" in services[lookup_function].service:
        call_prefix = "gDS->"
    else:
        call_prefix = ""
    
    if function_block.return_type == "EFI_STATUS":
        output.append(f"Status = {call_prefix}{function}(")
    else:
        output.append(f"{call_prefix}{function}(")

    for arg_key, arguments in function_block.arguments.items():
        original_arg_key = arg_key
        if prefix != "":
            arg_key = f'{prefix}_{arg_key}'
        if arguments[0].arg_dir == "IN" and arguments[0].variable == "__HANDLE__":
            tmp = f"    ImageHandle,"
        elif arguments[0].arg_dir == "IN" and arguments[0].variable == "__PROTOCOL__":
            tmp = f"    ProtocolVariable,"
        elif arguments[0].arg_dir == "OPTIONAL":
            tmp = f"    NULL,"
        else:
            tmp = f"    {cast_arg(function, arg_key, arguments, arg_type_list)},"
        # if the last iteration remove the comma
        if original_arg_key == list(function_block.arguments.keys())[-1]:
            tmp = tmp[:-1]
        output.append(tmp)
    output.append(f");")

    return add_indents(output, indent)

def add_ptrs(arg_type: str,
             num_ptrs: int) -> str:
    if num_ptrs == 0:
        return arg_type
    else:
        return add_ptrs(f"{arg_type}*", num_ptrs - 1)

def declare_var(function: str,
                arg_key: str, 
                arguments: List[Argument],
                arg_type_list: List[TypeTracker],
                indent: bool,
                fuzzable: bool,
                isStruct: bool,
                random) -> List[str]:
    output = []
    if arguments[0].pointer_count > 2:
        if arguments[0].arg_dir == "OUT":
            arg_type = add_ptrs(arguments[0].arg_type, arguments[0].pointer_count-1) if "void" in arguments[0].arg_type.lower() else arguments[0].arg_type
            arg_type_list.append(TypeTracker(arg_type, arg_key, arguments[0].pointer_count, fuzzable))
        else:
            print(f"ERROR: {function} {arg_key} has more than 2 pointers")
            return output
    elif arguments[0].pointer_count == 2:
        arg_type = "UINTN*" if "void" in arguments[0].arg_type.lower()  else arguments[0].arg_type.replace('**', '*')
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
    if (arguments[0].pointer_count > 0 and not "char" in arguments[0].arg_type.lower()) and not "IN" in arguments[0].arg_dir:
        output.append(f'{arg_type} {function}_{arg_key} = ({arg_type})AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
    else:
        output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arg_type)};")
        # if fuzzable :
        #     # output.append(f'{arg_type} {function}_{arg_key} = NULL;')
            
        # elif isStruct:
        #     output.append(f'{arg_type} {function}_{arg_key} = AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
        # else:
        #     output.append(f"{arg_type} {function}_{arg_key} = {set_undefined_constants(arguments[0])};")
    
    return add_indents(output, indent)

def fuzzable_args(function: str,
                  arg: str, 
                  indent: bool,
                  arg_type_list: List[TypeTracker]) -> List[str]:
    output = []
    output.append("// Fuzzable Variable Initialization")
    for arg_type in arg_type_list:
        if arg_type.name == arg:
            if arg_type.pointer_count == 0:
                output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *)&{function}_{arg});')
                break
            else:
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                # output.append(f'ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                output.append(f'UINT8 {function}_{arg}_choice = 0;')
                output.append(f'ReadBytes(Input, sizeof({function}_{arg}_choice), (VOID *)&{function}_{arg}_choice);')
                output.append(f'switch({function}_{arg}_choice % 2)' + ' {')
                output.append(f'    case 0:')
                output.append(f'        ReadBytes(Input, sizeof({function}_{arg}), (VOID *){function}_{arg});')
                output.append(f'        break;')
                output.append(f'    case 1:')
                output.append('    {')
                output.append(f'        gBS->FreePool({function}_{arg});')
                output.append(f'        {function}_{arg} = NULL;')
                output.append(f'        break;')
                output.append('    }')
                output.append('}')
                break
    
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
        if "IN" in arguments[0].arg_dir and not arguments[0].variable == "__HANDLE__" and not arguments[0].variable == "__PROTOCOL__":
            is_struct = remove_ref_symbols(arguments[0].arg_type) in types.keys() or aliases_map.get(remove_ref_symbols(arguments[0].arg_type), "") in types.keys()
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            tmp.extend(declare_var(function_block.function, arg_key, arguments, arg_type_list, False, arguments[0].variable == "__FUZZABLE__", is_struct, random))

    if len(tmp) > 0:
        output.append("/*")
        output.append("    Input Variable(s)")
        output.append("*/")
        output.extend(tmp)
        output.append("")

    for arg_key, arguments in function_block.arguments.items():
        if "IN" in arguments[0].arg_dir:
            if prefix != "":
                arg_key = f'{prefix}_{arg_key}'
            total_elements = len(arguments)
            if total_elements > 1:
                output.append(f'UINT8* {function_block.function}_{arg_key}_choice = AllocateZeroPool(sizeof(UINT8));')
                output.append(f'ReadBytes(Input, sizeof({function_block.function}_{arg_key}_choice), (VOID *){function_block.function}_{arg_key}_choice);')
                output.append(f'switch(*{function_block.function}_{arg_key}_choice % {total_elements})' + ' {')
            for arg in arguments:
                if total_elements > 1:
                    output.append(f'    case {arguments.index(arg)}:')
                    output.append('    {')
                if arg.variable == "__FUZZABLE__" or random:
                    output.extend(fuzzable_args(function_block.function, arg_key, total_elements > 1, arg_type_list))
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
        output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}_choice), (VOID *){function}_{arg_key}_choice);')
        usages = []
        matched_enum = enum_map.get(remove_ref_symbols(arg.arg_type), None)
        if matched_enum is None:
            matched_enum = enum_map.get(remove_ref_symbols(arg.data_type), EnumDef())
        for enum in matched_enum.values:
            tmp = copy.copy(arg)
            tmp.usage = enum
            usages.append(tmp)
        output.append(f'switch(*{function}_{arg_key}_choice % {len(usages)+1})' + ' {')
        for index, argument in enumerate(usages):
            output.append(f'    case {index}:')
            if argument.usage == "":
                output.append(f'        {function}_{arg_key} = {set_undefined_constants(argument)};')
            elif "char" in argument.arg_type.lower():
                output.append(f'        {function}_{arg_key} = StrDuplicate({argument.usage});')
            else:
                output.append(f'        {function}_{arg_key} = {argument.usage};')
            output.append(f'        break;')
        output.append(f'    case {len(usages)}:')
        if has_pointer(arg.arg_type):
            output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *){function}_{arg_key});')
        else:
            output.append(f'        ReadBytes(Input, sizeof({function}_{arg_key}), (VOID *)&{function}_{arg_key});')
        output.append(f'        break;')
        output.append('}')
    else:
        if arg.usage == "":
            output.append(f'{function}_{arg_key} = {set_undefined_constants(arg)};')
        elif "char" in arg.arg_type.lower():
            output.append(f'{function}_{arg_key} = StrDuplicate({arg.usage});')
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
    output.append(f'{function}_{arg_key} = {arg.usage};')

    return add_indents(output, indent)

def drop_one_pointer(arg_type: str) -> str:
    # the recorded type is spelled "TYPE * *" as often as "TYPE **", so a literal
    # replace('**', '*') leaves both stars in place
    base = arg_type.rstrip()
    if base.endswith('*'):
        base = base[:-1].rstrip()
    return base


def has_pointer(arg_type: str) -> bool:
    return arg_type.count('*') > 0

# A parameter block field filled from its own raw width is unreachable the moment the
# firmware tests it against a constant, and SMI handlers test almost every field they
# read. Measured on EVAL-1 run 42176147435: RWVariableHandler was dispatched 10548 times
# over 71418 iterations and its set path -- the one that hands SmmSetVariable a pointer
# the input places -- was never taken, because reaching it needs three raw-width scalars
# to land in narrow sets at the same time:
#
#   AccessType       UINT32, and the path is behind `if (CommData->AccessType)`      1 in 2^32
#   Attributes       UINT32, and SetVariable rejects any bit above 0x7F              1 in 2^25
#   VariableNameSize UINTN, and it becomes a DataSize bounded by MaxVariableSize     ~never
#
# Each is cheap on its own under a selector and jointly hopeless without one. Zero-filling
# does not rescue it either, and makes it worse: ReadBytes zeroes what the input cannot
# supply, so a short input zeroes AccessType -- and the same shortness zeroes
# VariableNameSize, which returns the handler early. The two conditions are mutually
# exclusive in exactly the regime that reaches the first one for free.
#
# So: one selector byte per scalar field, offering the values a C test distinguishes --
# zero, one, the low byte for a bitmask or a size, and all ones for an overflow check.
# Half of the selector's range is the raw read, so nothing that worked before stops
# working, and 0 is deliberately NOT one of the special cases: a spent input selects the
# raw read rather than zeroing every field in the block.
#
# The message length already picks between a delta, a short length and a modulo this way.
# This is the same trick applied to the parameter block the length describes.
SCALAR_CHOICE_CASES = (
    (8, '0'),
    (9, '1'),
    (10, '({cast})({ref} & 0xFF)'),
    (11, '({cast})~0ULL'),
)

# The selector is masked to 16 and the generic cases moved up to 8..11, which leaves 12..15
# for the constants the handler actually tests this field against. Half the range -- 0..7 --
# is still the raw read, so the invariant the comment above relies on is unchanged.
#
# Why this is worth four slots. The generic values cover the shapes a C test distinguishes
# in general; they do not cover the one thing an SMI handler does most, which is compare a
# command field against a value its own header names:
#
#     switch (CommunicationData->Function) { case UNREGISTER_FROM_RSC:   // 0x3
#
# Reaching that arm needed the low-byte case AND a 1-in-256 landing, about 1 in 2048, and
# the message length had to be exactly right at the same time: about 1 in 13000 per
# dispatch. Run 42490347442 dispatched HwLight 37278 times and HwAlarm 56021 times, so the
# arm was taken a handful of times across many boots.
#
# A handful is the wrong order of magnitude for what that arm leads to. It tears down a
# peer module's status-code registration, and the defect in doing that is doing it TWICE IN
# ONE BOOT -- which at 1 in 13000 per dispatch effectively never happened. With the
# constant offered directly it happens in roughly a quarter of dispatches.
# Four of the sixteen selector values -- 12..15 -- all mean "use a constant the source
# names", and a SECOND byte picks which one. Four dedicated slots would have capped a field
# at four constants, and that cap bites on exactly the handlers that matter most:
# VariableSmm switches on eight command codes and SmmSpi on FUNCTION_SPIFLASH_READ and
# FUNCTION_SPIFLASH_WRITE among others. With the index byte a field can offer as many as
# the source names, each at 25%/N instead of 2^-32 or worse.
#
# The index byte is read UNCONDITIONALLY, next to the selector, never inside the arm that
# uses it. A read inside the arm would make the input offset of every later field depend on
# which branch this one took, and the fuzzer's whole model is that a byte of input means
# the same thing from one execution to the next.
MAX_FIELD_CONSTANTS = 16
FIELD_CONSTANT_FIRST_CASE = 12
SCALAR_CHOICE_MASK = 16


def scalar_field_type(field_type: str) -> str:
    """The base integer spelling a field resolves to, or '' if it is not a scalar.

    Resolution is bounded: an alias map read out of a tree can be cyclic, and the generator
    runs before anything has had a chance to say so.
    """
    seen = set()
    name = remove_ref_symbols(field_type).strip()
    for _ in range(4):
        if name.upper() in SCALAR_FIELD_TYPES:
            return name.upper()
        if name in seen:
            break
        seen.add(name)
        nxt = aliases_map.get(name)
        if not nxt:
            break
        name = remove_ref_symbols(nxt).strip()
    return ''


# A constant is pasted into generated C, so it has to be a NAME or a NUMBER and nothing
# else. The analyzer already drops anything with punctuation in it, and this is the second
# gate on the same property, at the place where the text actually reaches a compiler: a
# malformed constant here does not produce a weaker harness, it produces firmware that
# does not build, and the campaign reports that as a broken port.
_SAFE_CONSTANT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$|^0[xX][0-9A-Fa-f]+$|^[0-9]+$')


# Cases 8 and 9 already assign 0 and 1, so a source constant equal to one of them is not
# worth an arm -- and for a BOOLEAN it is worse than not worth it. The fixture showed why:
# HwLight tests `if (CommunicationData->Disable == FALSE) break;`, so FALSE was collected
# as Disable's only constant, and the four constant selector values then all assigned the
# one value that makes the handler bail. Dropping it leaves Disable on the generic cases,
# where 1, the low byte and all ones are each non-zero.
_ALREADY_OFFERED = {'0', '0x0', '0X0', '1', '0x1', '0X1', 'FALSE', 'TRUE'}


def field_constants_for(ref: str, constants) -> List[str]:
    """The constants to offer for one field, cleaned and capped, in a stable order."""
    out = []
    for text in constants or ():
        text = str(text).strip()
        if not text or not _SAFE_CONSTANT.match(text):
            continue
        if text in _ALREADY_OFFERED:
            continue
        if text not in out:
            out.append(text)
    # Sorted so two runs of the generator emit the same harness: the analyzer writes a
    # set, and a set's iteration order is not something a build should depend on. Named
    # constants first, because a numeral that survived the filter above is a bare literal
    # in a comparison and a name is a command code the handler branches on -- and when the
    # cap bites, the command code is the one worth keeping.
    out.sort(key=lambda t: (t[:1].isdigit(), t))
    return out[:MAX_FIELD_CONSTANTS]


def scalar_choice(ref: str, field_type: str, chooser: str, constants=(),
                  index_chooser: str = '') -> List[str]:
    """The lines that fill one scalar field through a selector byte."""
    # The cast is the field's type AS WRITTEN, not the base type it resolves to: an alias
    # that lands on a wider spelling would otherwise truncate on assignment.
    cast = remove_ref_symbols(field_type).strip()
    wanted = field_constants_for(ref, constants)
    output = [f'ReadBytes(Input, sizeof({chooser}), (VOID *)&{chooser});']
    if wanted and index_chooser:
        # Read whether or not this field's arm is taken, so the offsets of every later
        # field are the same in every execution.
        output.append(f'ReadBytes(Input, sizeof({index_chooser}), '
                      f'(VOID *)&{index_chooser});')
    output.append(f'switch ({chooser} & {SCALAR_CHOICE_MASK - 1}) ' + '{')
    for case, value in SCALAR_CHOICE_CASES:
        output.append(f'    case {case}: {ref} = {value.format(cast=cast, ref=ref)}; break;')
    if wanted and index_chooser:
        for case in range(FIELD_CONSTANT_FIRST_CASE, SCALAR_CHOICE_MASK):
            output.append(f'    case {case}:')
        output.append(f'        switch ({index_chooser} % {len(wanted)}) ' + '{')
        for index, text in enumerate(wanted):
            output.append(f'            case {index}: {ref} = ({cast}){text}; break;')
        output.append('            default: break;')
        output.append('        }')
        output.append('        break;  // a constant the source tests this field against')
    output.append('    default: break;  // the raw read')
    output.append('}')
    return output


def generator_struct_args(arg_type: str, 
                          arg_name: str,
                          alias_map: Dict[str, str],
                          types: Dict[str, TypeInfo],
                          indent,
                          field_constants=None) -> List[str]:
    output = []
    output.append("// Generator Struct Variable Initialization")
    struct_type = remove_ref_symbols(arg_type) if len(types.get(remove_ref_symbols(arg_type), TypeInfo()).fields) > 0 else (aliases_map.get(remove_ref_symbols(arg_type), None))
    fields = types[struct_type].fields
    chooser = re.sub(r'\W', '', arg_name) + 'ScalarChoice'
    index_chooser = re.sub(r'\W', '', arg_name) + 'ConstChoice'
    if any(not has_pointer(f.type) and scalar_field_type(f.type) for f in fields):
        output.append(f'UINT8 {chooser} = 0;')
    # Declared only when some field actually has constants, so a block with none emits
    # byte-for-byte what it emitted before.
    if any(not has_pointer(f.type) and scalar_field_type(f.type)
           and field_constants_for('', (field_constants or {}).get(f.name, ()))
           for f in fields):
        output.append(f'UINT8 {index_chooser} = 0;')
    for field in fields:
        ref = f'{arg_name}->{field.name}'
        if not has_pointer(field.type):
            output.append(f'ReadBytes(Input, sizeof({ref}), (VOID *)&({ref}));')
            if scalar_field_type(field.type):
                output += scalar_choice(ref, field.type, chooser,
                                        (field_constants or {}).get(field.name, ()),
                                        index_chooser)
        else:
            output.append(f'ReadBytes(Input, sizeof({ref}), (VOID *)({ref}));')
    return add_indents(output, indent)


def harness_generator(functions: Dict[str, SmiInfo], 
                      types: Dict[str, TypeInfo], 
                      aliases: Dict[str, str],
                      enums: Dict[str, EnumDef],
                      random: bool = False) -> List[str]:
    aliases_map.update(aliases)
    enum_map.update(enums)
    # Initialize an empty string to store the generated content
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")
    #
    # Boundary lengths for the comm buffer, tried in preference to a uniform draw.
    #
    # What a missing lower bound looks like is a message SHORTER than the field the
    # handler reads: RWVariableHandler allocates *CommBufferSize bytes and then reads
    # CommData->VariableNameSize at offset 40, so anything from 0 to 40 is a heap
    # overread and 1080 -- the size of the struct, which is where the message starts --
    # is not. A uniform draw over 0..sizeof spends 96% of its mass on lengths that
    # cannot show the bug, and the target selector already costs a factor of eleven.
    #
    # So draw from the offsets that actually divide behaviour: zero, the small powers of
    # two and the ones either side of them, and the field offsets a parameter block of
    # any size is likely to have. The uniform draw stays as a fourth arm so nothing in
    # between is unreachable.
    #
    output.append('STATIC CONST UINTN mFirnessShortLengths[] = {')
    output.append('  0, 1, 2, 3, 4, 7, 8, 12, 15, 16, 20, 24, 28, 31, 32,')
    output.append('  40, 48, 56, 63, 64, 96, 127, 128, 160, 255, 256, 512')
    output.append('};')
    output.append("")

    # Iterate through functions and generate harnesses
    for function, smi_info in functions.items():
        output.append(f"/*")
        output.append(f"    This is a harness for fuzzing the SMI Handler")
        output.append(f"    called {function}.")
        output.append(f"*/")
        output.append(f'__attribute__((no_sanitize("address")))')
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        # the name the header declares and FirnessMain calls is Fuzz<name>; emitting
        # FuzzSmi<name> here left the definition unreferenced and the call unresolved
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable,")
        output.append(f"    IN EFI_HANDLE *ImageHandle")
        output.append(") {")
        output.append(f"    EFI_STATUS Status = EFI_SUCCESS;")
        output.append(f"    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;")
        output.append(f'    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;')
        output.append(f'    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;')
        output.append(f'    UINTN   CommSize = 0;')
        output.append(f'    UINT8    *CommBuffer = NULL;')
        output.append(f'    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;')
        output.append(f'    UINT32      Index = 0;')
        output.append(f'    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;')
        output.append(f'    UINTN  Size = 0;')
        output.append("")
        output.append(f'    Status = EfiGetSystemConfigurationTable (')
        output.append(f'                &gEdkiiPiSmmCommunicationRegionTableGuid,')
        output.append(f'                (VOID **)&PiSmmCommunicationRegionTable')
        output.append(f'            );')
        # the status was dropped here and the table only ASSERTed on. ASSERT compiles to
        # nothing in a RELEASE build, so a firmware without the table dereferenced NULL
        # and every iteration died in the harness rather than in a handler
        output.append('    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {')
        output.append('        return EFI_NOT_FOUND;')
        output.append('    }')
        output.append("")
        output.append(f'    Status = gBS->LocateProtocol(')
        output.append(f'                    &gEfiSmmCommunicationProtocolGuid,')
        output.append(f'                    NULL,')
        output.append(f'                    (VOID **)&SmmCommunication')
        output.append(f'                    );')
        output.append('    if (EFI_ERROR(Status)) {')
        output.append(f'        Print(L"Failed to handle SMM Communication Protocol");')
        output.append(f'        return Status;')
        output.append('    }')
        output.append('    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);')
        output.append('    Size  = 0;')
        output.append('    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {')
        output.append('        if (Entry->Type == EfiConventionalMemory) {')
        output.append('            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);')
        output.append('            if (Size >= MinimalSizeNeeded) {')
        output.append('                break;')
        output.append('            }')
        output.append('        }')
        output.append("")
        output.append(f'        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);')
        output.append('    }')
        output.append("")
        output.append('    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {')
        output.append('        return EFI_OUT_OF_RESOURCES;')
        output.append('    }')
        output.append(f'    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;')
        output.append("")

        #
        # Some handlers refuse any buffer but the one their DXE half published:
        #
        #   gBS->LocateProtocol (&gEfiLightStatusCodeCommunicationGuid, NULL, &mCommBuffer);
        #   ...
        #   if ((UINTN)CommBuffer != (UINTN)mCommBuffer + SMM_COMMUNICATE_HEADER_SIZE) return;
        #
        # That is an equality test on an address, so no input reaches past it and a campaign
        # looks like a handler that validates everything correctly. Measured on EVAL-1 run
        # 42490347442: UnregisterCBFunctionLight dispatched 37278 times and
        # UnregisterCBFunctionHwAlarm 56021 times, both with zero findings and zero coverage
        # past the third line of the body.
        #
        # So locate that protocol and send through its buffer instead. The region entry
        # above stays as the fallback: a firmware that does not publish the protocol, or a
        # build where the DXE half is absent, still gets a buffer and still exercises the
        # earlier checks rather than failing to start.
        #
        if getattr(smi_info, 'buffer_protocol', ''):
            protocol = smi_info.buffer_protocol
            output.append(f'    //')
            output.append(f'    // {smi_info.name} tests its comm buffer against the interface')
            output.append(f'    // pointer of {protocol}, so the buffer has to be that one.')
            output.append(f'    //')
            output.append(f'    VOID *PublishedBuffer = NULL;')
            output.append(f'    Status = gBS->LocateProtocol(')
            output.append(f'                    &{protocol},')
            output.append(f'                    NULL,')
            output.append(f'                    (VOID **)&PublishedBuffer')
            output.append(f'                    );')
            output.append(f'    if (!EFI_ERROR(Status) && PublishedBuffer != NULL) {{')
            output.append(f'        CommBuffer = (UINT8 *)PublishedBuffer;')
            output.append(f'    }}')
            output.append("")

        output.append(f'    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];')


        output.append(f'    CopyMem (&CommHeader->HeaderGuid, &{smi_info.guid}, sizeof ({smi_info.guid}));')
        # smi_info.type is the POINTER spelling -- line below declares HandlerData with
        # it -- so sizeof(smi_info.type) is 8 on X64 whatever the payload really is. Every
        # handler that checks MessageLength against its own parameter block rejected the
        # call before looking at a single fuzzed byte.
        payload_type = drop_one_pointer(smi_info.type).strip()
        # The analysis names the type of the parameter block a handler reads, which is not
        # always the whole message: VarCheckPolicyLibMmiHandler wants a
        # VAR_CHECK_POLICY_COMM_HEADER in front of its params, so at
        # sizeof(VAR_CHECK_POLICY_COMM_IS_ENABLED_PARAMS) it answered "Bad comm buffer
        # size! 1 < 20" and nothing past the size check was ever reached. Start at the
        # payload size and let the fuzzer grow the message up to the region it was given,
        # so both the size validation and the logic behind it are reachable.
        output.append(f'    CommHeader->MessageLength = sizeof ({payload_type});')
        output.append('    UINT8  MessageLengthChoice = 0;')
        output.append('    UINT16 MessageLengthDelta = 0;')
        output.append('    ReadBytes(Input, sizeof(MessageLengthChoice), '
                      '(VOID *)&MessageLengthChoice);')
        output.append('    ReadBytes(Input, sizeof(MessageLengthDelta), '
                      '(VOID *)&MessageLengthDelta);')
        output.append('    UINTN MessageLengthRoom = Size - '
                      'OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);')
        # Three outcomes, not two. Growing the message reaches the logic BEHIND a size
        # check. Shrinking it reaches the check itself -- and a missing lower bound is the
        # most common SMM comm-buffer defect there is, because the handler casts the buffer
        # to its parameter block and writes fields past the end of what the caller
        # actually sent. While this could only grow, every such handler was being tested
        # against the one input shape it never has to defend against, and a campaign that
        # found nothing could not distinguish "validates correctly" from "never asked".
        output.append('    switch (MessageLengthChoice & 3) {')
        output.append('        case 1:')
        output.append('            CommHeader->MessageLength += (UINTN)MessageLengthDelta;')
        output.append('            break;')
        output.append('        case 2:')
        # down to and including 0: SmiManage is still reached, and a handler that only
        # checks an upper bound will allocate for 0 bytes and write its first field anyway
        output.append('            CommHeader->MessageLength = mFirnessShortLengths['
                      '(UINTN)MessageLengthDelta % '
                      '(sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];')
        output.append('            break;')
        output.append('        case 3:')
        output.append(f'            CommHeader->MessageLength = (UINTN)MessageLengthDelta % '
                      f'(sizeof ({payload_type}) + 1);')
        output.append('            break;')
        output.append('        default:')
        output.append('            break;')
        output.append('    }')
        output.append('    if (CommHeader->MessageLength > MessageLengthRoom) {')
        output.append('        CommHeader->MessageLength = MessageLengthRoom;')
        output.append('    }')
        output.append(f'    {smi_info.type} HandlerData = ({smi_info.type})&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];')
        
        output.extend(generator_struct_args(smi_info.type, 'HandlerData', aliases, types,
                                            indent=True,
                                            field_constants=getattr(smi_info, 'field_constants', None)))

        output.append(f'    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;')
        # Without this the harness can never report anything: FirnessMain clears
        # mAsanFuzzingActive after HARNESS_START, and only FirnessSanitizer(TRUE) arms the
        # escalation, so a fault inside an SMI handler was logged and then ignored.
        # The comm buffer is the one place in this project where "untrusted" is literal:
        # the OS writes it and SMM reads it, so a handler that validates a field with one
        # read and uses it with another is the textbook SMM double fetch. FWSAN's check has
        # existed for a while and was inert here, because nothing registered the buffer --
        # so it only ever fired on DXE protocol arguments, where the caller is firmware and
        # re-reading its own buffer proves nothing.
        output.append(f'    FirnessUntrusted(CommBuffer, CommSize);')
        output.append('    FirnessSanitizer(TRUE);')
        output.append(f'    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);')
        # No FirnessUntrusted(0, 0) to close: FirnessSanitizer(FALSE) already calls
        # AsanRegisterUntrusted(0, 0), and the shim skips a NULL buffer by design, so the
        # explicit close would have been a no-op either way.
        output.append('    FirnessSanitizer(FALSE);')
        output.append(f"    return Status;")
        output.append("}")
        output.append("")

    # Print or use the output_string as needed
    return output