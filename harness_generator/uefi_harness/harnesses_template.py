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


# How many characters a fuzzed string argument gets. A callee walks a string to its
# terminator, so a one character buffer filled with fuzzed bytes has no terminator and
# sends StrLen off the end of the allocation into unmapped memory. That is a fault in the
# harness, not a finding: EdkiiVarCheck reported 914 "solutions" in 6225 iterations this way.
FIRNESS_STRING_CHARS = 32


def is_string_pointer(arg_type: str) -> bool:
    return has_pointer(arg_type) and 'CHAR' in remove_ref_symbols(arg_type).upper()


def set_undefined_constants(arg_type: str) -> str:
    if has_pointer(arg_type):
        base = remove_ref_symbols(arg_type)
        if is_string_pointer(arg_type):
            # room for a string, not for one character
            return f'({arg_type})AllocateZeroPool({FIRNESS_STRING_CHARS} * sizeof({base}))'
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
        if "IN" in arguments[0].arg_dir and arguments[0].variable == "__HANDLE__":
            tmp = f"    ImageHandle,"
        elif "IN" in arguments[0].arg_dir and arguments[0].variable == "__PROTOCOL__":
            tmp = f"    ProtocolVariable,"
        elif arguments[0].arg_dir == "OPTIONAL" or is_function_pointer(arguments[0].arg_type):
            # NULL only converts to a pointer. edk2 has parameters that are unions or
            # scalars passed by value (ACPI_RESOURCE_HEADER_PTR), and those need a zero of
            # their own type instead
            if has_pointer(arguments[0].arg_type) or is_function_pointer(arguments[0].arg_type):
                tmp = f"    NULL,"
            else:
                tmp = f"    ({arguments[0].arg_type}){{0}},"
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
                random) -> List[str]:
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
    if (arguments[0].pointer_count > 0 and not "char" in arguments[0].arg_type.lower()) and not "IN" in arguments[0].arg_dir:
        output.append(f'{arg_type} {function}_{arg_key} = ({arg_type})AllocateZeroPool(sizeof({remove_ref_symbols(arg_type)}));')
    elif arguments[0].pointer_count == 0:
        # a struct passed by value has no pointer to allocate and cannot be assigned 0.
        # this is not limited to types the analysis recognised as structs: a member built
        # from its header can name one the types map never saw, such as
        # EFI_80211_MAC_ADDRESS. {0} initialises a scalar just as well as an aggregate.
        output.append(f'{arg_type} {function}_{arg_key} = {{0}};')
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
                if is_string_pointer(arg_type.arg_type):
                    # fill all but the last character and leave that one zero, so the
                    # string the callee receives is terminated inside its own allocation
                    output.append(f'        ReadBytes(Input, {FIRNESS_STRING_CHARS - 1} * '
                                  f'sizeof(*{function}_{arg}), (VOID *){function}_{arg});')
                    output.append(f'        {function}_{arg}[{FIRNESS_STRING_CHARS - 1}] = 0;')
                else:
                    output.append(f'        ReadBytes(Input, sizeof(*{function}_{arg}), (VOID *){function}_{arg});')
                output.append(f'        break;')
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
            tmp.extend(declare_var(function_block.function, arg_key, arguments, arg_type_list, False, arguments[0].variable == "__FUZZABLE__", is_struct, random))

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
        for field in types.get(struct_type, TypeInfo()).fields:
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
            if not nameable or (not scalar and not has_pointer(field.type)):
                output.append(f'ReadBytes(Input, sizeof({function}_{arg_key}{accessor}{field.name}), (VOID *)&({function}_{arg_key}{accessor}{field.name}));')
            elif not has_pointer(field.type):
                # through a temporary of the field's own type: a bit field has neither a
                # size nor an address of its own, so sizeof and & on one do not compile
                output.append('{')
                output.append(f'    {field.type} Firness_{field.name};')
                output.append(f'    ReadBytes(Input, sizeof(Firness_{field.name}), (VOID *)&Firness_{field.name});')
                output.append(f'    {function}_{arg_key}{accessor}{field.name} = Firness_{field.name};')
                output.append('}')
            else:
                # the struct came from AllocateZeroPool, so this pointer field is NULL and
                # writing through it wrote to address 0. Give it something to point at
                # first. VOID * has no target size, so a machine word stands in.
                field_ref = f'{function}_{arg_key}{accessor}{field.name}'
                field_size = ('sizeof(UINTN)' if 'VOID' in field.type.upper()
                              else f'sizeof(*{field_ref})')
                output.append(f'{field_ref} = ({field.type})AllocateZeroPool({field_size});')
                output.append(f'if ({field_ref} != NULL) ' + '{')
                output.append(f'    ReadBytes(Input, {field_size}, (VOID *)({field_ref}));')
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







