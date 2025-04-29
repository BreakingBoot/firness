from typing import List, Dict
from common.types import TypeInfo, FieldInfo

def harness_header(functions: List[str],
                   matched_macros: Dict[str, str],
                   types: Dict[str, TypeInfo]) -> List[str]:
    output = []
    output.append("#ifndef __USERSPACE_HARNESSES__")
    output.append("#define __USERSPACE_HARNESSES__")

    output.append("")
    output.append("#include \"userspace_helpers.h\"")
    output.append("")

    for name, value in matched_macros.items():
        output.append(f"#define {name} {value}")
    output.append("")

    for type_name, type_info in types.items():
        output.append("typedef struct {")
        for field in type_info.fields:
            output.append(f"    {field.type} {field.name};")
        output.append("} " + type_info.name + ";")
        output.append("")

    # for name, value in guids.items():
    #     output.append(f'EFI_GUID {name} = {{{value}}};')
    # output.append("")

    for function in functions:
        output.append(f"EFI_STATUS")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input")
        output.append(");")
        output.append("")

    output.append("#endif // __USERSPACE_HARNESSES__")

    return output
