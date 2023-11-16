from typing import Dict, List
from common.types import FunctionBlock

def gen_firness_main(functions: Dict[str, FunctionBlock]) -> List[str]:
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    output.append("EFI_STATUS")
    output.append("EFIAPI")
    output.append("FirnessMain (")
    output.append("    IN EFI_HANDLE ImageHandle,")
    output.append("    IN EFI_SYSTEM_TABLE *SystemTable")
    output.append(") {")
    output.append("    EFI_STATUS Status = EFI_SUCCESS;")
    output.append("    UINT32 _a, _b, _c, _d = 0;")
    output.append("")
    output.append("    UINT8 buffer[0x20];")
    output.append("    UINTN size = sizeof(buffer) - 1;")
    output.append("    UINT8 *buffer_ptr = &buffer[0];")
    output.append("    UINTN *size_ptr = &size;")
    output.append("")
    output.append("    __asm__ __volatile__(")
    output.append("        \"cpuid\\n\\t\"")
    output.append("        : \"=a\"(_a), \"=b\"(_b), \"=c\"(_c), \"=d\"(_d), \"=S\"(buffer_ptr), \"=D\"(size_ptr)")
    output.append("        : \"0\"((0x0001U << 16U) | 0x4711U), \"S\"(buffer_ptr), \"D\"(size_ptr));")
    output.append("")
    output.append("    Input.Buffer = buffer_ptr;")
    output.append("    Input.Length = size;")
    output.append("")
    output.append("    UINT8 DriverChoice = 0;")
    output.append("    ReadBytes(&Input, sizeof(DriverChoice), &DriverChoice);")
    output.append(f'    switch(DriverChoice%{len(functions)})')
    output.append("    {")
    for index, function in enumerate(functions):
        output.append(f'        case {index}:')
        output.append(f'            Status = Fuzz{function}(&Input, SystemTable);')
        output.append("            break;")
    output.append("    }")

    output.append("")
    output.append("    __asm__ __volatile__(")
    output.append("        \"cpuid\\n\\t\"")
    output.append("        : \"=a\"(_a), \"=b\"(_b), \"=c\"(_c), \"=d\"(_d)")
    output.append("        : \"0\"((0x0002U << 16U) | 0x4711U));")
    output.append("")
    output.append("    return Status;")
    output.append("}")

    return output