from typing import Dict, List

def gen_stateful_fuzz(functions: List[str]) -> List[str]:
    output = []

    output.append("EFI_STATUS")
    output.append("EFIAPI")
    output.append("StatefulFuzz (")
    output.append("    IN INPUT_BUFFER *Input,")
    output.append("    IN EFI_SYSTEM_TABLE *SystemTable,")
    output.append("    IN EFI_HANDLE ImageHandle")
    output.append(") {")
    output.append("    EFI_STATUS Status = EFI_SUCCESS;")
    output.append("    UINTN OpChoice = 0;")
    output.append("    for(UINTN i = 0; i < 5; i++)")
    output.append("    {")
    output.append("        ReadBytes(Input, sizeof(OpChoice), (VOID *)&OpChoice);")
    output.append(f'        switch(OpChoice%{len(functions)})')
    output.append("        {")
    for index, function in enumerate(functions):
        output.append(f'            case {index}:')
        output.append(f'                Status = Fuzz{function}(Input, SystemTable, ImageHandle);')
        output.append("                break;")
    output.append("        }")
    output.append("    }")
    output.append("    return Status;")
    output.append("}")
    output.append("")
    return output

def gen_firness_main(functions: List[str],
                    stateful: bool) -> List[str]:
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    output.append("#include \"tsffs-gcc-x86_64.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    if stateful:
        output.extend(gen_stateful_fuzz(functions))
    output.append("")
    output.append("__attribute__((no_sanitize(\"address\")))")
    output.append("EFI_STATUS")
    output.append("EFIAPI")
    output.append("FirnessMain (")
    output.append("    IN EFI_HANDLE ImageHandle,")
    output.append("    IN EFI_SYSTEM_TABLE *SystemTable")
    output.append(") {")
    output.append("    EFI_STATUS Status = EFI_SUCCESS;")
    output.append("")
    output.append("    UINTN MaxInputSize = 0x1000;")
    output.append("    UINT8 *buffer = (UINT8 *)AllocatePages(EFI_SIZE_TO_PAGES(MaxInputSize));")
    output.append("    UINTN InputSize = MaxInputSize;")
    output.append("")
    output.append("    HARNESS_START(buffer, &InputSize);")
    output.append("")
    output.append("    Input.Buffer = buffer;")
    output.append("    Input.Length = InputSize;")
    output.append("")
    if stateful:
        output.append("    Status = StatefulFuzz(&Input, SystemTable, ImageHandle);")
    else:
        output.append("    UINT8 DriverChoice = 0;")
        output.append("    ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);")
        output.append(f'    switch(DriverChoice%{len(functions)})')
        output.append("    {")
        for index, function in enumerate(functions):
            output.append(f'        case {index}:')
            output.append(f'            Status = Fuzz{function}(&Input, SystemTable, ImageHandle);')
            output.append("            break;")
        output.append("    }")
    output.append("")
    output.append("    HARNESS_STOP();")
    output.append("")
    output.append("    return Status;")
    output.append("}")

    return output