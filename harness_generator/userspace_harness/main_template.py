from typing import Dict, List

def gen_stateful_fuzz(functions: List[str]) -> List[str]:
    output = []

    output.append("EFI_STATUS")
    output.append("StatefulFuzz (")
    output.append("    IN INPUT_BUFFER *Input")
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
        output.append(f'                Status = Fuzz{function}(Input);')
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

    output.append("#include \"userspace_harnesses.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    if stateful:
        output.extend(gen_stateful_fuzz(functions))
    output.append("")
    output.append("int")
    output.append("main (int argc, char *argv[])")
    output.append("{")
    output.append("    EFI_STATUS Status = 0x0;")
    output.append("")
    output.append("    if (argc != 2) {")
    output.append("        printf(\"Usage: %s <input_file>\\n\", argv[0]);")
    output.append("        return 1;")
    output.append("    }")
    output.append("")
    output.append("    Input = ReadFileToInputBuffer(argv[1]);")
    output.append("    if (Input.Buffer == NULL) {")
    output.append("        printf(\"Failed to read file.\\n\");")
    output.append("        return 1;")
    output.append("    }")
    output.append("")
    if stateful:
        output.append("    Status = StatefulFuzz(&Input);")
    else:
        output.append("    UINT8 DriverChoice = 0;")
        output.append("    ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);")
        output.append(f'    switch(DriverChoice%{len(functions)})')
        output.append("    {")
        for index, function in enumerate(functions):
            output.append(f'        case {index}:')
            output.append(f'            Status = Fuzz{function}(&Input);')
            output.append("            break;")
        output.append("    }")

    output.append("")
    output.append("    free(Input.Buffer);")
    output.append("    return Status;")
    output.append("}")

    return output