from typing import List, Dict

def harness_includes(includes: List[str]) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_INCLUDES__")
    output.append("#define __FIRNESS_INCLUDES__")

    output.append("")
    for include in includes:
        output.append(f"#include <{include}>")

    output.append("")
    output.append("#endif // __FIRNESS_INCLUDES__")

    return output

def harness_header(functions: List[str],
                   matched_macros: Dict[str, str],
                   guids=()) -> List[str]:
    output = []
    output.append("#ifndef __FIRNESS_HARNESSES__")
    output.append("#define __FIRNESS_HARNESSES__")

    output.append("")
    output.append("#include \"FirnessIncludes.h\"")
    output.append("#include \"FirnessHelpers.h\"")
    output.append("")

    for name, value in matched_macros.items():
        output.append(f"#define {name} {value}")
    output.append("")

    # The sanitizer is gated around the call under test so that only the firmware's own
    # faults become solutions. AsanLib defines AsanSetFuzzingActive and Firness.dsc links
    # it in for the tsffs backend; the other backends do not instrument at all, and a weak
    # DECLARATION left over from that arrangement is undefined at link time. The ELF link
    # tolerates that, and then GenFw refuses the image -- "Bad definition for symbol
    # 'AsanSetFuzzingActive'@0 or unsupported symbol type" -- because PE/COFF has nowhere
    # to put an undefined weak. A weak DEFINITION covers both: AsanLib's strong one wins
    # wherever it is linked, and this no-op stands in where it is not. The wrapper stays
    # inline so no non-EFIAPI helper is called across the ms_abi boundary.
    output.append('__attribute__((weak)) VOID AsanSetFuzzingActive(BOOLEAN Active)')
    output.append('{')
    output.append('    (VOID)Active;')
    output.append('}')
    output.append('static inline VOID FirnessSanitizer(BOOLEAN Active)')
    output.append('{')
    output.append('    if (AsanSetFuzzingActive != NULL) {')
    output.append('        AsanSetFuzzingActive(Active);')
    output.append('    }')
    output.append('}')
    output.append("")

    # the inf lists these under [Guids]/[Protocols] so the linker resolves them, but the
    # header that declares one is not necessarily part of the harness include set. edk2
    # declares every guid this way, and repeating an extern declaration is harmless
    for guid in sorted(guids):
        output.append(f"extern EFI_GUID {guid};")
    if guids:
        output.append("")

    for function in functions:
        output.append(f"EFI_STATUS")
        output.append(f"EFIAPI")
        output.append(f"Fuzz{function}(")
        output.append(f"    IN INPUT_BUFFER *Input,")
        output.append(f"    IN EFI_SYSTEM_TABLE *SystemTable,")
        output.append(f"    IN EFI_HANDLE *ImageHandle")
        output.append(");")
        output.append("")

    output.append("#endif // __FIRNESS_HARNESSES__")

    return output
