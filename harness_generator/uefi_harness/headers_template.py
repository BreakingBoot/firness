import re
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

    # FirnessIncludes.h is included directly above, so an edk2 header may already define
    # one of these names -- and MdePkg/Include/Base.h defines TRUE and FALSE with no guard
    # of its own, so an unconditional #define here is a redefinition rather than a shadow.
    # It went unnoticed because the replacement text is lifted from macros.json, which was
    # extracted from that same Base.h, so the two spellings cannot disagree; a clean build
    # should not rest on that coincidence. #ifndef keeps the declaring header's definition
    # wherever there is one and supplies the constant only where there is not, which is
    # what the harness wanted in the first place.
    for name, value in matched_macros.items():
        if re.fullmatch(r'[A-Za-z_]\w*', name or ''):
            output.append(f"#ifndef {name}")
            output.append(f"#define {name} {value}")
            output.append(f"#endif")
        else:
            # a function-like macro: the name carries its parameter list, which cannot go
            # after #ifndef
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
    # The firmware sanitizer's checks are gated separately from escalation, on purpose:
    # opening the escalation window arms a LibAFL command that is an invalid opcode
    # anywhere else. So a campaign has to turn the checks on itself, and until it did, a
    # generated harness reached none of them -- SanBenchFirmware fuzzed for 17030
    # iterations and reported nothing while the exerciser, which enables them by hand,
    # reported four classes on one boot. Same weak-definition reasoning as above.
    output.append('__attribute__((weak)) VOID AsanSetRegionChecks(BOOLEAN Active)')
    output.append('{')
    output.append('    (VOID)Active;')
    output.append('}')
    output.append('__attribute__((weak)) VOID AsanRegisterUntrusted(UINT64 Base, UINT64 Size)')
    output.append('{')
    output.append('    (VOID)Base;')
    output.append('    (VOID)Size;')
    output.append('}')
    # NULL is normal here: an OPTIONAL argument the fuzzer chose to pass as NULL has no
    # buffer to declare, and registering a zero base would make the whole first page
    # untrusted.
    output.append('static inline VOID FirnessUntrusted(VOID *Buffer, UINTN Size)')
    output.append('{')
    output.append('    if ((Buffer != NULL) && (AsanRegisterUntrusted != NULL)) {')
    output.append('        AsanRegisterUntrusted((UINT64)(UINTN)Buffer, (UINT64)Size);')
    output.append('    }')
    output.append('}')
    # The boundary between the firmware's own reports and the ones an input provoked,
    # written straight to the 16550 the capture is taken from.
    #
    # The report parser used to split on the line where DXE dispatches this image. That
    # line only reaches the same capture under Simics -- OVMF writes DEBUG to the ISA
    # debug port, not to serial -- so under QEMU the marker never appeared and every
    # report was filed as boot noise: 88 in one campaign, none of them counted. Doing it
    # here rather than in AsanLib because the harness declares AsanSetFuzzingActive weak
    # and does not link AsanLib, so the no-op above is what runs.
    output.append('static VOID FirnessMarkFuzzStart(VOID)')
    output.append('{')
    output.append('    STATIC BOOLEAN Announced = FALSE;')
    output.append('    STATIC CONST CHAR8 Marker[] = "FIRNESS: fuzzing starts\\n";')
    output.append('    UINTN Index;')
    output.append('')
    output.append('    if (Announced) {')
    output.append('        return;')
    output.append('    }')
    output.append('    Announced = TRUE;')
    output.append('    for (Index = 0; Marker[Index] != 0; Index++) {')
    output.append('        __asm__ __volatile__ ("outb %%al, %%dx"')
    output.append('                              :: "a" (Marker[Index]), "d" ((UINT16)0x3F8));')
    output.append('    }')
    output.append('}')
    #
    # What the guest actually received, on the same wire, once per iteration.
    #
    # This exists because the alternative is invisible. A campaign whose testcase never
    # reaches the guest buffer looks exactly like a healthy one: the length still arrives,
    # the harness still runs, coverage still moves with the length, and the reports that
    # come out are whatever the harness reaches with a constant input. SanBenchMemory
    # produced 474 byte-identical heap-overflow reports that way -- same address, same IP,
    # size 0x48 every time, because 0x48 is a constant the generator planted in one arm of
    # the length argument -- while its corpus sat at the seed count through 69120
    # executions. Nothing in the pipeline objected.
    #
    # So the harness says what it got, and scripts/input_check.py asserts the values vary.
    # Direct outb rather than SerialOutput: this has to work in a harness that does not
    # link AsanLib, which is the usual case.
    #
    output.append('static VOID FirnessReportInput(CONST UINT8 *Bytes, UINTN Length)')
    output.append('{')
    output.append('    STATIC CONST CHAR8 Hex[] = "0123456789abcdef";')
    output.append('    CHAR8 Line[32];')
    output.append('    UINTN At = 0;')
    output.append('    UINTN Index;')
    output.append('')
    output.append('    Line[At++] = \'I\'; Line[At++] = \'N\'; Line[At++] = \'=\';')
    # The length in hex, four nibbles: the buffer is 0x1000 so it always fits, and a
    # fixed width keeps the line greppable without a printf in a UEFI application.
    output.append('    for (Index = 4; Index > 0; Index--) {')
    output.append('        Line[At++] = Hex[(Length >> ((Index - 1) * 4)) & 0xF];')
    output.append('    }')
    output.append('    Line[At++] = \':\';')
    # Six bytes is enough to cover every selector the harness reads before it dispatches
    # -- the step count, the target, and the first argument's choice bytes -- which is
    # exactly the span that decides whether a member is reached at all.
    output.append('    for (Index = 0; Index < 6; Index++) {')
    output.append('        UINT8 Value = (Index < Length) ? Bytes[Index] : 0;')
    output.append('        Line[At++] = Hex[(Value >> 4) & 0xF];')
    output.append('        Line[At++] = Hex[Value & 0xF];')
    output.append('    }')
    output.append('    Line[At++] = \'\\n\';')
    output.append('')
    output.append('    for (Index = 0; Index < At; Index++) {')
    output.append('        __asm__ __volatile__ ("outb %%al, %%dx"')
    output.append('                              :: "a" (Line[Index]), "d" ((UINT16)0x3F8));')
    output.append('    }')
    output.append('}')
    output.append('static inline VOID FirnessSanitizer(BOOLEAN Active)')
    output.append('{')
    output.append('    if (Active) {')
    output.append('        FirnessMarkFuzzStart();')
    output.append('    }')
    output.append('    if (AsanSetFuzzingActive != NULL) {')
    output.append('        AsanSetFuzzingActive(Active);')
    output.append('    }')
    output.append('    if (AsanSetRegionChecks != NULL) {')
    output.append('        AsanSetRegionChecks(Active);')
    output.append('    }')
    output.append('    if (!Active && (AsanRegisterUntrusted != NULL)) {')
    output.append('        AsanRegisterUntrusted(0, 0);')
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
