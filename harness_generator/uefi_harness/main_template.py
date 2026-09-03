from typing import Dict, List

# how many calls one fuzzing iteration may chain together
# How many calls one fuzzing iteration chains together. Every step costs a full protocol
# call, and under emulation some protocols are slow enough that the chain, not the fuzzer,
# sets the iteration rate: EfiShell managed 8 iterations in 600s at 8 steps, and 0 in the
# run after that. Lower it for those; the sequence is still stateful, just shorter.
MAX_SEQUENCE_STEPS = 8


# Names that put a protocol into a usable state. A sequence that opens before it reads
# gets past the entry checks; one that reads first can only ever return EFI_NOT_STARTED,
# and with a uniform choice most sequences start on the wrong call.
SETUP_PREFIXES = ('Configure', 'Create', 'Open', 'Start', 'Init', 'Register', 'Allocate',
                  'Reset', 'Set', 'Add', 'Install', 'Connect', 'Enable', 'Map', 'Attach')


def setup_first(functions, precedence=()):
    """Order the dispatch so state-establishing calls come first, and say how many.

    A precedence observed in the firmware beats the naming convention: EFI_DISK_IO2's
    WriteDiskEx runs before ReadDiskEx in FatQueueTask, and neither name looks like setup.
    The names are the fallback for protocols the analysis saw no ordering for.
    """
    observed = [f for f in precedence if f in functions]
    if observed:
        rest = [f for f in functions if f not in observed]
        ordered = observed + rest
        # the calls seen running before others open the sequence
        leading = max(1, len(observed) // 2)
        return ordered, leading
    setup = [f for f in functions if f.startswith(SETUP_PREFIXES)]
    rest = [f for f in functions if not f.startswith(SETUP_PREFIXES)]
    return setup + rest, len(setup)


def gen_firness_main(functions: List[str], max_steps: int = MAX_SEQUENCE_STEPS,
                     precedence=()) -> List[str]:
    output = []

    output.append("#include \"FirnessHarnesses.h\"")
    # FirnessBackend.h supplies HARNESS_START/HARNESS_STOP for whichever fuzzer the
    # harness is built against; it defaults to tsffs, so this is a no-op change unless
    # -D FIRNESS_BACKEND is passed
    output.append("#include \"FirnessBackend.h\"")
    output.append("")
    output.append("INPUT_BUFFER Input;")
    output.append("")
    # weak so a harness regenerated against an older AsanLib still links; without a
    # sanitizer present the symbol resolves to NULL and escalation is simply off
    output.append("extern VOID AsanSetFuzzingActive(BOOLEAN Active) __attribute__((weak));")
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
    output.append("    if (buffer == NULL) {")
    output.append("        return EFI_OUT_OF_RESOURCES;")
    output.append("    }")
    output.append("")
    output.append("    HARNESS_START(buffer, &InputSize);")
    output.append("")
    # from here on a sanitizer report also ends the iteration as a solution; before
    # this point the ~630 boot-time reports would kill every boot
    output.append("    if (AsanSetFuzzingActive != NULL) {")
    # start with reporting off: each harness turns it on around its own call and off
    # again afterwards, so the harness's own marshalling never raises a solution
    output.append("        AsanSetFuzzingActive(FALSE);")
    output.append("    }")
    output.append("")
    output.append("    Input.Buffer = buffer;")
    output.append("    Input.Length = InputSize;")
    output.append("")
    # switch(x % 0) is a hard compile error, so fail here with something readable
    if not functions:
        raise ValueError('no target functions were resolved -- the static analysis '
                         'produced an empty call database for this input file')

    # one iteration drives a sequence of calls rather than a single one. the protocol
    # instance is located afresh inside each harness, but the driver behind it keeps its
    # state, so a sequence is what reaches anything past the first entry check -- a lone
    # Transmit on an unconfigured EFI_IP4_PROTOCOL can only ever return EFI_NOT_STARTED
    output.append("    UINT8 SequenceLength = 0;")
    output.append("    UINTN Step = 0;")
    output.append("    UINTN Steps = 0;")
    output.append("    ReadBytes(&Input, sizeof(SequenceLength), (VOID *)&SequenceLength);")
    output.append(f"    Steps = (UINTN)(SequenceLength % {max_steps}) + 1;")
    output.append("")
    # the first call of a sequence chooses only among the setup calls when there are any,
    # so the driver is in a usable state before the rest of the sequence runs
    functions, setup_count = setup_first(list(functions), precedence)
    output.append(f"    UINTN Choices = {len(functions)};")
    output.append("    for (Step = 0; Step < Steps; Step++) {")
    output.append("        UINT8 DriverChoice = 0;")
    # once the input is spent ReadBytes zero-fills, so every remaining step would repeat
    # the same call with the same arguments
    output.append("        if (Step > 0 && Input.Length == 0) {")
    output.append("            break;")
    output.append("        }")
    output.append("        ReadBytes(&Input, sizeof(DriverChoice), (VOID *)&DriverChoice);")
    if setup_count:
        output.append(f"        Choices = (Step == 0) ? {setup_count} : {len(functions)};")
    output.append("        switch(DriverChoice % Choices)")
    output.append("        {")
    for index, function in enumerate(functions):
        output.append(f'            case {index}:')
        output.append(f'                Status = Fuzz{function}(&Input, SystemTable, ImageHandle);')
        output.append("                break;")
    output.append("        }")
    output.append("    }")

    output.append("")
    output.append("    HARNESS_STOP();")
    output.append("")
    output.append("    return Status;")
    output.append("}")

    return output