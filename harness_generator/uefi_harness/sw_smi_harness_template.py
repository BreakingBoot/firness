"""The software SMI harness: the channel an OS-level attacker actually has.

A comm-buffer handler is addressed by a GUID and reads a buffer the caller wrote, so a
harness for one is a buffer to fill. A software SMI handler has neither. It is registered
against a COMMAND BYTE on the software dispatch protocol, and it is raised by writing that
byte to the software SMI port -- one `out` instruction, from ring 0, with no firmware
cooperation of any kind. That is the single most exposed SMM entry point on real hardware
and the comm-buffer harness cannot produce it: see DISPATCH_REASON['SwDispatch'] in
analyze_smi.py, which is correct about the comm buffer and was being read as a statement
that the handler could not be driven at all.

Two bytes reach the handler, and the dispatcher builds its EFI_MM_SW_CONTEXT out of them:

    SwContext.CommandPort = IoRead8 (SMM_CONTROL_PORT);     // 0xB2
    SwContext.DataPort    = IoRead8 (SMM_DATA_PORT);        // 0xB3

so the harness writes those two ports and the firmware does the rest.

**The command byte is confined to the values discovery found registered, and that is a
safety property, not a tuning choice.** Port 0xB2 is shared with the platform:
ICH9_APM_CNT_CPU_HOTPLUG (0x04) reaches CpuHotplugSmm, whose error paths CpuDeadLoop()
inside SMM and take the guest with them, and OVMF's own SmmControl2 Trigger writes this
port for every SmmCommunicate. A byte nothing registered reaches no handler at all -- both
dispatchers in this tree log "No handler for SMI value 0x%x" and return -- so sweeping
0..255 buys no coverage and can forfeit a whole campaign budget on a guest that powers off.
The set the harness draws from is exactly the set the tree registers.
"""
from typing import Dict, List

# The ICH9/PCH software SMI pair, as every dispatcher in edk2 reads it.
#
# Writing the data port does NOT raise the SMI: the ICH9 spec calls 0xB3 a scratchpad --
# "the so-called Advanced Power Management Status Port Register is in fact a generic data
# passing register", as OvmfPkg/SmmControl2Dxe/SmmControl2Dxe.c puts it. Writing the
# command port is what raises it. So the data byte is written FIRST and the command byte
# LAST; the other order raises the SMI while the data port still holds whatever the
# previous iteration left in it, and the handler reads the two as one pair.
DATA_PORT = 0xB3
COMMAND_PORT = 0xB2

# How the data byte is drawn: the raw read, plus the boundaries worth spending an arm on.
# Deliberately short. The data byte is one eighth of the entropy a comm-buffer payload has
# and the raw read already covers it uniformly; the arms exist so 0, 1 and 0xFF come up
# often rather than once in 256.
DATA_CHOICES = (
    (1, '0x00'),
    (2, '0x01'),
    (3, '0xFF'),
    (4, '(UINT8)(DataPort ^ 0xFF)'),
)
DATA_CHOICE_MASK = 8


def command_macro(handler: str) -> str:
    """The name the generated C gives one handler's registered command byte."""
    return f'FIRNESS_SWSMI_{handler.upper()}'


def preamble(functions: Dict[str, object]) -> List[str]:
    """The ports, the per-handler command bytes, and the set they are drawn from.

    The table is built out of the per-handler macros rather than out of a second list of
    numbers. One spelling of each value means the confinement cannot drift: whatever a
    harness writes to the command port is a macro defined here, and every macro defined
    here is in the table.
    """
    output = []
    output.append('//')
    output.append('// The software SMI ports. The data port is a scratchpad -- writing it')
    output.append('// raises nothing -- and the command port is what raises the SMI, so')
    output.append('// every harness below writes the data byte first and the command byte')
    output.append('// last.')
    output.append('//')
    output.append(f'#define FIRNESS_SW_SMI_DATA_PORT     0x{DATA_PORT:02X}')
    output.append(f'#define FIRNESS_SW_SMI_COMMAND_PORT  0x{COMMAND_PORT:02X}')
    output.append('')
    output.append('//')
    output.append('// The command bytes this tree registers, each with the registration it')
    output.append('// was read out of. A command byte is an arbitrary-looking number whose')
    output.append('// only justification is the line of firmware that asked for it.')
    output.append('//')
    for name in sorted(functions):
        info = functions[name]
        value = int(getattr(info, 'sw_smi_value', 0) or 0)
        where = getattr(info, 'file', '') or 'an unrecorded registration'
        spelling = getattr(info, 'sw_smi_spelling', '') or ''
        note = f' ({spelling})' if spelling and spelling != f'0x{value:02X}' else ''
        output.append(f'#define {command_macro(name)}  0x{value:02X}  '
                      f'// {where}{note}')
    output.append('')
    output.append('//')
    output.append('// Nothing outside this set is ever written to the command port.')
    output.append('//')
    output.append('// Port 0xB2 is not an address space to sweep. ICH9_APM_CNT_CPU_HOTPLUG')
    output.append('// (0x04) reaches CpuHotplugSmm, whose error paths CpuDeadLoop() inside')
    output.append('// SMM and take the guest with them; command 0 is what OVMF\'s own')
    output.append('// SmmControl2 Trigger writes for every SmmCommunicate, and both')
    output.append('// dispatchers in this tree treat it as "not a software SMI" and return.')
    output.append('// A byte nothing registered reaches no handler either way, so a blind')
    output.append('// sweep buys no coverage and can forfeit a whole campaign budget.')
    output.append('//')
    output.append('STATIC CONST UINT8 mFirnessSwSmiCommands[] = {')
    for name in sorted(functions):
        output.append(f'  {command_macro(name)},')
    output.append('};')
    output.append('#define FIRNESS_SW_SMI_COMMAND_COUNT  '
                  '(sizeof (mFirnessSwSmiCommands) / sizeof (mFirnessSwSmiCommands[0]))')
    output.append('')
    return output


def harness(name: str, info) -> List[str]:
    """One handler's harness: pick a registered command byte, fuzz the data byte, write."""
    output = []
    output.append('/*')
    output.append('    This is a harness for fuzzing the software SMI Handler')
    output.append(f'    called {name}.')
    output.append('*/')
    output.append('__attribute__((no_sanitize("address")))')
    output.append('EFI_STATUS')
    output.append('EFIAPI')
    # Fuzz<name>, not FuzzSwSmi<name>: the header declares and FirnessMain calls Fuzz<name>,
    # and a definition under any other spelling leaves the call unresolved.
    output.append(f'Fuzz{name}(')
    output.append('    IN INPUT_BUFFER *Input,')
    output.append('    IN EFI_SYSTEM_TABLE *SystemTable,')
    output.append('    IN EFI_HANDLE *ImageHandle')
    output.append(') {')
    output.append('    UINT8 CommandChoice = 0;')
    output.append('    UINT8 DataChoice = 0;')
    output.append('    UINT8 CommandPort = 0;')
    output.append('    UINT8 DataPort = 0;')
    output.append('')
    output.append('    ReadBytes(Input, sizeof(CommandChoice), (VOID *)&CommandChoice);')
    output.append('    ReadBytes(Input, sizeof(DataPort), (VOID *)&DataPort);')
    output.append('    ReadBytes(Input, sizeof(DataChoice), (VOID *)&DataChoice);')
    output.append('')
    output.append('    //')
    output.append(f'    // Half the selector space sends the byte {name} is')
    output.append('    // registered for, so this target is reached whatever else the tree')
    output.append('    // registers. The other half sends one of the registered set,')
    output.append('    // because a dispatcher that confuses two commands -- or a handler')
    output.append('    // that answers one it never registered for -- is only visible if')
    output.append('    // its siblings\' bytes are sent too. Both arms take a value from')
    output.append('    // mFirnessSwSmiCommands, so the command byte never leaves it.')
    output.append('    //')
    output.append('    if ((CommandChoice & 1) == 0) {')
    output.append(f'        CommandPort = {command_macro(name)};')
    output.append('    } else {')
    output.append('        CommandPort = mFirnessSwSmiCommands['
                  '(CommandChoice >> 1) % FIRNESS_SW_SMI_COMMAND_COUNT];')
    output.append('    }')
    output.append('')
    output.append('    // The data byte is the rest of what the channel carries. The raw')
    output.append('    // read stays as the default arm so nothing is unreachable.')
    output.append(f'    switch (DataChoice & {DATA_CHOICE_MASK - 1}) {{')
    for case, value in DATA_CHOICES:
        output.append(f'        case {case}: DataPort = {value}; break;')
    output.append('        default: break;  // the raw read')
    output.append('    }')
    output.append('')
    output.append('    //')
    output.append('    // Nothing to hand FirnessUntrusted: this channel gives the handler')
    output.append('    // no caller buffer at all. The EFI_MM_SW_CONTEXT it reads is built')
    output.append('    // by the dispatcher inside SMRAM out of the two port reads, so the')
    output.append('    // untrusted input is in the CPU\'s I/O space and there is no address')
    output.append('    // range for the double-fetch check to watch.')
    output.append('    //')
    output.append('    // FirnessSanitizer is armed all the same, and for the same reason')
    output.append('    // the comm-buffer harness arms it: FirnessMain clears')
    output.append('    // mAsanFuzzingActive after HARNESS_START, and without the arming a')
    output.append('    // fault inside the handler is logged and then dropped instead of')
    output.append('    // being escalated into a finding this campaign is credited with.')
    output.append('    //')
    output.append('    FirnessSanitizer(TRUE);')
    output.append('    IoWrite8 (FIRNESS_SW_SMI_DATA_PORT, DataPort);')
    # Last, and on its own line: this is the instruction that raises the SMI.
    output.append('    IoWrite8 (FIRNESS_SW_SMI_COMMAND_PORT, CommandPort);')
    output.append('    FirnessSanitizer(FALSE);')
    output.append('    return EFI_SUCCESS;')
    output.append('}')
    output.append('')
    return output


def harness_generator(functions: Dict[str, object],
                      types=None,
                      aliases=None,
                      enums=None,
                      random: bool = False) -> List[str]:
    """FirnessHarnesses.c for the software SMI target.

    Signature-compatible with the comm-buffer generator so main.py's emitter does not have
    to know which one it is holding; the type, alias and enum maps describe comm-buffer
    payloads and this channel has none.
    """
    output = ['#include "FirnessHarnesses.h"', '']
    output.extend(preamble(functions))
    for name in sorted(functions):
        output.extend(harness(name, functions[name]))
    return output
