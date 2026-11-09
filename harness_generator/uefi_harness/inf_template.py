from typing import Dict, List

# The packages the harness inf declares. The harness is built with WORKSPACE pointing at
# the edk2 tree alone, so these are the only .dec files whose guids the build can resolve.
HARNESS_PACKAGES = [
    'MdePkg/MdePkg.dec',
    'MdeModulePkg/MdeModulePkg.dec',
    'ShellPkg/ShellPkg.dec',
    'NetworkPkg/NetworkPkg.dec',
    'OvmfPkg/OvmfPkg.dec',
    'UefiCpuPkg/UefiCpuPkg.dec',
]

# The MODULE_TYPE decides WHEN the harness runs, and for an SMI handler that is the
# difference between reaching its body and not reaching it at all.
#
# 'application' is the default and what every campaign has used: a UEFI_APPLICATION written
# to the ESP as EFI/BOOT/BOOTX64.EFI, so BDS launches it as a boot option.
#
# 'dxe' makes it a DXE_DRIVER placed in the firmware volume, dispatched by the DXE core.
# Needed because a handler that latches on EndOfDxe is already shut by the time a boot
# option runs. Measured on EVAL-1 run 42633354713's debugcon:
#
#     line 1688  SmmEndOfDxeHandler
#     line 3183  FSOpen: Open '\EFI\BOOT\BOOTX64.EFI' Success
#                SmmFtwHandler: Not safe to do the operation ... after End Of Dxe,
#                so access denied!
#
# The latch closes 1495 narration lines before the harness exists, and no boot-time
# mechanism gets ahead of it: OVMF signals EndOfDxe in PlatformBootManagerBeforeConsole
# (BdsPlatform.c:451), which BDS calls BEFORE it processes Driver#### options
# (BdsEntry.c:899), and SMM locks down immediately after. In this tree that shuts SmmSpi
# entirely, FaultTolerantWriteSmm, two paths in Tcg2Smm, and 3 of VariableSmm's 13
# commands including INIT_RUNTIME_VARIABLE_CACHE_CONTEXT.
#
# It is opt-in because the cost does not scale: a UEFI_APPLICATION is one firmware and many
# harnesses, while a module in the FV means a firmware build per harness. Fine for an SMI
# campaign with one target, six hours for a 262-protocol sweep.
HARNESS_TIMINGS = ('application', 'dxe')

# What the DXE flavour must wait for before its body can do anything.
SMM_COMMUNICATION = 'gEfiSmmCommunicationProtocolGuid'


def depex_for_smi(smi_data, declared) -> List[str]:
    """The buffer protocols a DXE_DRIVER harness must be dispatched after.

    A handler that compares its comm buffer against the pointer its DXE half published
    rejects anything else on an address compare. Two DXE drivers have no guaranteed
    dispatch order between them, so without these in the depex the harness can run first,
    its LocateProtocol fails, it falls back to the PI communication region, and every
    input is rejected -- which is the exact failure the BufferProtocol work was done to fix.

    Only protocols the INF DECLARES are returned. A depex naming a GUID the INF does not
    declare does not build, and -- worse -- a module whose depex never evaluates TRUE is
    never dispatched at all, which from the outside is indistinguishable from a harness
    that cannot be reached.
    """
    wanted = {getattr(info, 'buffer_protocol', '') for info in (smi_data or {}).values()}
    return [p for p in sorted(wanted) if p and p in declared]


def gen_firness_inf(uuid: str, 
                    driver_guids: List[str], 
                    protocol_guids: List[str],
                    libraries: Dict[str, str],
                    packages: List[str] = None,
                    priority: List[str] = None,
                    timing: str = 'application',
                    depex_protocols: List[str] = None) -> List[str]:
    output = []
    if timing not in HARNESS_TIMINGS:
        raise ValueError(f'unknown harness timing {timing!r}; '
                         f'expected one of {HARNESS_TIMINGS}')
    dxe = timing == 'dxe'

    output.append("[Defines]")
    output.append("  INF_VERSION                    = 0x00010005")
    output.append("  BASE_NAME                      = Firness")
    output.append(f'  FILE_GUID                      = {uuid}')
    output.append(f'  MODULE_TYPE                    = '
                  f'{"DXE_DRIVER" if dxe else "UEFI_APPLICATION"}')
    output.append("  VERSION_STRING                 = 1.0")
    output.append("  ENTRY_POINT                    = FirnessMain")

    if not dxe:
        output.append("")
        output.append("#")
        output.append("#  This flag specifies whether HII resource section is generated into PE image.")
        output.append("#")
        output.append("  UEFI_HII_RESOURCE_SECTION      = TRUE")

    output.append("")
    output.append("#")
    output.append("# The following information is for reference only and not required by the build tools.")
    output.append("#")
    output.append("#  VALID_ARCHITECTURES           = IA32 X64 EBC")
    output.append("#")

    output.append("")
    output.append("[Sources]")
    output.append("  FirnessMain.c")
    output.append("  FirnessHarnesses.c")
    output.append("  FirnessHelpers.c")

    output.append("")
    output.append("[Packages]")
    # The fixed six, plus whichever packages the harness's own includes come from. A
    # header outside the six is on disk and not on the include path, and the build stops
    # at "fatal error: 'Guid/DebugAgentGuid.h' file not found".
    # A package listed in priority goes ahead of them: it is the one that publishes the
    # header the harness was written against where two packages publish the same path, and
    # the include path is searched in the order this section lists.
    ordered = list(priority or [])
    for package in HARNESS_PACKAGES + list(packages or []):
        if package not in ordered:
            ordered.append(package)
    for package in ordered:
        output.append(f'  {package}')

    output.append("")
    output.append("[LibraryClasses]")
    for lib in libraries.keys():
        if lib == "NULL":
            continue
        # A DXE_DRIVER's entry point comes from UefiDriverEntryPoint. Leaving the
        # application one in place does not fail the build -- it fails the LINK, with an
        # unresolved _ModuleEntryPoint, which reads as a broken harness rather than a
        # wrong MODULE_TYPE.
        if dxe and lib == 'UefiApplicationEntryPoint':
            output.append('  UefiDriverEntryPoint')
            continue
        output.append(f'  {lib}')
    if dxe and 'UefiDriverEntryPoint' not in libraries \
            and 'UefiApplicationEntryPoint' not in libraries:
        output.append('  UefiDriverEntryPoint')

    output.append("")
    output.append("[Guids]")
    for guid in driver_guids:
        output.append(f'  {guid}')

    output.append("")
    output.append("[Protocols]")
    for guid in protocol_guids:
        output.append(f'  {guid}')

    if dxe:
        #
        # The depex is what orders the harness after the drivers it needs, and getting it
        # wrong is silent: a module whose depex never evaluates TRUE is never dispatched,
        # the boot walks past it to BDS, and the campaign reports "every boot spent its
        # budget without reaching the harness" with nothing to say why.
        #
        # SMM_COMMUNICATION is the floor -- without it there is no way to raise an SMI at
        # all. The rest are the protocols a handler compares its comm buffer against,
        # published by that driver's DXE half, which is itself a DXE driver with no
        # guaranteed order relative to this one. Without them in the depex the harness can
        # dispatch first, its LocateProtocol fails, it falls back to the communication
        # region, and the handler rejects every input on the address compare -- which is
        # the exact failure the BufferProtocol work was done to fix.
        #
        wanted = [SMM_COMMUNICATION]
        for guid in (depex_protocols or []):
            if guid and guid not in wanted:
                wanted.append(guid)
        output.append("")
        output.append("[Depex]")
        output.append('  ' + ' AND\n  '.join(wanted))

    return output