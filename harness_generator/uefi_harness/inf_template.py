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

def gen_firness_inf(uuid: str, 
                    driver_guids: List[str], 
                    protocol_guids: List[str],
                    libraries: Dict[str, str],
                    packages: List[str] = None,
                    priority: List[str] = None) -> List[str]:
    output = []

    output.append("[Defines]")
    output.append("  INF_VERSION                    = 0x00010005")
    output.append("  BASE_NAME                      = Firness")
    output.append(f'  FILE_GUID                      = {uuid}')
    output.append("  MODULE_TYPE                    = UEFI_APPLICATION")
    output.append("  VERSION_STRING                 = 1.0")
    output.append("  ENTRY_POINT                    = FirnessMain")

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
        if lib != "NULL":
            output.append(f'  {lib}')

    output.append("")
    output.append("[Guids]")
    for guid in driver_guids:
        output.append(f'  {guid}')

    output.append("")
    output.append("[Protocols]")
    for guid in protocol_guids:
        output.append(f'  {guid}')

    return output