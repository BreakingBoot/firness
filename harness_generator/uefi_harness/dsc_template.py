from typing import List, Dict
import uuid

default_dsc_libs = [
    "NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf",
    "ArmTrngLib|MdePkg/Library/BaseArmTrngLibNull/BaseArmTrngLibNull.inf",
    "RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf",
    "CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf",
    "SmmCpuRendezvousLib|MdePkg/Library/SmmCpuRendezvousLibNull/SmmCpuRendezvousLibNull.inf",
    "DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf",
    "BaseLib|MdePkg/Library/BaseLib/BaseLib.inf",
    "BaseMemoryLib|MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf",
    "DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf",
    "HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf",
    "IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf",
    "MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf",
    "PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf",
    "PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf",
    "SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf",
    "UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf",
    "UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf",
    "UefiLib|MdePkg/Library/UefiLib/UefiLib.inf",
    "UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf",
    "TimerLib|UefiCpuPkg/Library/CpuTimerLib/BaseCpuTimerLib.inf",
    "DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf"
    ]

def gen_firness_dsc(libraries: Dict[str, str], backend: int = 1) -> List[str]:
    output = []
    dsc_guid = str(uuid.uuid4()).upper()

    output.append("[Defines]")
    output.append("  PLATFORM_NAME                  = Firness")
    output.append(f'  PLATFORM_GUID                  = {dsc_guid}')
    output.append("  PLATFORM_VERSION               = 0.1")
    output.append("  DSC_SPECIFICATION              = 0x00010005")
    output.append("  OUTPUT_DIRECTORY               = Build/Firness")
    output.append("  SUPPORTED_ARCHITECTURES        = X64")
    output.append("  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT")
    output.append("  SKUID_IDENTIFIER               = DEFAULT")

    # start from what the static analysis discovered, then pin the classes a
    # UEFI_APPLICATION harness depends on. discovery resolves each class from whichever
    # .dsc os.walk reaches first, which is how MemoryAllocationLib ended up on
    # BaseMemoryAllocationLibNull, whose AllocatePages() is ASSERT(FALSE); return NULL
    #
    # The sanitizers only work on firmware that publishes gAsanInfoGuid: AsanLib's
    # constructor reads that HOB to find the shadow region. The Simics platform build
    # publishes it, OVMF does not, and a harness carrying the instrumentation onto
    # firmware that does not faults during its own constructors. So instrument for tsffs
    # and not otherwise -- under libafl-qemu the coverage and the crash detection both
    # come from the emulator, so nothing is lost by dropping it.
    #
    asan = backend == 1
    memory_lib = ("MdePkg/Library/AsanMemoryLibRepStr/AsanMemoryLibRepStr.inf" if asan
                  else "MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf")
    resolved = {}
    for lib, path in libraries.items():
        if lib == "NULL":
            continue
        if "BaseMemoryLib" in lib:
            path = memory_lib
        resolved[lib] = path
    for entry in default_dsc_libs:
        lib, _, path = entry.partition('|')
        if lib == "NULL":
            continue
        if "BaseMemoryLib" in lib:
            path = memory_lib
        resolved[lib] = path

    output.append("")
    output.append("[LibraryClasses]")
    if asan:
        output.append(f'  NULL|MdeModulePkg/Library/AsanLib/AsanLib.inf')
    for lib in sorted(resolved):
        output.append(f'  {lib}|{resolved[lib]}')
    
    output.append("")
    output.append("[Components]")
    output.append("  Firness/FirnessHarnesses.inf")

    # pick the fuzzer backend FirnessBackend.h compiles against. "GCC" is the tool
    # FAMILY, which is what CLANGSAN declares in tools_def, and a single "=" appends
    # so the toolchain's own CC_FLAGS survive
    if backend and backend != 1:
        output.append("")
        output.append("[BuildOptions]")
        output.append(f'  GCC:*_*_*_CC_FLAGS = -D FIRNESS_BACKEND={backend}')
        # SAN_FLAGS is a variable of its own and build_rule appends it AFTER CC_FLAGS
        # ("$(CC) $(DEPS_FLAGS) $(CC_FLAGS) $(SAN_FLAGS) -c ..."), so -fno-sanitize in
        # CC_FLAGS is overridden and the module stays instrumented. It carries
        # -fsanitize=address, -fsanitize=undefined and -fsanitize-coverage=trace-pc
        # together, so replacing it with "==" is what turns all three off; leaving the
        # sanitizers on here would also leave __asan_* and __sanitizer_cov_trace_pc
        # undefined, because the ASan libraries are not in the list above.
        output.append(f'  *_CLANGSAN_X64_SAN_FLAGS == -Wno-frame-address')

    return output