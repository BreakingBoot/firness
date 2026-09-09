from typing import Dict, List

from common.types import SmiInfo
from linux_harness import guid_values


# A Linux kernel module that drives the same SMI handlers the UEFI harness drives.
#
# WHY A DRIVER AND NOT AN APPLICATION
#   The UEFI harness runs before an OS exists, with SMM set up the way the firmware left
#   it. An SMI handler is also reachable after ExitBootServices, from a running kernel,
#   with the memory map, the page tables and the CPU state an attacker would actually
#   have. Those are different states of the same handler, so both are worth fuzzing, and
#   the generator emits whichever is asked for.
#
# HOW AN SMI IS RAISED FROM RING 0
#   EDK2's DXE side does not just write the SMI command port. PiSmmIpl.c:547 stores the
#   buffer in the SMM Core private data first:
#       gSmmCorePrivate->CommunicationBuffer = CommBuffer;
#       gSmmCorePrivate->BufferSize          = *CommSize;
#       mSmmControl2->Trigger (...);
#   and the SMM entry point reads it back. So a driver needs three physical addresses
#   the firmware never publishes to an OS: the communication region, and the two fields
#   of that private structure. They are module parameters here rather than something
#   discovered, because there is no standard table that carries them -- the PI spec's
#   SMM Communication ACPI Table would, and this tree does not implement it.
#
# INPUT
#   The fuzzer's magic instructions are not privileged: the TSFFS CPUID sequence has no
#   CPL gate, and the LibAFL custom instruction is decoded during translation, so both
#   work from a module exactly as they do from a UEFI application.
FIRNESS_BACKEND_HEADER = 'firness_backend.h'


def backend_header() -> List[str]:
    """The ring 0 half of FirnessBackend.h.

    Not the edk2 file: that includes <Base.h> and speaks UINTN. The instruction sequences
    are the same, and are the part that has to stay in step with the fuzzers.
    """
    return [
        '/* Generated: the fuzzer handshake, for a Linux kernel module. */',
        '#ifndef FIRNESS_BACKEND_H_',
        '#define FIRNESS_BACKEND_H_',
        '',
        '#include <linux/types.h>',
        '',
        '#define FIRNESS_BACKEND_TSFFS        1',
        '#define FIRNESS_BACKEND_LIBAFL_QEMU  2',
        '#define FIRNESS_BACKEND_NONE         4',
        '',
        '#ifndef FIRNESS_BACKEND',
        '#define FIRNESS_BACKEND  FIRNESS_BACKEND_TSFFS',
        '#endif',
        '',
        '#if FIRNESS_BACKEND == FIRNESS_BACKEND_TSFFS',
        '',
        '/* cpuid with eax = (n << 16) | 0x4711; the hypervisor writes the length',
        ' * through the pointer in rdx, so the memory clobber is load bearing. */',
        '#define FIRNESS_MAGIC  0x4711',
        '',
        'static inline u64 firness_start(void *buffer, u64 *size)',
        '{',
        '\tu32 eax = (1u << 16) | FIRNESS_MAGIC, ebx = 0, ecx = 0, edx = 0;',
        '',
        '\t__asm__ __volatile__("cpuid"',
        '\t\t: "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx)',
        '\t\t: "D"(0), "S"(buffer), "d"(size)',
        '\t\t: "memory");',
        '\treturn *size;',
        '}',
        '',
        'static inline void firness_stop(int crash)',
        '{',
        '\tu32 eax = ((crash ? 5u : 4u) << 16) | FIRNESS_MAGIC;',
        '',
        '\t__asm__ __volatile__("cpuid" : "+a"(eax) : : "ebx", "ecx", "edx", "memory");',
        '}',
        '',
        '#elif FIRNESS_BACKEND == FIRNESS_BACKEND_LIBAFL_QEMU',
        '',
        '/* the four bytes are not an x86 instruction; qemu-libafl-bridge matches them',
        ' * during translation, which is why this is TCG only and #UD everywhere else. */',
        '#define FIRNESS_LQEMU_INSN  ".byte 0x0f, 0x3a, 0xf2, 0x66\\n\\t"',
        '',
        'static inline u64 firness_start(void *buffer, u64 *size)',
        '{',
        '\tu64 ret = 0; /* LIBAFL_QEMU_COMMAND_START_VIRT */',
        '',
        '\t__asm__ __volatile__(FIRNESS_LQEMU_INSN',
        '\t\t: "+a"(ret)',
        '\t\t: "D"((u64)(uintptr_t)buffer), "S"(*size)',
        '\t\t: "memory", "cc");',
        '\t*size = ret;',
        '\treturn ret;',
        '}',
        '',
        'static inline void firness_stop(int crash)',
        '{',
        '\tu64 ret = 4; /* LIBAFL_QEMU_COMMAND_END */',
        '',
        '\t__asm__ __volatile__(FIRNESS_LQEMU_INSN',
        '\t\t: "+a"(ret)',
        '\t\t: "D"((u64)(crash ? 2 : 1))',
        '\t\t: "memory", "cc");',
        '}',
        '',
        '#else',
        '',
        '/* no fuzzer: replay whatever is already in the buffer and return. */',
        'static inline u64 firness_start(void *buffer, u64 *size) { (void)buffer; return *size; }',
        'static inline void firness_stop(int crash) { (void)crash; }',
        '',
        '#endif',
        '',
        '#endif /* FIRNESS_BACKEND_H_ */',
    ]


def makefile(module_name: str) -> List[str]:
    return [
        f'obj-m += {module_name}.o',
        '',
        '# FIRNESS_BACKEND picks the handshake in firness_backend.h: 1 tsffs (default),',
        '# 2 libafl-qemu, 4 none. Build against the kernel the target actually runs:',
        '#   make KDIR=/lib/modules/$(uname -r)/build FIRNESS_BACKEND=2',
        '#',
        '# The -D is conditional on purpose. An unconditional -DFIRNESS_BACKEND=$(VAR)',
        '# with VAR unset expands to a definition with an empty value, which satisfies',
        "# the header's #ifndef and then fails as \"operator '==' has no left operand\".",
        'ccflags-y += $(if $(FIRNESS_BACKEND),-DFIRNESS_BACKEND=$(FIRNESS_BACKEND))',
        '',
        'KDIR ?= /lib/modules/$(shell uname -r)/build',
        '',
        'all:',
        '\t$(MAKE) -C $(KDIR) M=$(PWD) modules',
        '',
        'clean:',
        '\t$(MAKE) -C $(KDIR) M=$(PWD) clean',
    ]


def driver(smi_data: Dict[str, SmiInfo], guids: Dict[str, tuple],
           module_name: str) -> List[str]:
    handlers = list(smi_data.keys())
    unresolved = [name for name, info in smi_data.items()
                  if info.guid not in guids]

    output = [
        '// SPDX-License-Identifier: GPL-2.0',
        '/*',
        ' * Generated by firness: fuzz UEFI SMI handlers from a running kernel.',
        ' *',
        ' * See linux_harness/smi_driver_template.py for why the three physical',
        ' * addresses below are parameters rather than something this discovers.',
        ' */',
        '#include <linux/module.h>',
        '#include <linux/kernel.h>',
        '#include <linux/io.h>',
        '#include <linux/delay.h>',
        '#include <asm/io.h>',
        '',
        f'#include "{FIRNESS_BACKEND_HEADER}"',
        '',
        'MODULE_LICENSE("GPL");',
        'MODULE_DESCRIPTION("firness SMI handler fuzzing harness");',
        '',
        '#define FIRNESS_INPUT_MAX  0x1000',
        '',
        '/* EFI_SMM_COMMUNICATE_HEADER: a GUID, then a native word, then the message.',
        ' * Spelled out because a kernel module cannot include the edk2 headers. */',
        '#define FIRNESS_COMM_GUID_SIZE  16',
        '#define FIRNESS_COMM_DATA_OFF   (FIRNESS_COMM_GUID_SIZE + sizeof(u64))',
        '',
        'static u64 comm_phys;',
        'module_param(comm_phys, ullong, 0444);',
        'MODULE_PARM_DESC(comm_phys, "physical address of the SMM communication region");',
        '',
        'static u64 comm_size = 0x1000;',
        'module_param(comm_size, ullong, 0444);',
        'MODULE_PARM_DESC(comm_size, "size of the SMM communication region");',
        '',
        'static u64 bufptr_phys;',
        'module_param(bufptr_phys, ullong, 0444);',
        'MODULE_PARM_DESC(bufptr_phys,',
        '\t"physical address of gSmmCorePrivate->CommunicationBuffer");',
        '',
        'static u64 bufsize_phys;',
        'module_param(bufsize_phys, ullong, 0444);',
        'MODULE_PARM_DESC(bufsize_phys,',
        '\t"physical address of gSmmCorePrivate->BufferSize");',
        '',
        'static unsigned int smi_port = 0xb2;',
        'module_param(smi_port, uint, 0444);',
        'MODULE_PARM_DESC(smi_port, "APM control port that raises the software SMI");',
        '',
        'static unsigned int smi_data;',
        'module_param(smi_data, uint, 0444);',
        'MODULE_PARM_DESC(smi_data, "value written to smi_port");',
        '',
        'static unsigned int iterations = 1;',
        'module_param(iterations, uint, 0444);',
        'MODULE_PARM_DESC(iterations,',
        '\t"testcases to run before unloading; the fuzzer restores the machine, so 1"',
        '\t" is right under a snapshotting backend");',
        '',
        'static unsigned int chain = 1;',
        'module_param(chain, uint, 0444);',
        'MODULE_PARM_DESC(chain,',
        '\t"handlers to call per iteration, sharing whatever state they leave behind."',
        '\t" A cross handler data bug -- one handler stores a length or a variable that"',
        '\t" another later trusts -- cannot be reached with a single call per iteration,"',
        '\t" because the second handler never runs against the first one\'s state");',
        '',
        'static int target = -1;',
        'module_param(target, int, 0444);',
        'MODULE_PARM_DESC(target,',
        '\t"handler index to call, or -1 to let the fuzzer input choose. Fixing it is"',
        '\t" what makes the driver usable without a fuzzer attached: with no backend"',
        '\t" the input is all zeroes, so the choice byte is always 0 and only the"',
        '\t" first handler is ever reached");',
        '',
        'static u8 firness_input[FIRNESS_INPUT_MAX];',
        'static u64 firness_input_len;',
        'static u64 firness_input_pos;',
        '',
        '/* mirrors ReadBytes in the UEFI harness: a short read leaves zeroes rather',
        ' * than reusing earlier bytes, so a truncated testcase stays reproducible. */',
        'static void firness_read(void *out, size_t len)',
        '{',
        '\tsize_t have = 0;',
        '',
        '\tmemset(out, 0, len);',
        '\tif (firness_input_pos < firness_input_len)',
        '\t\thave = min_t(size_t, len, firness_input_len - firness_input_pos);',
        '\tif (have)',
        '\t\tmemcpy(out, firness_input + firness_input_pos, have);',
        '\tfirness_input_pos += have;',
        '}',
        '',
        'static void __iomem *comm_map;',
        'static void __iomem *bufptr_map;',
        'static void __iomem *bufsize_map;',
        '',
        '/* Publish the buffer the way PiSmmIpl does, then raise the SMI. Without the',
        ' * two stores the SMM entry point dispatches on whatever the last DXE caller',
        ' * left behind, which is not this buffer. */',
        'static void firness_trigger(u64 message_len)',
        '{',
        '\tu64 total = FIRNESS_COMM_DATA_OFF + message_len;',
        '',
        '\twriteq(comm_phys, bufptr_map);',
        '\twriteq(total, bufsize_map);',
        '\twmb();',
        '\toutb((u8)smi_data, (u16)smi_port);',
        '}',
        '',
    ]

    for name, info in smi_data.items():
        value = guids.get(info.guid)
        output.append(f'/* {name}: {info.guid} */')
        if value is None:
            output.append(f'/* skipped: no .dec file declares {info.guid}, so its value')
            output.append(' * cannot be carried into a module that does not link edk2 */')
            output.append('')
            continue
        output.append(f'static const u8 guid_{name}[FIRNESS_COMM_GUID_SIZE] = '
                      f'{guid_values.as_c_initialiser(value)};')
        output.append('')
        output.append(f'static void fuzz_{name}(void)')
        output.append('{')
        output.append('\tu64 message_len;')
        output.append('\tu8 grow;')
        output.append('')
        output.append(f'\tmemcpy_toio(comm_map, guid_{name}, FIRNESS_COMM_GUID_SIZE);')
        output.append('')
        output.append('\t/* the payload size is not known here -- the type that names it')
        output.append('\t * is an edk2 one -- so the fuzzer chooses it, bounded by the')
        output.append('\t * region. The UEFI harness starts from sizeof(payload) instead. */')
        output.append('\tfirness_read(&grow, sizeof(grow));')
        output.append('\tmessage_len = (u64)grow * 4;')
        output.append('\tif (message_len > comm_size - FIRNESS_COMM_DATA_OFF)')
        output.append('\t\tmessage_len = comm_size - FIRNESS_COMM_DATA_OFF;')
        output.append('')
        output.append('\twriteq(message_len, comm_map + FIRNESS_COMM_GUID_SIZE);')
        output.append('')
        output.append('\t{')
        output.append('\t\tu8 byte;')
        output.append('\t\tu64 i;')
        output.append('')
        output.append('\t\tfor (i = 0; i < message_len; i++) {')
        output.append('\t\t\tfirness_read(&byte, sizeof(byte));')
        output.append('\t\t\twriteb(byte, comm_map + FIRNESS_COMM_DATA_OFF + i);')
        output.append('\t\t}')
        output.append('\t}')
        output.append('')
        output.append('\tfirness_trigger(message_len);')
        output.append('}')
        output.append('')

    callable_handlers = [n for n in handlers if smi_data[n].guid in guids]

    output += [
        'static unsigned int step_index;',
        '',
        'static void firness_one(void)',
        '{',
        '\tu8 choice;',
        '',
        f'\tif ({len(callable_handlers)} == 0)',
        '\t\treturn;',
        '\tfirness_read(&choice, sizeof(choice));',
        '\t/* With no fuzzer attached the input is all zeroes, so a chain would call the',
        '\t * same handler every step and no state would cross between handlers. Stepping',
        '\t * from target makes the sequence deterministic: chain=N target=K calls K,',
        '\t * K+1, ... so one handler runs against what the previous one left behind. */',
        '\tif (target >= 0)',
        '\t\tchoice = (u8)(target + step_index);',
        f'\tswitch (choice % {max(len(callable_handlers), 1)}) {{',
    ]
    for index, name in enumerate(callable_handlers):
        output.append(f'\tcase {index}:')
        output.append(f'\t\tfuzz_{name}();')
        output.append('\t\tbreak;')
    output += [
        '\tdefault:',
        '\t\tbreak;',
        '\t}',
        '}',
        '',
        'static int __init firness_init(void)',
        '{',
        '\tunsigned int run;',
        '\tunsigned int step;',
        '',
        '\tif (!comm_phys || !bufptr_phys || !bufsize_phys) {',
        '\t\tpr_err("firness: comm_phys, bufptr_phys and bufsize_phys are required\\n");',
        '\t\treturn -EINVAL;',
        '\t}',
        '',
        '\t/* the region is firmware reserved memory, not device registers, but',
        '\t * ioremap is what gives a mapping the kernel did not already make. */',
        '\tcomm_map = ioremap(comm_phys, comm_size);',
        '\tbufptr_map = ioremap(bufptr_phys, sizeof(u64));',
        '\tbufsize_map = ioremap(bufsize_phys, sizeof(u64));',
        '\tif (!comm_map || !bufptr_map || !bufsize_map) {',
        '\t\tpr_err("firness: could not map the SMM communication region\\n");',
        '\t\tgoto out;',
        '\t}',
        '',
        '\tfor (run = 0; run < iterations; run++) {',
        '\t\tfirness_input_len = FIRNESS_INPUT_MAX;',
        '\t\tfirness_input_pos = 0;',
        '\t\tfirness_start(firness_input, &firness_input_len);',
        '\t\tif (firness_input_len > FIRNESS_INPUT_MAX)',
        '\t\t\tfirness_input_len = FIRNESS_INPUT_MAX;',
        '\t\tfor (step = 0; step < chain; step++) {',
        '\t\t\tstep_index = step;',
        '\t\t\tfirness_one();',
        '\t\t}',
        '\t\tfirness_stop(0);',
        '\t}',
        '',
        '\t/* the only success output: an SMI that reached a handler leaves its trace in',
        '\t * the firmware log, not here, so say at least that the trigger ran. */',
        '\tpr_info("firness: raised %u SMI(s) via port 0x%x\\n", iterations * chain,',
        '\t\tsmi_port);',
        '',
        'out:',
        '\tif (comm_map)',
        '\t\tiounmap(comm_map);',
        '\tif (bufptr_map)',
        '\t\tiounmap(bufptr_map);',
        '\tif (bufsize_map)',
        '\t\tiounmap(bufsize_map);',
        '\tcomm_map = bufptr_map = bufsize_map = NULL;',
        '\t/* Nothing to leave loaded: the work happens here, and returning an error',
        '\t * means insmod unloads us instead of the operator having to. */',
        '\treturn -ENODEV;',
        '}',
        '',
        'static void __exit firness_exit(void) { }',
        '',
        'module_init(firness_init);',
        'module_exit(firness_exit);',
    ]
    if unresolved:
        output.insert(6, ' * Handlers left out because their GUID is not in any .dec: '
                         + ', '.join(sorted(unresolved)))
    return output
