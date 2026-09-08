import os
import re


# Resolve an EDK2 GUID symbol to its bytes.
#
# The UEFI harness never needs this: it writes gEfiSmmVariableProtocolGuid and the edk2
# build resolves the symbol. A Linux driver cannot link against edk2, so the value has to
# be carried across as literals, and the only place it exists in source form is the
# [Guids] / [Protocols] / [Ppis] sections of the package .dec files.
DECLARATION = re.compile(
    r'^\s*(g[A-Za-z0-9_]+)\s*=\s*\{\s*'
    r'(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*'
    r'\{([^}]*)\}\s*\}')


def collect(edk2_dirs):
    """Every GUID symbol declared by the .dec files under these roots."""
    found = {}
    for root in edk2_dirs:
        if not root or not os.path.isdir(root):
            continue
        for base, _, names in os.walk(root):
            for name in names:
                if not name.endswith('.dec'):
                    continue
                try:
                    with open(os.path.join(base, name), errors='ignore') as handle:
                        text = handle.read()
                except OSError:
                    continue
                for line in text.splitlines():
                    match = DECLARATION.match(line)
                    if not match:
                        continue
                    tail = [part.strip() for part in match.group(5).split(',')]
                    tail = [part for part in tail if part]
                    if len(tail) != 8:
                        continue
                    found.setdefault(match.group(1), (match.group(2), match.group(3),
                                                      match.group(4), tail))
    return found


def as_c_initialiser(value):
    """The EFI_GUID as a byte array, in the little endian layout a comm buffer wants.

    EFI_GUID is not sixteen ordered bytes: the first three fields are integers, so they go
    out little endian while the last eight are already bytes. Writing the struct field by
    field in a Linux driver would need the edk2 type; writing the bytes does not.
    """
    data1, data2, data3, data4 = value
    one, two, three = int(data1, 16), int(data2, 16), int(data3, 16)
    octets = [one & 0xFF, (one >> 8) & 0xFF, (one >> 16) & 0xFF, (one >> 24) & 0xFF,
              two & 0xFF, (two >> 8) & 0xFF,
              three & 0xFF, (three >> 8) & 0xFF]
    octets += [int(part, 16) & 0xFF for part in data4]
    return '{ ' + ', '.join(f'0x{octet:02x}' for octet in octets) + ' }'
