"""Make a handler's parameter block available to the harness without its header.

An SMI handler's CommBuffer is a pointer to a parameter block, and the harness has to
declare one to fuzz it field by field. The obvious way to get the declaration is to
#include the header that holds it, and that is what the generator used to require: a
payload type whose header is not reachable as <Dir/File.h> got its handler dropped.

That rule drops exactly the handlers worth fuzzing. edk2 convention puts a comm-buffer
struct in the driver's own directory -- OvmfPkg/HwLight/SmmLight.h,
MdeModulePkg/Universal/QueryVariableInfo/QueryVariableInfo.h -- because nothing outside
the driver is supposed to construct one. Every vendor-specific handler looks like this,
and so do several upstream ones.

Including the private header anyway is not a fix. OvmfPkg/Spi/SmmSpiCommon.h holds
SPI_COMM_HEADER and also pulls in <Library/SpiFlashLib/SpiCommon.h>, which lives at
UefiPayloadPkg/Library/SpiFlashLib/SpiCommon.h -- not under any Include/ directory, so it
only resolves for a module whose own -I flags reach it. A harness that includes the header
inherits that problem; a harness that carries just the struct does not.

So: re-emit the struct from the field list the analyser already recorded, and only when
every field's type is one the harness is certain to have. "Certain" means a base type, or
a type whose own declaration IS includable, or a struct this module can emit too. Anything
else still drops the handler -- the point is to narrow that outcome to the cases where
generating would really produce a harness that cannot compile, not to guess.
"""

import re
from typing import Dict, List, Optional, Tuple

# Spelled by the compiler or by MdePkg/Include/Base.h, which every harness already has
# through default_includes. Listing them beats asking types.json, which has no entry for a
# builtin and would send every one of them down the "unresolvable" path.
BASE_TYPES = {
    'void', 'VOID', 'char', 'short', 'int', 'long', 'unsigned', 'signed', 'float',
    'double', '_Bool', 'size_t', 'intptr_t', 'uintptr_t',
    'BOOLEAN', 'CHAR8', 'CHAR16', 'UINT8', 'UINT16', 'UINT32', 'UINT64', 'UINTN',
    'INT8', 'INT16', 'INT32', 'INT64', 'INTN', 'EFI_STATUS', 'EFI_HANDLE',
    'EFI_PHYSICAL_ADDRESS', 'EFI_VIRTUAL_ADDRESS', 'EFI_TPL', 'EFI_LBA',
    'RETURN_STATUS', 'EFI_GUID', 'GUID', 'EFI_EVENT', 'EFI_TIME',
}

# "UINT8[1024]" -> ("UINT8", "[1024]"); "UINT8 *" -> ("UINT8 *", "")
_ARRAY = re.compile(r'^(?P<base>.*?)\s*(?P<dims>(?:\[[^\]]*\])+)$')


def split_array(field_type: str) -> Tuple[str, str]:
    match = _ARRAY.match((field_type or '').strip())
    if match:
        return match.group('base').strip(), match.group('dims')
    return (field_type or '').strip(), ''


def bare_name(field_type: str) -> str:
    """The type name with pointers, arrays and qualifiers stripped off."""
    base, _ = split_array(field_type)
    base = base.replace('*', ' ')
    words = [w for w in base.split() if w not in ('const', 'volatile', 'CONST', 'VOLATILE',
                                                  'struct', 'union', 'enum')]
    return words[-1] if words else ''


def resolve(root: str,
            types: Dict[str, object],
            aliases: Dict[str, str],
            includable) -> Tuple[Optional[List[str]], str]:
    """Work out how the harness can get a declaration of `root`.

    Returns (order, reason):
      ([], '')            -- nothing to do, the real declaration is includable
      ([names...], '')    -- emit these struct definitions, dependencies first
      (None, 'reason')    -- cannot be made available; the caller should drop the handler

    `includable(TypeInfo) -> bool` says whether that type's own header can be #included,
    which is the generator's existing test; it is injected so this module does not depend
    on how include paths are filtered.
    """
    order: List[str] = []
    seen = set()

    def walk(name: str, why: str) -> str:
        """Returns '' when `name` is available, otherwise a reason it is not."""
        if not name or name in BASE_TYPES:
            return ''
        real = name
        info = types.get(real)
        if (info is None or not getattr(info, 'fields', None)) and real in aliases:
            # the recorded field type is a typedef; the fields hang off the underlying tag
            real = aliases[real]
            info = types.get(real)
        if info is None:
            return f'{name} is not a type the analyser recorded ({why})'
        if includable(info):
            return ''
        if real in seen:
            return ''
        if not getattr(info, 'fields', None):
            # opaque to us and not includable: a forward declaration would compile but
            # sizeof() would not, and sizeof is the whole point
            return f'{name} has no recorded fields and no header the harness can include'
        seen.add(real)
        for field in info.fields:
            inner = bare_name(field.type)
            if inner == real:
                # a struct containing itself can only do so through a pointer, and a
                # pointer to an incomplete type is fine
                continue
            problem = walk(inner, f'field {real}.{field.name}')
            if problem:
                return problem
        order.append(real)
        return ''

    problem = walk(root, 'the handler parameter block')
    if problem:
        return None, problem
    return order, ''


def render(order: List[str], types: Dict[str, object]) -> List[str]:
    """C declarations for the types `resolve` said to emit, dependencies first."""
    if not order:
        return []
    out = [
        '#ifndef __FIRNESS_VENDORED_TYPES__',
        '#define __FIRNESS_VENDORED_TYPES__',
        '',
        '//',
        '// Parameter blocks re-emitted from the static analysis, because the headers that',
        '// declare them are private to their drivers and cannot be included from here.',
        '// Field order and spelling come from the analyser, so sizeof and every offset',
        '// match the firmware under test; see common/vendor_types.py for why this is a',
        '// copy rather than an #include.',
        '//',
        '',
    ]
    for name in order:
        info = types[name]
        out.append(f'typedef struct {{')
        for field in info.fields:
            base, dims = split_array(field.type)
            # "UINT8 *" -> "UINT8 *Name"; "UINT8" + "[16]" -> "UINT8 Name[16]"
            spacer = '' if base.endswith('*') else ' '
            out.append(f'  {base}{spacer}{field.name}{dims};')
        out.append(f'}} {name};')
        out.append('')
    out.append('#endif // __FIRNESS_VENDORED_TYPES__')
    return out
