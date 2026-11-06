"""Cross-module risk in what an SMI handler does with its comm buffer.

An SMI handler receives a buffer the caller owns. Whatever it then hands to another
module's interface arrives there WITHOUT that module's own SMI entry validation, because
the call is a protocol call, not an SMI. That difference is a bug class on its own, and it
is the one injected into EVAL-1:

    RWVariableHandler        reads CommBuffer into CommData, takes
                             VarName = (CHAR16 *)CommData->Data and
                             DestBuffer = ((RW_VARIABLE_INFO *)CommBuffer)->Data + Offset,
                             and calls mSmmVariable->SmmSetVariable with both.

    SmmVariableHandler       reaches the same variable services, but first checks
                             NameSize >= sizeof(CHAR16) and
                             Name[NameSize/sizeof(CHAR16) - 1] == L'\\0'
                             (VariableSmm.c:546).

So a caller-supplied name that is not NUL-terminated cannot reach StrLen through the
standard handler, and can through RWVariable. Fuzzing found it after 110255 iterations and
filed it against VariableSmm.efi, the module that faulted; the edge was in the source the
whole time.

WHAT THIS DOES NOT DO. There is no path sensitivity and no knowledge of what any
particular callee validates. A flagged edge is a place to read, not a confirmed defect: a
handler that validates thoroughly before the call is flagged exactly like one that does
not. The ordering is reported so that can be judged, and nothing here is a severity.
"""

from typing import Dict, List, Set

# The parameter an SMI handler receives its untrusted bytes in. Fixed by
# EFI_MM_HANDLER_ENTRY_POINT, so it is a name and not a guess -- but a handler may copy out
# of it into a local first, which is what the propagation below is for.
COMM_BUFFER = 'CommBuffer'
COMM_SIZE = 'CommBufferSize'

# A call whose job is to move bytes. If one of its arguments is tainted then its other
# pointer arguments are too, which is the single hop that carries CommBuffer into the local
# struct almost every handler copies it into.
COPY_LIKE = ('CopyMem', 'DuplicateMemory', 'CopyGuid', 'SetMem', 'AsanCopyMem', 'memcpy')


def _mentions(text: str, names: Set[str]) -> bool:
    """Whether any of `names` appears in `text` as a whole identifier."""
    if not text:
        return False
    for name in names:
        start = 0
        while True:
            at = text.find(name, start)
            if at < 0:
                break
            before = text[at - 1] if at > 0 else ' '
            after = text[at + len(name)] if at + len(name) < len(text) else ' '
            if not (before.isalnum() or before == '_') and not (after.isalnum() or after == '_'):
                return True
            start = at + 1
    return False


def _arg_text(arg: dict) -> str:
    return ' '.join(str(arg.get(k) or '') for k in ('variable', 'assignment', 'usage'))


def propagate(tainted: Set[str], edge: dict) -> None:
    """Extend `tainted` with what this one call launders, if it is a copy.

    A copy-like call with a tainted argument taints the variables of its other arguments;
    that is the hop from CommBuffer into the local the handler works on. Only copies: an
    arbitrary function that happens to take CommBuffer does not hand attacker control to
    everything else on its argument list.
    """
    args = (edge.get('Arguments') or {}).values()
    if not any(_mentions(_arg_text(a), tainted) for a in args):
        return
    if not any(edge.get('Function', '').endswith(name) for name in COPY_LIKE):
        return
    for arg in args:
        var = (arg.get('variable') or '').strip()
        if var and not var.startswith('__'):
            tainted.add(var)


def cross_module_edges(all_edges: List[dict]) -> List[dict]:
    """Calls through another module's interface carrying caller-controlled data.

    `Service` is what makes it cross-module: the analyzer fills it when the callee is
    reached through a pointer -- mSmmVariable->SmmSetVariable -- rather than linked in.
    A direct call to a library function in the same image has no Service and is not an
    interface crossing, however badly it may be used.
    """
    by_handler: Dict[str, List[dict]] = {}
    for edge in all_edges:
        by_handler.setdefault(edge.get('EnclosingFunction') or '', []).append(edge)

    findings = []
    for handler, edges in sorted(by_handler.items()):
        if not handler:
            continue
        tainted = {COMM_BUFFER, COMM_SIZE}
        ordered = sorted(edges, key=lambda e: e.get('CallOrder') or 0)
        for edge in ordered:
            #
            # Judged against the taint known AT THIS POINT in the body, then extended.
            # Computing the whole set first and applying it to every call let a crossing at
            # call 0 be judged with taint learned from a copy at call 1 -- that is a claim
            # that a value was attacker-controlled before the copy that made it so, and
            # smi_call_edges_check.py has the case that caught it.
            #
            if not (edge.get('Service') or '').strip():
                propagate(tainted, edge)
                continue
            args = edge.get('Arguments') or {}
            carried = []
            for key in sorted(args):
                arg = args[key]
                text = _arg_text(arg)
                if not _mentions(text, tainted):
                    continue
                assignment = (arg.get('assignment') or '').strip()
                # Offset arithmetic on a caller-owned pointer is the sharpest shape: the
                # callee is handed a destination the caller chose, outside any object the
                # callee can check. That is issue #48.
                offsetted = bool(assignment) and ('+' in assignment) and _mentions(assignment, {COMM_BUFFER})
                carried.append({
                    'arg': key,
                    'variable': arg.get('variable') or '',
                    'data_type': arg.get('data_type') or '',
                    'assignment': assignment,
                    'offset_arithmetic': offsetted,
                })
            propagate(tainted, edge)
            if not carried:
                continue
            findings.append({
                'handler': handler,
                'file': edge.get('EnclosingFile') or '',
                'service': edge.get('Service'),
                'function': edge.get('Function'),
                'call_order': edge.get('CallOrder') or 0,
                'ran_before': [e.get('Function') for e in ordered
                               if (e.get('CallOrder') or 0) < (edge.get('CallOrder') or 0)],
                'carries': carried,
            })
    return findings


def report(all_edges: List[dict]) -> None:
    """One line per crossing, plus the arguments that carry caller data."""
    findings = cross_module_edges(all_edges)
    handlers = {e.get('EnclosingFunction') for e in all_edges if e.get('EnclosingFunction')}
    print(f'SMI cross-module: {len(findings)} interface crossing(s) carrying '
          f'caller-controlled data, from {len(handlers)} handler body(ies)')
    for find in findings:
        print(f"  {find['handler']} -> {find['service']}->{find['function']}  "
              f"(call {find['call_order']} in the body)")
        for carry in find['carries']:
            why = ' [offset arithmetic on the caller\'s buffer]' if carry['offset_arithmetic'] else ''
            shown = carry['assignment'] or carry['variable']
            print(f"      {carry['arg']} {carry['data_type']} = {shown}{why}")
        if find['ran_before']:
            print(f"      ran first in this body: {', '.join(find['ran_before'])}")
        print('      the callee validates its own SMI entry path, not this one -- read '
              'what it assumes about these arguments')
