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

A SECOND SHAPE, which the argument-only pass above cannot see. A handler can cross into
another module carrying nothing at all and still be doing the caller's bidding, because
the caller chooses whether the call happens:

    UnregisterCBFunctionLight   switch (CommunicationData->Function) {
                                  case UNREGISTER_FROM_RSC:
                                    if (CommunicationData->Disable == FALSE) break;
                                    if (mRscProtocol != NULL)
                                      mRscProtocol->Unregister (LightStatusCode);

LightStatusCode is the handler's own function, so no argument is tainted. The caller still
decides whether a peer module's status-code registration is torn down, and decides it again
on the next SMI. EVAL-1 dispatched this handler and its HwAlarm twin about 93000 times
between them for no sanitizer report, and there is none to get: nothing accesses memory out
of bounds. The defect, if the callee has one, is a state transition -- unregister twice,
unregister what was never registered, use what was unregistered. These are reported as
reach 'control' and listed separately, because triaging one asks a different question.

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

# The core's own service tables. A handler reaching these is not bypassing a peer module's
# SMI entry validation -- it IS calling the core, which validates its own arguments, so
# these do not carry the property that makes the class interesting.
#
# Measured on EVAL-1 run 42310220335: of 5 crossings, 3 were gSmst->SmmAllocatePool taking
# *CommBufferSize and gSmst->SmmFreePool taking back the buffer it had just allocated.
# Both are what a correct handler does, and reporting them alongside the two real findings
# put the signal at two in five.
#
# They are classified rather than dropped. An unvalidated size reaching an allocator, or a
# caller-controlled name reaching gRT->SetVariable, is a real finding -- it is just a
# different one, and a reader who wants it should not have to re-run the analysis to see
# that it was considered.
CORE_SERVICES = ('gSmst', 'gMmst', 'gBS', 'gRT', 'gDS', 'gST', 'gSmmst')


def crossing_kind(service: str) -> str:
    """'core-service' for the core's own tables, 'peer-protocol' otherwise."""
    head = (service or '').split('->')[0].strip()
    return 'core-service' if head in CORE_SERVICES else 'peer-protocol'



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
            #
            # Two ways a crossing can be caller-controlled, and only one of them shows up
            # in the arguments.
            #
            #   reach 'data'     -- an argument carries caller bytes. RWVariable hands
            #                       SmmSetVariable a name and a destination the caller
            #                       chose; issues #47 and #48.
            #
            #   reach 'control'  -- no argument carries anything, but the call sits under a
            #                       condition that reads caller bytes, so the caller
            #                       chooses WHETHER it happens and can choose again next
            #                       SMI. HwLight and HwAlarm tear down a peer module's
            #                       status-code registration this way, passing only their
            #                       own function pointer. 93000 dispatches across the two
            #                       of them produced no sanitizer report, because there is
            #                       no bad access to report -- the defect is a state
            #                       transition, and the argument-only pass could not see it.
            #
            gate = (edge.get('CallerGate') or '').strip()
            if not carried and not gate:
                continue
            findings.append({
                'kind': crossing_kind(edge.get('Service')),
                'reach': 'data' if carried else 'control',
                'gate': gate,
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
    """Peer-protocol crossings in full; core-service ones counted, not listed.

    The split is about which finding a reader is being handed, not about hiding anything:
    a peer-protocol crossing is the shape that skipped another module's validation, and a
    core-service one is a handler using the core with data it was given. Both are printed
    with enough to act on -- the second as a count and a list of names, because on EVAL-1
    those were three correct allocator and free calls and burying two real findings under
    them is how a report stops being read.
    """
    findings = cross_module_edges(all_edges)
    peer = [f for f in findings if f['kind'] == 'peer-protocol' and f.get('reach') != 'control']
    gated = [f for f in findings if f['kind'] == 'peer-protocol' and f.get('reach') == 'control']
    core = [f for f in findings if f['kind'] == 'core-service' and f.get('reach') != 'control']
    core_gated = [f for f in findings if f['kind'] == 'core-service' and f.get('reach') == 'control']
    handlers = {e.get('EnclosingFunction') for e in all_edges if e.get('EnclosingFunction')}

    print(f'SMI cross-module: {len(peer)} peer-protocol crossing(s) carrying '
          f'caller-controlled data, from {len(handlers)} handler body(ies)')
    for find in peer:
        print(f"  {find['handler']} -> {find['service']}->{find['function']}  "
              f"(call {find['call_order']} in the body)")
        for carry in find['carries']:
            why = " [offset arithmetic on the caller's buffer]" if carry['offset_arithmetic'] else ''
            shown = carry['assignment'] or carry['variable']
            print(f"      {carry['arg']} {carry['data_type']} = {shown}{why}")
        if find['ran_before']:
            print(f"      ran first in this body: {', '.join(find['ran_before'])}")
        print('      the callee validates its own SMI entry path, not this one -- read '
              'what it assumes about these arguments')

    #
    # Printed as its own class, not merged into the list above. A reader triaging these is
    # asked a different question: not "what does the callee assume about this value" but
    # "what happens if the caller does this twice, or without the call that should have
    # come first". Merging them would put a state-transition finding under a heading that
    # says it carries data, which is the one thing it does not do.
    #
    if gated:
        print(f'  and {len(gated)} peer-protocol crossing(s) the caller can choose to '
              f'trigger while carrying no data into them:')
        for find in gated:
            print(f"  {find['handler']} -> {find['service']}->{find['function']}  "
                  f"(call {find['call_order']} in the body)")
            print(f"      reached when: {find['gate']}")
            if find['ran_before']:
                print(f"      ran first in this body: {', '.join(find['ran_before'])}")
            print('      no argument carries caller data, so no sanitizer report is '
                  'expected -- read the callee for what repeating this does, and what it '
                  'assumes ran first')

    if core_gated:
        names = sorted({f"{f['service']}->{f['function']}" for f in core_gated})
        print(f'  and {len(core_gated)} call(s) into the core services the caller can '
              f'choose to trigger: {", ".join(names)}')

    if core:
        names = sorted({f"{f['service']}->{f['function']}" for f in core})
        print(f'  and {len(core)} call(s) into the core services with caller-controlled '
              f'arguments: {", ".join(names)}')
        print('      the core checks its own arguments, so these are only a finding if the '
              'value itself is out of range -- a size, a length or a name worth reading')
