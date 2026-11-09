# Installer-selected libdispatch voucher hooks and receive-header normalization

The selected cache contains an original installation route from libSystem to
libdispatch's constant voucher table and the libkernel root-pointer setter.
Executing the leaf installer and original callbacks on the four existing
zero-name kernel packets normalizes header0x80111112 to0x80001112. The packet's
voucher name remains0 and adoption returns-1 before any thread-local-state read.
Thus the kernel-produced header and post-adoption header are separate states.
[DH1-DH8]

The named clear routine behaves differently on the same zero-name packets:
it returns before changing the header. This is a bounded operation-contract
distinction, not a native resource-leak or authorization finding. The normalized
buffers retain the prior original CF/daemon dispatch and reply behavior. Native
startup, effective hook-table identity and the full FairPlay transaction remain
unknown. The broad interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| DH1 | Pinned cache/kernel/daemon snapshots form the selected source corpus | Addresses, callbacks and component composition | Recapture original source, nlists, chains and eight cache hashes; attest actual loaded-image pairing separately |
| DH2 | Static parent call sites identify an available installation route | libSystem -> dispatch -> voucher table provenance | Verify complete parent bodies, initializer-offset record, exact call instructions and shared-stub targets; native branch/startup execution remains unknown |
| DH3 | Invoking the original leaf initializer provides the installed-table case | Root publication and callback selection in four private runs | Check constant table address, exact root store, all callback loads and unchanged private-state/public-call handoff; capture actual native root and subsequent writers separately |
| DH4 | Prior kernel contexts and Mach/task-transfer contracts apply | Original CF receive bytes/status | Reuse frozen exact-CF-option producers, freshly replay each kernel case and check API arguments/result bytes/volatile clobbers |
| DH5 | All tested voucher names are0 and prior state is-1 | Header normalization without TSD/port work | Check both values at callback entry, exact source branches/stores, absence of MRS/MSR/system calls and complete post-hook buffers; nonzero-right paths remain separate |
| DH6 | Logical v5 fixups/PAC describe private control transfer | Original shared-stub and authenticated callback edges | Verify eleven original pointer chains and exact callback nlists; attest runtime rebases/signatures/hardware authentication separately |
| DH7 | Prior separate run-loop caller, CF object/helper and daemon/library premises apply | Downstream normalized-buffer dispatch | Compare complete buffer/record/reply equality and replay all downstream instructions; effective source/port/cache identity remains unknown |
| DH8 | Clear return, receive-helper return, pthread entry and source return delimit observations | Status, ownership and processing scope | Execute remaining native initialization, rights/thread/environment/output/disposal paths before claiming complete service processing or reply |

## Primary source and recovery boundary

The cache UUID is2bd06591-e751-3e84-963f-b08dab6af23a. Selected libdispatch UUID
is6f5e8225-ad67-3644-afef-25a4a43bf604; libSystem.B UUID is
deaf2098-8edd-3e5d-a821-f63a14d6c055. All addresses are preferred unslid virtual
addresses. [The receive/voucher report](cf_receive_voucher_report.md) retains
the exact kernel options/capacity, original CF/libkernel wrappers, preceding
null-callback cases and original kernel/daemon identities. [DH1]

[Source capture](triage_evidence/dispatch_voucher_hooks_source.json) retains
12 complete cache functions, five16-byte original import stubs,663 instructions,
five original callback-table members, three parent call edges, the libSystem
initializer-offset record, eleven original pointer chains and eight full
cache-file hashes. Parent functions and unused table members are captured
without claiming they all execute. [Profiles](triage_evidence/dispatch_voucher_hooks_profiles.json)
retain four original-kernel records, four installer/receive paths, four clear
comparisons and four downstream dispatch paths.
[Independent checks](triage_evidence/dispatch_voucher_hooks_checks.json)
recapture the source and independently replay every experimental phase.
No IDB query/mutation or native target/API operation occurs.

## Source-defined installation route

```text
libSystem __init_offsets -> initializer0x2cbbed264 [captured, not executed]
  BL0x2cbbed354 -> shared stub0x2d00a0a60
    -> binding cell0x2ddf6bd78 -> _libdispatch_init0x18554a280
       [parent body captured, not executed]
       BL0x18554a460 -> _voucher_init0x18553ac4c [execution begins here]
         X0 = constant table0x1e24b27d0
         B -> shared stub0x18808c2a0
           -> binding cell0x1e21032e8
           -> ___libkernel_voucher_init0x180548154
              STR X0 -> root global0x1ed83e8d8
              raw W0=0; return
```

The leaf dispatch initializer has three instructions. Together with the
four-instruction shared stub and four-instruction libkernel setter, it executes
11 original instructions before the explicit public CF-helper call setup. The
table pointer is selected by original ADRP/ADD instructions; no synthetic callback
pointer is supplied at an internal gate. [DH2,DH3,DH6]

The parent source graph is verified from exact call instructions and original
v5 targets. Full libSystem initialization and `_libdispatch_init` are not run;
their preceding guards, dependencies and native ordering remain unverified.
The source-defined route therefore does not establish effective runtime root
selection or exclude later replacement. [DH2,DH3]

The initializer stub's binding cell0x1e21032e8 is outside both selected
libdispatch-local GOT sections. A library-local GOT search misses this shared
cache binding. The exact original shared stub and v5 chain recover it. Callback
names below come from original nlist records, including entries absent from the
selected export-trie lookup; names alone are not execution proof. [DH1,DH6]

## Original constant table and callback ABI

Table address is0x1e24b27d0. Its first eight observed bytes encode3; the C field
width/type and semantic version label are not recovered from these consumers.
The remaining five8-byte entries decode through authenticated original chains.
[DH1,DH6]

| Table offset, bytes | Original nlist name | Exact target | Execution in this increment |
| ---: | --- | --- | --- |
| 0x08 | `_voucher_mach_msg_set` | 0x18553a9a0 | Body captured |
| 0x10 | `_voucher_mach_msg_clear` | 0x18553aa44 | Four zero-name comparison cases |
| 0x18 | `_voucher_mach_msg_adopt` | 0x18553aa9c | Four CF receive cases |
| 0x20 | `_voucher_mach_msg_revert` | 0x18553ab70 | Four unchanged-state cases |
| 0x28 | `_voucher_mach_msg_fill_aux` | 0x18553c2a8 | Body captured |

Original libkernel revert/adopt wrappers load offsets0x20/0x18 from the published
root and tail-call these actual table members. Original pointer cells are
logically decoded for private execution; hardware PAC is not validated.
The receive-helper's kernel/Mach boundary remains an explicit return-transfer
contract from the matching original kernel result. [DH3,DH4,DH6]

## Header states and original adopt semantics

All four kernel predecessors use CF options0x07000806 and capacity3072 bytes,
producing80 inline bytes plus68 trailer bytes and29 OOL bytes. Reply/service names,
CPU/origin fields and zero audit-token contents retain their prior fixture
provenance. Voucher name at request+16 is0. [DH4,DH5]

| State / operation | Header bits | Voucher name |
| --- | --- | ---: |
| Queued kernel internal header | 0x80111211 | 0 |
| Kernel-produced user header under CF options | 0x80111112 | 0 |
| Post-hook header with the earlier null-callback table | 0x80111112 | 0 |
| Post-hook header with this original dispatch table | 0x80001112 | 0 |
| Direct named clear on the same kernel user packet | 0x80111112 | 0 |

On entry, adopt tests `H & 0x001f0000`. When that field is nonzero, it loads the
voucher name, stores0 through request+16, computes the32-bit value
`H & 0xdfe0ffff`, and stores it through request+0. Only then does it branch on
the loaded voucher name. In these cases,0x80111112 becomes0x80001112 and the
zero name selects the-1 return. The mask also covers bit29; that bit is already0
in these packets. No semantic name is assigned to that additional bit here.
[DH5]

| Original adopt site | Verified operation |
| --- | --- |
| 0x18553aaac /0x18553aab0 | Read header and test voucher-disposition mask |
| 0x18553aabc | Read32-bit voucher name |
| 0x18553aac0 | Store zero voucher name |
| 0x18553aac8 /0x18553aacc | Apply mask and store normalized header |
| 0x18553aad0 | Test previously loaded name after those stores |
| 0x18553ab00..0x18553ab10 | Produce-1 and return through original frame |

The actual adopt path executes19 instructions. It avoids the later MRS/TSD
reads and voucher-object work. The revert callback receives prior state-1 and
executes three instructions to return immediately. CF then stores voucher
state-1, skips copying a voucher object, publishes the local receive name and
returns true. These are bounded private-path results, not native credential or
thread-policy observations. [DH5,DH8]

All USER/OOL/trailer bytes are compared with the original kernel result. Only
the header's byte2 changes from11 to00. The voucher-name zero store is also
verified as an executed idempotent write, rather than inferred from final zeros.
No nonzero voucher right is supplied, consumed or released. [DH4,DH5]

## Named clear is a separate operation

The original clear function extracts the disposition and reads the name before
its guarded stores/helper call. For these disposition17/name0 inputs, it takes
the return path before header or name stores. Four direct-entry comparisons
therefore preserve the complete original kernel user buffer. Each executes
15 instructions without API models or message writes. Residual X0 is0; it is
not assigned a business-status interpretation. [DH5,DH8]

This establishes why the names adopt and clear cannot be substituted when
reconstructing message mutation. Nonzero-name branches, voucher release and
thread-object lifetimes require their own inputs and contracts; no failure or
resource-loss conclusion follows from these zero-name observations.

## Downstream composition and verification

Four original CF source/perform/daemon executions consume the post-adopt buffers
through the prior explicit run-loop caller/source-selection premise. The bytes
now exactly match the earlier0x80001112 explicit-input composition, including
all original dispatch sequences and complete prepared reply buffers. [DH7]

| Request | Original downstream result |
| --- | --- |
| RPC502 | Application/libbsm path reaches pthread identity entry; private120-byte argument record unchanged |
| RPC700 | Callback remains unrecognized; CF stores null generic reply and returns source-handled=true |

Fresh independent replay checks10652 kernel visits,500 installed-hook receive
visits,60 clear-comparison visits and7038 downstream visits:18250 in total.
The receive cases check124 reads /928 bytes,112 writes /768 bytes,48 complete
CPU/record frames, four original installer-return/public-call handoffs and
4194304 final private-RAM bytes. Clear cases check another4194304 final RAM
bytes. Whole kernel/downstream states and inherited original ABI/object journals
are independently replayed separately. Totals count repeated private fixtures,
not distinct native maps or native execution duration.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_dispatch_voucher_hooks.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_dispatch_voucher_hooks.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_dispatch_voucher_hooks.py
```

Time is O(B+H+S+V+J), space O(B+S+R+J), for fixed selected source bytes B,
streamed hash bytes H, original symbol records S, visits V, journal bytes J and
private RAM R. Addresses/state pointers are64-bit; message fields/masks32-bit;
all offsets and extents are bytes. Native image pairing, table replacement,
source/port identity, syscall/task coupling and successful FairPlay output remain
unknown. The broad investigation remains active.

| Impact | Remaining requirement / opportunity | Completing evidence |
| --- | --- | --- |
| High | Effective native initialization/table history | Actual parent execution/guards, root and later writers, matching loaded libraries |
| High | Receive-return/source-selection coupling | Original run-loop caller, port-set/direct-port identity and cached CF object history |
| High | Full request/reply ownership | Remaining application/environment/output producers and original reply/VM/right consumption |
| Medium | Nonzero voucher-name paths | Matching legitimate voucher rights, TSD/object states and original helper effects |
| Medium | Set/aux table members | Original outgoing voucher and auxiliary-message contracts beyond their captured names/bodies |
| Medium | Shared-cache import discovery | Follow original branch stubs and chains beyond library-local GOT/export-only inventories |

[Preservation](triage_evidence/dispatch_voucher_hooks_delivery.json) and
[quality gates](triage_evidence/dispatch_voucher_hooks_quality_gates.json) record
retained evidence and reporting/index changes.

QG1: factual interface analysis. QG2: DH1-DH8 with dependent results and probes.
QG3: installer-selected table, original normalization, clear comparison and
downstream composition covered; full goal active. QG4: byte extents,32/64-bit
operations, status roles, counts and complexity explicit. QG5: static parent
routes, leaf execution, actual versus null hooks, zero versus nonzero names,
normalization and native ownership remain distinct. QG6: original cache/kernel
bytes, nlists, eleven chains, three parent edges, eight cache hashes and fresh
independent packet/store-order/initializer/clear/record/reply oracles.
QG7: impact-bounded continuation above.
