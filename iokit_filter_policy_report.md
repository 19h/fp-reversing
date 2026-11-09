# IOKit filter callbacks, per-task cache and Sandbox linkage

Original collection evidence links IOKit's open/method/free paths to Sandbox's
`iofilter_resolver`, `iofilter_applier` and `iofilter_release`. Its registration
caller, three original callback pointers and matching call discriminators are
resolved. A24 B per-task cache record is distinct from the48 B connection-owner
record and the separate24 B Sandbox policy object. Runtime registration and
actual policy decisions remain unknown. [FP1-FP8]

[Source capture](triage_evidence/iokit_filter_policy_source.json),
[independent checks](triage_evidence/iokit_filter_policy_checks.json),
[preservation seal](triage_evidence/iokit_filter_policy_delivery.json) and
[quality gates](triage_evidence/iokit_filter_policy_quality_gates.json)
retain original bytes, symbols and bindings. No target code executes/emulates,
no policy callback is invoked, and no native IPC observation is added.

```text
Sandbox hook_policy_init -> registerFilterCallbacks(table,24)
                                   |
IOKit open: lookup(client,owningTask) -> resolver if needed
                                   -> cache(task,policy,next)
IOKit method: lookup(client,callingTask)
               -> optional applier(client,policy,kind,selector)
               -> zero status continues to method helper
IOUserClient::free: release(policy) -> free cache node -> free expansion
```

These are static interfaces, conditional on valid state and preceding guards.
The [connection lifecycle](iokit_connection_lifecycle_report.md) and
[structure arguments](iokit_structure_arguments_report.md) supply surrounding
interfaces. The [ZUT capture](zut_trace_report.md) still has a failed open and
no selector26 transaction. B denotes bytes; pointers/unsigned long are64-bit,
selector/status/size words use their stated widths; addresses are unslid.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| FP1 | Pinned collection identifies kernel and Sandbox images | Original addresses, symbols and records | Rehash/recapture; preserve kernel and Sandbox UUIDs and entry-specific compiler bounds |
| FP2 | Registration supplies valid persistent table storage and callbacks | Applying static callback interfaces | Match actual initialization/registration and lifetime; image-zero root is not a runtime observation |
| FP3 | Preceding connection, object, task and policy guards hold | Method-admission interpretation | Establish actual client/task identity, admission and module pairing; historical open failed |
| FP4 | Selected calls return normally and declared fields remain valid | Local status/publication/cleanup order | Resolve transitive calls, aliases, exceptions and concurrent writers separately |
| FP5 | Original lock paths and allocator classes supply their declared contracts | Cache operations and size/class interpretation | Source checks cover lock call sites and allocation metadata; native exclusion/zone extent/ownership remain unknown |
| FP6 | Exact nlist types and SDK constants corroborate the compared ABI | Role names, status names and argument widths | Check original names/chains and seven SDK assertions; SDK identity is not runtime identity |
| FP7 | Seven ADRP candidate windows describe only their declared scan | Static registration and reference leads | Scan covers kernel text, page-relative instructions and sixteen following instructions; it is not an exhaustive semantic writer census |
| FP8 | Earlier caller/record contracts retain their stated premises | FairPlay applicability and surrounding dispatch | Preserve prior hashes; no successful native daemon/kext processing is inferred |

## Original registration and callback ABI

Exact `IOUserClient::registerFilterCallbacks(io_filter_callbacks const*,unsigned long)`
is `0xfffffe000c572e34`. It requires size>=24 B, then uses CASAL to install
the supplied pointer into image slot `0xfffffe0007f50528` when its old value
is zero. Too-small size returns `0xe00002c2`; an already-nonzero slot returns
`0xe00002c2+0x13 = 0xe00002d5`, SDK `kIOReturnBusy`. The body stores a pointer;
it does not copy the24 B table. Table validity/lifetime and actual installation
remain premises. It does not explicitly reject a null proposed pointer.
[FP1-FP2,FP4,FP6]

The original root slot contains eight zero bytes and is not a chained pointer.
This is an image initialization fact. Sandbox `_hook_policy_init` at
`0xfffffe000b7a5978` supplies table `0xfffffe0008a79de0`, size24, at call
`0xfffffe000b7a6d08`, through stub `0xfffffe000b7e42f0`. Original import
cell `0xfffffe0008a7fbd8` resolves to the registration entry. The caller tests
nonzero return and branches to `0xfffffe000b7a72a8`; complete initialization
reachability/failure handling is not established. [FP1-FP2]

| Table offset / original cell | Exact Sandbox target | Call interface recovered from original callers | IA discriminator |
| --- | --- | --- | --- |
| +0 / `0xfffffe0008a79de0` | `iofilter_resolver`, `0xfffffe000b7906d4` | task, client, connection type32, output-policy-word pointer | 0x0e2e |
| +8 / `0xfffffe0008a79de8` | `iofilter_applier`, `0xfffffe000b7904e0` | client, policy word64, filter kind32, selector32 | 0xb286 |
| +16 / `0xfffffe0008a79df0` | `iofilter_release`, `0xfffffe000b790454` | policy word64; caller does not consume a return value | 0x0a98 |

Exact names are original Sandbox nlist symbols, including task/client pointers,
unsigned-long policy values and `io_filter_type_t`. Each original callback
pointer's discriminator matches its IOKit call site. This proves a static ABI
binding, not hardware authentication or execution. Sandbox UUID is
`3db87bed-1032-30fa-906f-828b8ad70ca8`. Its977 LC_FUNCTION_STARTS entries,
separate from the kernel's function table, bound all five captured Sandbox
bodies; the large initialization body is retained without claiming all its
operations have been interpreted. [FP1-FP2,FP6]

## Cache, ownership and method admission

Anonymous helper `0xfffffe000c568e48` searches client expansion+8 for a task
match. An existing match returns its stored policy value without replacing it.
Absent task plus incoming zero returns zero without allocation. Absent task plus
nonzero policy requests a new record, stores task/policy/next and publishes it
at the list head. Its selected paths acquire/release the client lock; native
exclusion and duplicate-construction behavior remain unknown. [FP4-FP5]

| Original allocation class / size word | Accessed record | Distinction |
| --- | --- | --- |
| `site.IOUCFilterPolicy`,24 B; allocation `0xfffffe0007e56dd8`, free `0xfffffe0007e56e18` | task+0, policy+8, next+16; three64-bit words | Per-client/task filter cache |
| `site.IOUserClientOwner`,48 B; `0xfffffe0007e56d58` | task+0, client+24 and two list-link pairs | Connection-owner bookkeeping, separate helper `0xfffffe000c56848c` |
| `site.ExpansionData`,16 B; `0xfffffe0007e56e58` | first word references another facility; second word is filter-list head | Contains the cache head, not an inline cache node |
| `site.typeof(**(&filter))`,24 B; Sandbox `0xfffffe0008a7dde8` | Sandbox `iofilter` object; three per-kind words | Separate object referenced by cached policy value |

Original class-name/signature pointers and size word+44 are retained.
`_kalloc_type_impl`'s cold path reads flags/size with LDP at
`0xfffffe000bcfebe8`; the pinned reference declaration separately corroborates
this metadata interpretation. Requested size is not a native zone-allocation
extent or liveness proof. [FP1,FP5-FP6]

Open first queries the per-task cache at `0xfffffe000c56ef70`. If resolver is
needed, call `0xfffffe000c56f07c` supplies owning task, client, connection type
and a local output-policy cell. Return0 reaches cache storage; Unsupported
`0xe00002c7` takes the selected zero-status continuation; other nonzero status
takes failure handling. Returned policy zero creates no cache node. Owner
bookkeeping occurs separately. Resolver internals and native outcomes are not
inferred from these interface continuations. [FP3-FP5]

Method processing derives the calling task, searches the filter list by task
pointer identity, unlocks, then conditionally calls the applier. Its arguments
at `0xfffffe000c570c5c` are client, cached policy value, kind1, selector.
Return0 reaches the method helper; nonzero skips it and reaches output-size
publication/cleanup. Earlier argument preparation has already occurred, so
this does not imply that rejection precedes every operation. Missing matching
record, zero policy, or absent applier takes the selected method continuation
without this callback. Other guards remain separate. [FP3-FP5]

| Original entry point | Filter kind | Evaluator call site |
| --- | ---: | --- |
| MIG2865 `io_connect_method` -> `0xfffffe000c5708f4` | 1 | `0xfffffe000c570c5c` |
| MIG2872 `io_connect_method_var_output` -> `0xfffffe000c570318` | 1 | `0xfffffe000c570654` |
| MIG2866 `io_connect_async_method` -> `0xfffffe000c570cc0` | 2 | `0xfffffe000c571088` |
| Original IOKit trap handler `0xfffffe000c572744` | 3 | `0xfffffe000c5729c4` |

Three original MIG records bind the method frontends. Numeric kind values are
call-site facts; the names correspond to these entry points, not an invented
public enum declaration. The Sandbox applier selects policy word+0 for kind1,
+8 for kind2 and+16 for kind3. Lower policy encodings, rules and actual decisions
remain outside this report. A cached nonzero policy assumes the registered
callback-table root remains valid; this is a lifetime invariant, not a modeled
fault experiment. [FP1-FP4,FP6]

## Cleanup and evidence limits

Exact `IOUserClient::free` at `0xfffffe000c5654a8` saves each cache node's next
pointer, invokes callback+16 for its nonzero policy, then calls the internal
typed free for the cache node. After the list, it clears client+136, frees
ExpansionData and requests lock destruction before its base-free continuation.
These source requests do not prove native retirement or ownership balance.
[FP4-FP5]

The release callback tail-calls exact `iofilter_free(iofilter*)` at
`0xfffffe000b79045c`. Its final typed-free request uses Sandbox stub
`0xfffffe000b7e41c0`, bound to exact `_IOFreeTypeImpl` at
`0xfffffe000c4ba368`, whose original two-instruction body tail-calls internal
`_kfree_type_impl` at `0xfffffe000bcff010`. This frees the separate policy
object under its declared contracts; it is distinct from IOKit's cache-node
free and from connection-name/right deallocation. [FP1,FP4-FP6]

The kernel ADRP scan retains seven candidate windows spanning registration,
open, free, three method frontends and the IOKit trap. Its page/immediate/window
criteria are recorded; no complete writer census or actual runtime table value
is claimed. No new Mach port name or emission is established. The original
connection remains the method destination; filter values are kernel policy
data, not Mach names. [FP3,FP7-FP8]

Verification covers14 kernel and five Sandbox compiler-bounded bodies,
4519 instructions /18076 B,81 exact instruction assertions, three callback
bindings, five allocation-class records, three MIG records, seven candidate
windows,977 Sandbox function-start entries, seven SDK assertions/two hashed
headers and ten rejected static alterations. Target instruction visits,
emulation, new runtime observations and policy-callback invocations are0.

| Impact | Remaining evidence | Architectural question |
| --- | --- | --- |
| High | Native initialization, callback registration and actual client/task identity | Which registered policies apply to a live FairPlay connection |
| High | Resolver/applier's lower rule and policy-word encoding contracts | What decisions the resolved callbacks actually make for the relevant selectors |
| High | Concurrent construction, policy references and full destruction | Ownership balance beyond cache/store/release/free requests |
| Medium | Async notification/trap argument and result interfaces | Remaining direction, port and payload contracts around the newly mapped entry points |
| Medium | Complete root-writer and component lifetime analysis | Publication/lifetime invariants beyond the bounded ADRP candidate scan |

Task-policy lookup is O(k) time for k list nodes and O(1) auxiliary space;
registration has a constant amount of source work excluding hardware contention.
Capture/scan is O(collection+fixups+symbols+kernel words) time and
O(collection+capture) space. Native timing/concurrency is not measured.
The full interface objective remains active.

## Quality gates and reproduction

QG1: descriptive interface evidence requires no normative conclusion.
QG2: FP1-FP8 identify assumptions, dependent claims and falsification probes.
QG3: registration, callback ABI, task cache, owner/policy distinctions,
method-kind mapping and cleanup linkage are covered; native decisions remain unknown.
QG4:24/48/16 B records, word widths, exact status arithmetic, source bounds and
complexities are explicit; allocator metadata is distinct from native zone extent.
QG5: image versus runtime root, optional callback versus other admission,
same-sized distinct allocations and release request versus retirement are separated.
QG6: original collection/Sandbox bytes, exact symbols, chains, allocation-class
names, compiler bounds and SDK constants supply verified provenance.
QG7: five bounded continuation questions above have impact labels.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_iokit_filter_policy.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iokit_filter_policy.py
```
