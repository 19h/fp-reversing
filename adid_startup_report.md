# CoreADI adid: startup, record transfer, listener and shutdown

The original startup path is now connected to the ADID listener and its peer/message callbacks. It prepares shared and private persistent contexts, transfers opaque record bytes, queries the VMM indicator, installs a SIGTERM event source, creates the XPC listener and reaches `CFRunLoopRun`. Source-created blocks then reach the previously recovered request/error-response path in a linked private experiment.

The fuller startup state also advances the normal-environment request beyond the unresolved read in the [preceding receiver report](adid_receiver_report.md). Actual native service/port identity, record grammar, successful operation semantics and complete ownership/concurrency remain unknown. The broad investigation remains active.

## Identity, assumptions and provenance

Addresses are original preferred virtual addresses in provider arm64e SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`, base `0x100000000`. The [receiver report](adid_receiver_report.md) pins the universal executable and prior pointer-format analysis. Native target, loader, host IPC, signal, environment, synchronization and target-file APIs were not executed. Original reference files and SDK headers were read; analyst code was compiled and bounded original code ran in private Unicorn memory.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| S1: the pinned original and declarations define the reference objects | Every address, interface and symbol | Fresh source/instruction/chain/static-tool/SDK/account readbacks agree. Native executable selection and effective credentials remain unknown. |
| S2: the declared API, PAC, vector, lock and entropy fixtures permit these continuations | Startup and teardown paths | Initial opaque boundaries remain retained. A separate uninterrupted source run agrees with the checkpoint join, including final mutable memory and registers. Native PAC, scheduling, allocation and API implementations remain unverified. |
| S3: private filesystem metadata and explicit API statuses describe the stated cases | Context preparation and byte transfer | Sizes 0/16/31/257, descriptor 0, metadata boundaries, short/error writes, truncate and unlink failures are separated. The model tracks selected metadata, bytes and descriptor ownership; it is not a native filesystem implementation or a complete record parser. |
| S4: the captured local control prefix applies to the recovered predicates | Signed open result, write-count edge and VMM byte | Original operands/constants/branch pointers are checked. Full 32-bit and 64-bit-domain SMT obligations are local; other allocation/control states and large-file reachability remain open. |
| S5: opaque CF/XPC references and the explicit private block copy represent their stated roles | Listener/peer/request linkage | Original block descriptors specify 40 bytes. Captures and copied bytes are checked. Native block copying, retention, port rights, namespace identity and real peer delivery remain unknown. |
| S6: injected kevent records represent the stated callback inputs | SIGTERM consumer and loop-stop requests | Empty/error/other-ident/SIGTERM cases and two VMM outcomes differ as recorded. Native signal delivery, kernel event generation, races and reentrancy remain unobserved. |
| S7: comparing the two retained initialization states isolates the stated private context dependency | Earlier unresolved read versus later persistence boundary | Matching request arguments and instruction models reproduce the early unresolved read and advance the later case to a concrete `lstat`. Native startup success and all request prerequisites are not inferred. |
| S8: installed account/launchd declarations are configuration evidence | Provider UID/home context | `/etc/passwd` declares `_fpsd` as UID/GID 265, home `/var/db/fpsd`; launchd names that account. No live credential query or process identity match was performed. |

Evidence: [contracts and proofs](triage_evidence/adid_startup_contracts.json), [private profiles](triage_evidence/adid_startup_profiles.json), [pre-UID checkpoint](triage_evidence/adid_startup_checkpoint.json), [listener checkpoint](triage_evidence/adid_listener_checkpoint.json), [peer checkpoint](triage_evidence/adid_peer_checkpoint.json), [account declaration](triage_evidence/adid_provider_account.json), [checks](triage_evidence/adid_startup_checks.json) and [quality gates](triage_evidence/adid_startup_quality_gates.json). Compressed streams retain all source visits/events and their ordered-byte digests.

## Startup and persistent context flow [S1-S4,S8]

```text
original main 0x100011180
  -> arena/state initialization -> getuid 0x100014374
  -> /Users/Shared/adi and shared adi.pb
     -> read opaque N bytes -> close
  -> /var/db/fpsd/adi and private adi.pb
     -> open -> ftruncate(N) -> write(N) -> close
  -> conditional unlink(shared adi.pb) -> context cleanup
  -> kern.hv_vmm_present -> query-result byte 9 or 10
  -> event source -> XPC listener -> CFRunLoopRun
```

Controlled UID results 0, 265 and 501 all reach the initial directory query for `/Users/Shared/adi`. This finite prefix observation does not establish equivalence of all later UID effects. The account declaration is independently pinned; its home prefix also appears in the private context path.

The selected directory-preparation cases request `chmod(...,0777)`, CF file-security mode 0777 and hidden-resource updates. The source also queries backup exclusion and requests exclusion with `exclude=1`, `excludeByPath=0`. SDK declarations establish that `CSBackupIsItemExcluded` returns a Boolean and has one optional output pointer; the observed call supplies NULL for that pointer. Successful metadata API outcomes are explicit fixture inputs.

Other retained CF resource calls use `kCFURLTypeIdentifierKey` and the imported `kUTTypePlainText` object. Neither the `.pb` suffix nor that metadata establishes the record's serialization grammar. The transfer experiments treat its bytes as opaque.

| Operation | Original callsite | Recovered arguments / local behavior |
| --- | --- | --- |
| Shared record open | `0x100014e04` | `/Users/Shared/adi/adi.pb`, flags `0x110` = `O_RDONLY | O_SHLOCK | O_NOFOLLOW` |
| Read-open predicate | `0x100014e14` | Signed W0 compared against zero in the retained prefix; descriptor zero reaches `fstat` |
| Source `fstat` | `0x10001511c` | Descriptor and 144-byte stat result; 64-bit `st_size` is supplied at offset 96 |
| Source read | `0x100015768` | Caller-owned buffer and N-byte request |
| Source close | `0x100015d24` | Observed before destination open |
| Destination open | `0x100016bd0` | `/var/db/fpsd/adi/adi.pb`, flags `0x321` = `O_WRONLY | O_EXLOCK | O_NOFOLLOW | O_CREAT` |
| Destination mode | Same call | Low 32 bits of the first variadic stack slot are `0666`; X2 is not assigned this role |
| Set destination extent | `0x100016cf4` | `ftruncate(fd,N)`; N is the copied extent, including zero for the empty case |
| Destination write | `0x100016d84` | Exactly the retained source bytes in the 0/16/31/257-byte cases |
| Write-count comparison | `0x100016d8c` | `CMP X0,X25`; 64-bit returned count versus requested count |
| Destination close | `0x1000174fc` | Observed before source unlink |
| Source unlink request | `0x100017e74` | Shared record path; occurs in the full-count cases |

The source bytes and destination write bytes agree exactly in all four size cases. These are private transfer observations; valid production record contents, all metadata predicates, advisory-lock behavior, durability, replacement races and native filesystem effects remain unknown.

| Controlled outcome, N=31 bytes | Observed continuation |
| --- | --- |
| Full write, truncate success | Destination close, shared unlink request and later listener setup |
| Short write, result 15 | No shared unlink request; fully continued case returns W0=`0xffffffff` before listener creation |
| Write result -1 | No shared unlink request in the retained prefix |
| Truncate result -1 | No shared unlink request in the retained prefix |
| Unlink result -1 | Distinct retained error continuation; no successful namespace removal is modeled |

The encoded write branch uses fixed-prefix indices `0x2734` for equality and `0x2447` otherwise, resolving through original authenticated chain members to `0x100016dbc` and `0x10001722c`. The local SMT proof covers both 64-bit count operands. As an arithmetic illustration, a request of 4294967327 bytes and return of 31 bytes have equal low 32 bits but fail the source 64-bit equality. This is not a demonstrated large-file execution.

## VMM query-result byte [S1,S2,S4]

Original helper `0x10002ba5c` calls `sysctlbyname` at `0x10002bd94` with constructed name `kern.hv_vmm_present` and a four-byte result extent. At `0x10002bdac`, it writes a byte at its record pointer +4:

```text
byte = 10  iff  query_status == 0 AND result_u32 == 1
byte = 9   otherwise
```

The complete source helper and a full-domain proof are retained. Cases with values 0, 1, 2 and a query error reach kqueue setup. The value-1 case takes a shorter internal initialization path; values 0/2 and the error case follow the other retained path. The result is not classified as a blanket startup refusal. Meanings of similarly numbered fields in other service namespaces remain separate.

## Event source and XPC listener [S1,S2,S5,S6]

```text
kqueue
  <- SIGTERM registration: ident 15, EVFILT_SIGNAL -6, flags 5
  -> CFFileDescriptor(closeOnInvalidate=1, callback=0x100045bdc)
  -> read callback enabled -> CF source -> common run-loop modes

com.apple.adid, main dispatch queue, listener flag 1
  -> activate
  -> source-created block 0x1000009f8 [capture: main queue]
     -> peer target queue -> source-created block 0x100029fc8
        [capture: peer]
        -> original request/audit/data adapter -> reply data -> send
```

| Interface | Original site / observed contract |
| --- | --- |
| Create kqueue | `0x10001a0c4` |
| BSD handler request | `0x10001a1f4`; `signal(SIGTERM,SIG_IGN)` |
| Register signal event | `0x10001a298`; one 32-byte kevent: ident 15, filter -6, flags `EV_ADD | EV_ENABLE` = 5, zero remaining fields |
| CF descriptor wrapper | `0x10001a464`; callback `0x100045bdc`, close-on-invalidate true, context NULL |
| Enable read callback | `0x10001a504`; callback mask 1 |
| Create CF source | `0x10001a55c`; order zero |
| Add source | `0x10001a654`; imported `kCFRunLoopCommonModes` |
| Create listener | `0x10001a7b4`; `com.apple.adid`, normalized imported main-dispatch-queue object, flag 1 |
| Install listener block | `0x10001a930`; invoke `0x1000009f8`, captured queue at +32 |
| Activate listener | `0x10001a980` |
| Enter run loop | `0x10001aa10`; `CFRunLoopRun` boundary |

Both generated block descriptors specify 40 bytes. The linked experiment feeds main's generated listener block into original peer setup, checks the queue argument, captures the generated peer block, explicitly copies its 40 bytes into private fixture storage and invokes the original message handler. That copy is an analysis fixture, not a native block-lifetime proof.

The linked request reaches the original adapter and produces `data = ff ff 4f f2`, sent at `0x1000aaa70`, consistent with the [prior CoreFP error pairing](adid_receiver_report.md). Native listener creation, peer admission, Mach port names/objects/rights and underlying libxpc emission remain unobserved. Compatibility with the client's legacy 56-byte Mach-1200 request remains unknown.

## SIGTERM consumer and teardown [S2,S5,S6]

The original CF callback at `0x100045bdc` obtains the native descriptor and queries kevent. Empty and error results return after requesting callback re-enablement. An injected other identifier returns without a run-loop stop request. Injected SIGTERM cases query the VMM indicator, then reach:

| Request | Original site |
| --- | --- |
| Invalidate CF descriptor wrapper | `0x100048dd8` |
| Stop current run loop | `0x100048e68` |

Both tested VMM outcomes request those operations. Kernel signal production and actual CF event scheduling were not exercised.

A separate explicit `CFRunLoopRun`-return fixture continues main through wrapper release and two original `munmap` calls at `0x10001c4dc` and `0x10001c574`, each for 65536 bytes. The private emulator actually removes both owned mappings and the original main returns zero to the fixture. This establishes the local continuation under the modeled return. Full native CF/XPC retention, port destruction, close errors and concurrent callback lifetime remain open.

## Initialization-context discrimination [S2,S7]

The pre-UID checkpoint, with the same request arguments and vector model used for the later case, still reaches the unresolved read at `0x10010a050`, X21 zero. From the listener-setup checkpoint, the request instead reaches `lstat("/var/db/fpsd/adi")` at `0x10010b178` under the normal, NULL `__OSINSTALL_ENVIRONMENT` result.

This comparison shows the effect of the retained initialization state in the private experiments. The earlier unresolved read is not promoted to a native fault. The next persistence operations, successful selector behavior and the opaque X1 request field still require recovery.

## Validation and bounded continuation

The increment passes **52608 assertions** across **52 private cases**, three serialized checkpoints and three full-domain local SMT proofs. Fresh readback covers 22886 original instruction records, 22 compiler-bounded ranges and 2544799 retained original source visits. The uninterrupted replay takes 1013559 private hooks. The SDK/compiler readback passes. Original supplied inputs and IDBs remain preserved; these results do not complete the broad objective.

One fresh, uninterrupted private startup run agrees with the serialized prefix-plus-continuation instruction stream, every retained mutable memory region and every captured GPR/SIMD/control register at the listener boundary. This checks the checkpoint mechanism without relying solely on per-region hashes. It remains execution under explicit API/PAC models.

The [SDK model](triage_evidence/adid_startup_layouts.c) and [compiler output](triage_evidence/adid_startup_layouts.s) verify stat offsets/widths, signal-event layout/constants, listener flag, backup API signatures and Darwin variadic open-mode placement. Three local SMT obligations cover the VMM byte, signed32 open result and encoded full64 write-count edge.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_startup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_startup.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_startup_delivery.py
```

Readback is O(B+F+R+V) time/space for image bytes B, fixups F, retained code R and source visits V. Checkpoint continuations retain their declared hook bounds; the uninterrupted replay has a 2000000-hook cap. SMT cost is separate, with 30 s/query limits. Counts and byte extents are exact; no native timing or performance measurement is asserted.

| Impact | Further discriminating evidence |
| --- | --- |
| High | Recover successful request/persistence semantics after the fuller initialization state, all six selectors and actual caller provenance for the opaque 64-bit field. |
| High | Establish native endpoint/peer/credential identity, underlying libxpc Mach transport and legacy fallback compatibility. |
| High | Complete record grammar, metadata/errno predicates, partial read/write/close behavior, replacement and crash/durability boundaries. |
| Medium | Recover native CF descriptor/block/XPC ownership, signal-event kernel production, reentry and concurrent shutdown/port retirement. |
| Medium | Connect the remaining protected persistence/context routines to actual IOKit provider names, user-client selectors and deeper facilities. |

QG1-QG7 apply to these stated claims and assumptions. The full daemon/kext/deeper-interface objective remains active and incomplete.
