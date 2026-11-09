# Original run-loop receive-to-source-to-daemon composition

The complete original `___CFRunLoopRun` body supplies the previously separate
receive-helper and source-dispatch calls in four private CPU executions. Its
own prologue allocates the receive buffer; its original instructions consume
the returned local port name, perform source lookup, and pass the buffer and
inline size to `DoSource1`, the CFMachPort callback and the daemon. There is no
internal caller-frame or program-counter reset between receive and dispatch.
Runtime helpers and dictionary membership remain declared contracts. [RH1-RH8]

Both RPC700 cases return from the original run loop with raw result4 after
source-handled=true and a null generic reply. This result does not establish
that the daemon recognized or processed RPC700: its prior unrecognized path
remains unchanged. Both RPC502 cases reach the original application/libbsm path
and stop before `_pthread_self`; subsequent processing and return are unknown.
Native source registration, port-set membership and the complete FairPlay
transaction remain unknown. The broader investigation remains active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RH1 | Pinned original cache/kernel/daemon snapshots form the selected corpus | Addresses, source identities and composition | Recapture complete functions, nlists, fixups and nine full cache hashes; independently attest actual loaded-image pairing |
| RH2 | The original leaf voucher initializer is invoked before this run-loop call | Installed original dispatch hooks | Check all11 installer instructions, root publication and complete unchanged CPU/RAM handoff except declared public arguments; native parent startup and later writers remain unknown |
| RH3 | Public run-loop inputs select non-main, no-deadline, stop-after-handled operation without pending source0/blocks | Observed original caller route and termination | Check duration bits, arguments, mode/stop fields and every modeled helper result; finite deadlines, pending work, timers and main-thread paths are outside these four cases |
| RH4 | Declared mode dictionary maps the returned local port to the declared source | Source identity and callback selection | Check original mode+0x80 load, exact returned live-name key, lookup result and original source call; recover actual dictionary insertion, source registration and port-set construction separately |
| RH5 | Fresh original-kernel delivery and explicit Mach return transfer apply to this buffer/context | Exact received message and OOL bytes | Freshly replay all four kernel cases; check seven Mach arguments,148+29 transferred bytes, before-images and full3072-byte receive capacity; native task/map/trap pairing remains unknown |
| RH6 | Prior CF object, primitive, stack, allocation and library-binding contracts apply | CF/daemon/application continuation | Independently check every model frame, exact original instruction suffix, records and memory journals; execute lower primitives and attest object/runtime epochs separately |
| RH7 | Logical chained fixups and authentication model private source transfer | Cache stubs/callbacks/returns | Recheck original pointers/words and all logical transfers; hardware PAC, native ASLR, concurrency and TSD effects remain unknown |
| RH8 | Run-loop return and the pre-pthread boundary delimit the observation | Result, cleanup and reply scope | Verify full final memory and exact boundary; continue actual thread/environment/output/disposal paths before claiming successful FairPlay processing or a completed round trip |

## Primary source and execution boundary

[Source capture](triage_evidence/cf_runloop_handoff_source.json) contains18
complete cache functions and eight original16-byte import stubs,1722 captured
instructions in total. The run-loop body is677 instructions at preferred,
unslid addresses0x184756e7c..0x184757910 (exclusive end), with exact original
nlist `___CFRunLoopRun`. Nine cache files are hashed in full. The original
daemon ranges, selected libbsm body, CF receive/source/perform bodies, dispatch
installer/hooks and libkernel voucher wrappers retain their source provenance.
The preceding [dispatch-hook report](dispatch_voucher_hooks_report.md) records
the table and static parent route. [RH1,RH2,RH7]

Two additional original libobjc bodies include `_objc_release` at0x18040bbec
and its shared return island at0x18040bbdc. The latter lies inside the preceding
captured function. The RPC700 cleanup executes the original null-release path
through that island. A function-entry-only whitelist would omit this edge.

[Profiles](triage_evidence/cf_runloop_handoff_profiles.json) retain four kernel
producers and four continuous installer/run-loop/receive/source/daemon runs.
[Independent checks](triage_evidence/cf_runloop_handoff_checks.json) recapture
source and replay original instructions, ordered reads/writes, CPU/ABI frames,
model before/after states and final private memory. No native daemon, Mach IPC,
run loop, TSD, allocator, thread API or hardware authentication executes here.
No original binary, trace or IDB is modified. [RH1-RH8]

```text
original voucher leaf installer -> original root/table store
  explicit public run-loop call setup
  -> original ___CFRunLoopRun prologue
     -> original receive helper / libkernel / dispatch voucher callbacks
        <- exact original-kernel USER148 + OOL29 return contract
     -> original live-name / mode-dictionary lookup call
        <- declared source membership
     -> original DoSource1 -> perform -> daemon callback
        +-- RPC502 -> MIG stub -> application -> libbsm -> pre-pthread stop
        `-- RPC700 -> unrecognized -> null generic reply
                    -> original source-handled path -> run-loop result4
```

## Caller frame and ABI

Let E be the run-loop entry stack pointer, S its local stack pointer and U its
receive buffer. All offsets below are bytes. The original prologue saves112
bytes and allocates3296 bytes: E-S=112+3296=3408 (0xd50). Its native receive
buffer is U=S+208 (0xd0). The fixture chooses E=0x6500001c80, therefore
S=0x6500000f30 and U=0x6500001000. These addresses align the original buffer with
the selected kernel-return contract; they are private fixture addresses.
[RH3,RH5,RH6]

| Original call / observation | Address | Checked ABI or state |
| --- | --- | --- |
| Run-loop entry | 0x184756e7c | X0=runloop, X1=mode, X2=1, D0=positive infinity |
| Receive-helper call | 0x18475730c | X0=mode receive facility, X1=S+0x68, X2=S+0x64, X3=0xffffffff, X4=S+0x78, X5=S+0x70 |
| Receive-helper return | 0x184757310 | X0=1; buffer pointer at S+0x68; live name at S+0x64; voucher state=-1; copied voucher=NULL |
| Source dictionary call | 0x1847576f4 | X0=*(mode+0x80), X1=returned live local name |
| Source dispatch call | 0x184757718 | X0=runloop, X1=mode, X2=source, X3=U, W4=*(U+4)=80, X5=S+0x50 |
| Original daemon callback | 0x100425f78 | X0=CF object, X1=U, X2=80, X3=NULL |
| Generic reply load | 0x184757720 | Load S+0x50; NULL in returning RPC700 cases |
| Generic Mach send site | 0x184757744 | Captured source; not visited in these cases |
| Stack-buffer disposal test | 0x1847577b0 | Returned buffer pointer equals U; heap-buffer free branch skipped in RPC700 |

The Mach entry is0x180547f94. Checked arguments are U, options0x07000806,
send size0 bytes, receive capacity3072 bytes, receive facility0x303 or0x403,
timeout0xffffffff and notify name0. These facility values are declared fixture
names. Native port-set construction, membership and effective namespace identity
are not established by assigning mode+0x88. The returned local name used as
the dictionary key is recovered from original message/receive processing.
[RH4,RH5]

Kernel return supplies148 bytes (80-byte inline message plus68-byte trailer)
and29 OOL bytes. Original dispatch adoption normalizes header0x80111112 to
0x80001112 while voucher name stays0. All3072 receive-capacity bytes and the
complete16384-byte OOL observation region match their oracles. The larger
8192-byte user observation region also includes original caller-frame saves
starting at U+3072; those bytes are not message payload or kernel transfer.
Their final values are independently replayed, rather than compared to an
all-padding message oracle. [RH3,RH5-RH7]

## Runtime and control-flow premises

The run-loop public duration is positive infinity (binary64 bits
0x7ff0000000000000); the original no-finite-deadline branch executes. The clock
models return100 raw absolute-time ticks and0 seconds of CF absolute time.
The tick-to-second conversion is unknown and unused in this selected path.
No elapsed-time or native timeout claim follows. Helpers report a non-main
thread, no pending blocks and no source0 work. Original CASAL instructions
execute on a MAX-feature private ARM64 CPU; no native concurrency is modeled.
The CPU model is selected before any instruction. A pre-execution engine
transfer checks all copied mapping bytes; there is no mid-execution engine
replacement. [RH3,RH6,RH7]

The source route calls `__CFSetTSD` with key13, copied voucher NULL and destructor
pointer0x1855148ec. Original cell0x1e01c8830 and its exact nlist identify that
destructor as `_os_release`. It is not a recovered CFRelease callback. The
model returns prior NULL and performs no actual TSD mutation. RPC700 later
calls the same setter to restore that prior value; RPC502 stops before the
restore. This demonstrates original argument construction and control flow,
not native TSD ownership or voucher lifetime. [RH4,RH6,RH7]

Original instructions initialize S+0x50 to NULL before DoSource1. The original
perform callback and bridge retain the prior null-reply behavior on RPC700.
The caller reads the slot, skips its generic send, combines source-handled
state, restores the declared TSD value, recognizes its stack buffer and
executes original null ObjC release and the original return epilogue. With
stop-after-handled enabled, it sets result4. RPC700 therefore provides an
explicit example of source-handled status without daemon RPC recognition.
No reply emission or successful FairPlay output follows. [RH3,RH6,RH8]

## Verification and reproduction

| Cases | Kernel local name | Original composed visits per case | Observed boundary |
| --- | --- | ---: | --- |
| 0,1: RPC502 | 0x303 | 3485 | Before `_pthread_self`; no run-loop return observed |
| 2,3: RPC700 | 0x403 | 883 | Original run-loop return; X0=4, SP=E |

Four fresh kernel replays check10652 original visits. Four composed replays
check8736 original visits,1796 reads /9666 bytes,1100 writes /7654 bytes and392
complete CPU frames. The total across the two phases is19388 visits. Complete
final private memory comprises4*(1048576+2097152)=12582912 bytes; the additional
2097152-byte region per run contains the lower private stack. Its address is
recorded separately from the one-mebibyte private region. Four altered journals
(instruction word, receive patch, dictionary result and return status) are
rejected. Each original DoSource1/daemon/application instruction suffix matches
the preceding separate-source execution exactly despite the caller-frame shift.
[RH1,RH5-RH8]

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_runloop_handoff.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_runloop_handoff.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_runloop_handoff.py
```

Run from the extracted directory with the pinned source/cache files and existing
Unicorn/Capstone environment. Recovery writes source JSON; the probe writes
profiles; validation recaptures source and writes checks with
`all_checks_pass=true`. Algorithms use O(image+source visits+RAM+journals) time
and space, plus linear full-file hashing. The independent replayer imports
the frozen loader and prior replay machinery, without importing this increment's
probe. Shared loader/model premises remain explicit. [RH1,RH6,RH7]

## Bounded continuation

| Impact | Remaining question | Discriminating evidence |
| --- | --- | --- |
| High | Which daemon port and CF source actually coexist in one runtime epoch? | Recover source creation, dictionary insertion, mode port-set membership and task-local names from the same original initialization route |
| High | Does a recognized request complete processing and emit a matching reply? | Continue the original thread/environment/output path and correlate exact reply ID, right and payload with the kernel receiver |
| Medium | Which helper outcomes preserve this route? | Replace dictionary, TSD and CF helper models with their original implementations and source-produced state |
| Medium | What do alternate scheduling conditions change? | Recover original pending-work, timer, wakeup and finite-deadline paths with consistent clock and mode state |
| Low | Which additional shared islands evade function-entry inventories? | Audit original cross-function branches, retaining enclosing bodies and exact source provenance |

## Scoped quality gates

QG1: Descriptive source/ABI analysis; no normative premise is required.

QG2: RH1-RH8 identify assumptions, dependent claims and falsification probes.

QG3: This increment covers the original caller/receive/source/daemon link,
ports, data/control flow, helper boundaries and respective report updates.
The broad investigation and native round trip remain incomplete.

QG4: Sizes/offsets are bytes; clock ticks are not converted to seconds; exact
integer frame equations, visit totals and independent oracles reproduce.

QG5: Source-handled, daemon recognition, null generic reply, raw result4 and
successful FairPlay processing are distinct. RPC502 has no observed return.
Native registration and helper outcomes are explicit assumptions.

QG6: Exact original source, nlists, fixups, full cache hashes, kernel producers,
ordered journals and independent replay support the bounded claims.

QG7: High/medium/low continuation questions are bounded to missing source and
runtime provenance. No native interface, ownership or exploit claim follows.

[Preservation seal](triage_evidence/cf_runloop_handoff_delivery.json),
[quality gates](triage_evidence/cf_runloop_handoff_quality_gates.json) and
[current manifest](triage_evidence/interface_manifest.json) retain publication
provenance. The complete goal remains active.
