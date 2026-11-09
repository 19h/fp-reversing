# CF receive options, kernel voucher bits and original libkernel hook handling

Using CF's actual receive options0x07000806 and capacity3072 changes the
kernel-produced header from0x80001112 to0x80111112 in all four request fixtures.
The queued internal header already contains voucher-disposition byte0x11; the
CF receive configuration retains that byte even though the delivered voucher
name is0. All other observed user-message bytes and OOL bytes match the earlier
extended-trailer results. This qualifies the earlier explicit-input CF/daemon
composition with the actual CF receive configuration. [RV1-RV3]

Eight original CF receive executions consume those exact kernel results and
execute the original libkernel voucher wrappers. The file-default table and
a valid table published through the original initializer both have null
callbacks in these fixtures. Both leave the packet intact; adopt returns-1,
the copied-voucher output becomes null, and CF reports receive success. Four
downstream CF/daemon executions consume the corrected post-voucher buffers and
retain their original dispatch/record/reply behavior. [RV4-RV8]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RV1 | Pinned daemon/kernel/cache files are the selected corpus | Source addresses and component correspondence | Recapture source, original cache-pointer chains, five cache hashes and kernel instruction roles; attest native loaded pairing separately |
| RV2 | Prior source-produced loan/context and lower VM/hash/retirement contracts apply | Four original kernel receives | Compare complete initial records/overlays with frozen producer states and freshly replay each exact CF option/capacity case |
| RV3 | The userspace Mach-call return is supplied from the corresponding kernel C-entry result | Exact kernel-to-CF transfer | Check all API arguments, original status0, before/after bytes and copy extents; original Mach wrapper/trap and native task switching are not executed |
| RV4 | File-default and valid published null-callback tables describe only these cases | No-op voucher paths and intact post-voucher message | Recheck default48-byte table, original initializer stores and actual callback loads; capture real runtime initialization and nonnull hook implementations separately |
| RV5 | Original logical cache bindings and PAC substitutions apply | Import-stub and library control transfers | Verify four original v5 chains, exact exports and every opcode; native rebases/authentication remain unknown |
| RV6 | Post-receive buffers feed the separately invoked CF source/daemon component | Downstream composition | Compare complete bytes across the phase boundary and replay every downstream instruction; actual run-loop source selection/caller state remains unknown |
| RV7 | Prior CF runtime/object/helper and daemon malloc/stack/library premises apply | Original dispatch, application records and bounded returns | Reuse frozen source contracts, compare exact downstream traces and full outputs; recover native object/cache/environment epochs separately |
| RV8 | Receive-helper return, pthread entry and CF source return delimit the results | Output and ownership scope | Execute the remaining native caller/APIs and successful output/disposal paths before claiming complete service processing or a FairPlay reply |

## Primary source and observation scope

The selected cache UUID is2bd06591-e751-3e84-963f-b08dab6af23a. CF UUID is
7fe5392e-ff16-31e1-8552-3a45c6b68224; libsystem_kernel UUID is
f2bceb9a-0fec-3c92-b6ea-8e37157050a8. [Original kernel delivery](kernel_request_delivery_report.md)
and [CF/daemon composition](cf_daemon_request_report.md) retain the original
binary identities and predecessor evidence. All addresses below are preferred
unslid virtual addresses. Native pairing is not assumed. [RV1,RV5]

[Source capture](triage_evidence/cf_receive_voucher_source.json) contains four
complete cache functions and three original16-byte import stubs:133 instructions
in total, plus five exact kernel instruction roles. It retains the original
default table, four cache-pointer chains and five full cache-file hashes.
[Profiles](triage_evidence/cf_receive_voucher_profiles.json) contain four kernel
cases, eight receive/voucher cases and four downstream dispatch cases.
[Independent checks](triage_evidence/cf_receive_voucher_checks.json) recapture
sources and replay all three phases with independent packet/ABI/record oracles.
No IDB operation or native target/IPC/VM operation occurs.

```text
CF original receive helper
  -> original import stub -> mach_msg entry boundary
               |
               +-- explicit API/kernel/task-transfer contract
               |      original kernel receive at options07000806/capacity3072
               |      -> exact148-byte message/trailer +29 OOL bytes, status0
               |
  <- exact original kernel result
  -> original voucher-revert wrapper
  -> original voucher-adopt wrapper
  -> publish live name, state-1, copied voucherNULL; return true
               |
               +-- explicit separate run-loop caller/source-selection premise
               |
       original CF source/perform -> original daemon
           RPC502 -> application/libbsm -> pthread entry
           RPC700 -> CF generic replyNULL, source handled=true
```

These are component compositions. The Mach wrapper/trap, native task switch and
run-loop caller between receive-helper return and DoSource1 are not executed.
The latter phases use exact buffer equality rather than an invented complete
caller frame. Native table/endpoint selection and full round trip remain unknown.
[RV3,RV6,RV8]

## Actual receive ABI and kernel result

The original CF call at0x184758ac4 enters stub0x188076b60 and resolves through
the original v5 cell0x1e2103a58 to exact export `_mach_msg` at0x180547f94.
Execution stops at that export's entry for the explicit result transfer; its
body and syscall/trap are not executed. [RV3,RV5]

| Userspace Mach argument | Actual value in these cases |
| --- | --- |
| X0 buffer | 0x6500001000 |
| W1 options | 0x07000806 |
| W2 send size | 0 |
| W3 receive capacity | 3072 bytes |
| W4 receive name | 0x303 for502;0x403 for700 |
| W5 timeout | 0xffffffff |
| W6 notify | 0 |

These fixtures receive from the direct service name. Actual run-loop port-set
selection remains separate. The matching original kernel C entry uses its
separately recovered eight-register ABI with the same options, capacity and
receive name. Each of four executions returns0, publishes an80-byte inline
request and68-byte trailer, and copies148 bytes despite the3072-byte offered
capacity. OOL delivery remains29 bytes under the prior VM byte-copy contract.
[RV2,RV3]

| Field / configuration | Earlier explicit receive | Actual CF receive configuration |
| --- | --- | --- |
| Options | 0x07000002 | 0x07000806 |
| Capacity | 148 bytes | 3072 bytes |
| Final user header bits | 0x80001112 | 0x80111112 |
| Voucher name | 0 | 0 |
| Inline/trailer size | 80/68 bytes | 80/68 bytes |
| Copied inline/trailer extent | 148 bytes | 148 bytes |
| Other complete USER/OOL observations | Reference bytes | Identical except USER byte2:00 ->11 |

The queued internal header is0x80111211. Its voucher-disposition byte17 is
retained in the actual-CF configuration; remote/local header conversion produces
0x80111112. The receiver does not obtain a nonzero voucher name in these cases.
Original TBZ instructions at0xfffffe000bcc1430 and0xfffffe000bcda4bc inspect
W1 bit11, corresponding to0x800. The header construction ORR at
0xfffffe000bcc53a8 places the selected disposition at bit16; the original stores
at0xfffffe000bcc53c4 and0xfffffe000bcc6648 publish the header and packed user
representation. Exact words/operands are retained in the source artifact.
These observations concern the tested null-voucher messages, not all voucher
objects or failure routes. [RV2,RV3]

Before the Mach boundary, CF's own instructions prepare the receive buffer.
Independent before-image oracles ensure that the packet was not preseeded there.
The result contract then supplies exactly148 original kernel bytes and29 OOL
bytes. Remaining observation bytes retain their declaredA5 fixture pattern;
that pattern is not native VM/page-initialization evidence. [RV3]

## Voucher table ABI and original control flow

| Boundary | Exact target / source role |
| --- | --- |
| CF revert call0x184758ad0 | Stub0x188081380 -> `_voucher_mach_msg_revert`0x18054b32c |
| CF adopt call0x184758ad8 | Stub0x188081360 -> `_voucher_mach_msg_adopt`0x18054b344 |
| Hook-table root | Global0x1ed83e8d8; original default target0x18057d1a0 |
| Default table observation | 48 original zero bytes |
| Revert callback slot | Root target+0x20 |
| Adopt callback slot | Root target+0x18 |
| Initializer | Exact export `___libkernel_voucher_init`0x180548154..0x180548164 |

The revert wrapper loads its callback pointer and tail-branches through BRAAZ
when nonnull. With a null callback it returns without writing packet memory;
its residual X0 is not interpreted as a status. The adopt wrapper similarly
loads its callback, and with null callback returns all64 bits set. These wrappers
perform no native credential lookup on the executed paths. [RV4,RV5]

The initializer consists of ADRP, STR X0 to the root global, MOV W0=0 and RET.
It publishes the caller's table pointer directly; no table copy or local field
validation is present in those four instructions. The experiment passes a valid
private48-byte zero table. Its lifetime and runtime call context are explicit
premises; no malformed pointer/table experiment or native registration occurs.
[RV4]

| Table case | Cases | Receive/voucher visits per case | Established table behavior |
| --- | ---: | ---: | --- |
| Original file-default table | 4 | 93 | Original root points to original zero table |
| Valid null-callback replacement | 4 | 97 | Original initializer stores private table pointer and returns raw0; original wrappers read its null slots |

Each case calls revert with prior state0xffffffffffffffff, then adopt with the
received message pointer. With the tested null callbacks, adopt returns-1 and
CF stores that value through its voucher-state output. CF skips the voucher-copy
call and stores null through the optional copied-voucher output. The live-name
output receives the message's local receive name as a32-bit store; its adjacent
four guard bytes remainA5. CF returns Boolean1 after the kernel status0.
Kernel status0, CF Boolean1 and voucher state-1 have distinct roles. [RV3,RV4]

The actual runtime root may be replaced and its nonnull callbacks may implement
different semantics. Neither the file-default bytes nor these valid replacement
cases establish the daemon's native hook table or native voucher effects.

## Corrected post-voucher bytes at downstream dispatch

For each producer, the file-default post-receive buffer is passed unchanged to
the existing original CF DoSource1/perform/daemon/application executor. Both
table cases produce identical complete USER/OOL observations. The four executed
downstream cases use the file-default outputs; their source instruction
sequences and complete prepared replies match the preceding composition.
[RV6,RV7]

| Corrected request | Original downstream outcome |
| --- | --- |
| RPC502, header0x80111112 | Reaches original MIG/application/libbsm and stops before pthread identity; complete120-byte argument record unchanged |
| RPC700, header0x80111112 | Callback remains unrecognized; CF stores null generic reply and returns source-handled=true |

Thus the retained voucher-disposition byte does not change the observed local
dispatch or prepared reply in these cases. This does not establish native
identity, authorization, actual RPC700 endpoint or successful FairPlay processing.
The receive site above is receive-only; daemon reply emission at0x100035184
remains a downstream boundary. [RV7,RV8]

## Verification and bounded continuation

Fresh independent replay checks10652 kernel visits,760 CF receive/voucher
visits and7038 downstream visits. The eight receive/voucher cases check192
reads /1472 bytes,172 source writes /1184 bytes,60 complete CPU/record frames,
four original initializer-to-public-CF-call handoffs and8388608 final private-RAM
bytes. The Mach result contracts transfer1416 bytes total across repeated
cases. The kernel and downstream phases additionally check their whole private
states and original VM/object/ABI journals. Counts describe repeated private
observations, not native throughput or distinct native mapped memory.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_receive_voucher.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_receive_voucher.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_receive_voucher.py
```

Time is O(B+H+V+J+F), space O(B+R+J+F), for original source bytes B, streamed
cache hashes H, visits V, journals J, fixups F and private RAM R. All sizes,
capacities and offsets above are bytes; options/header fields are32-bit,
pointer/state fields64-bit. No exhaustive proof of runtime hook combinations
or full native protocol processing is claimed.

| Impact | Remaining requirement / opportunity | Completing evidence |
| --- | --- | --- |
| High | Actual initialized voucher root/callbacks | Original runtime installer callers, selected table identity, callback implementations and post-hook native buffers |
| High | Mach wrapper/trap/task coupling | Original libkernel wrapper/trap ABI and matching native kernel entry/state |
| High | Receive return to source selection | Original run-loop caller, direct-port/port-set identity and effective source/object/cache history |
| High | Successful application/reply lifecycle | Original downstream environment/output construction, initialized records, OOL rights and full reply consumption |
| Medium | Nonnull voucher behavior | Matching legitimate runtime hook implementations and their field/thread/ownership effects |
| Medium | RPC700 receiver | Actual slot34 publication and corresponding server remain unknown |

[Preservation](triage_evidence/cf_receive_voucher_delivery.json) and
[scoped quality gates](triage_evidence/cf_receive_voucher_quality_gates.json)
record baseline retention and reporting/index changes.

QG1: factual interface analysis. QG2: RV1-RV8 with dependent results and probes.
QG3: actual-CF receive configuration, original voucher paths and corrected-byte
downstream composition covered; full goal active. QG4: byte units,32/64-bit
domains, counts, copy geometry and complexity explicit. QG5: three status roles,
null voucher name versus disposition, file/default/runtime tables, separate
caller handoffs and native ownership remain distinct. QG6: original kernel/cache
bytes, five instruction roles, four chains, five cache hashes, three-phase fresh
replay and complete packet/record/status/before-image oracles. QG7: bounded
continuation table above.
