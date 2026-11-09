# FairPlay XPC record iteration, status selection, and linked lookup

The record helper's equality result reloads the saved end offset and re-enters parsing. After result publication, a selected outer control/status path starts a fixed encoded lookup query. Lookup traverses Q+0 and then node+0 links, compares an address-decoded buffer word, and writes either the first matching node or NULL to a local output slot. These connect the earlier parser/constructor contracts to a consumer; native processing, wire-command meaning, authorization, reply emission and daemon/kext interaction remain unknown [IL1-IL7].

Primary evidence: [capture](triage_evidence/daemon_xpc_iteration_source.json), [checks and queries](triage_evidence/daemon_xpc_iteration_checks.json), [capture script](triage_evidence/recover_daemon_xpc_iteration.py), [validator](triage_evidence/validate_daemon_xpc_iteration.py), [preservation](triage_evidence/daemon_xpc_iteration_delivery.json), and [quality gates](triage_evidence/daemon_xpc_iteration_quality_gates.json). The daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The [record report](daemon_xpc_records_report.md) and [payload report](daemon_xpc_payload_report.md) supply the inherited frame, copied input, record fields and allocations. Local original-image references are sufficient for this increment; no additional IDA read, target execution or knowledge-store recall is performed.

```text
fitted record -> constructor/helper -> W23 == 8b3dc651?
                        | no                   | yes
                        v                      v
                 failure frontier       cursor = saved end
                                               |
                                    parse next / result / short
                                               |
                                         publish Q
                                               |
                        selected control cell and status checks
                                               |
                              encoded query ff7657b9, Q
                                               |
                         link = Q+0, then candidate node+0
                             | NULL                  | non-NULL
                             v                       v
                         output NULL           buffer = node+24
                                                     |
                                             decode/compare word
                                                | other | equal
                                                v       v
                                             next link  output node
```

## Record-loop and result control

Let N be the zero-extended low32 copy extent in B, c the 64-bit cursor offset in B, P the current BE32 record extent in B, and e=c+10+P. The inherited source initializes c=0. The following local contracts are established under `c<=N`, preserved frame values and the original table bindings [IL2-IL5]:

| Site / block | Selected behavior | Target / index |
|---|---|---|
| `0x1009e1268` | W23 equals literal `0x8b3dc651` | `0x100bd6fd8` / `0xa101` |
| Same | Other W23 | `0x100bd9558` / `0x5c78` |
| `0x100bd6fe0` / `0x100bd6fe4` | Reload e from SP+`0x450`, encoded N from SP+`0x680` | `0x100b22fe4` / `0x2282` |
| `0x100b23018` | N>c | Nonempty/minimum path; N-c is the remaining extent |
| Same | N<=c | Result path; this means N=c only under the stated invariant |
| `0x100ba952c` | Remaining extent >9 B | Header/extent decode |
| Same | Remaining extent 1-9 B | Failure continuation `0x100bd9558` |
| `0x100a6c118` | Unsigned e<=N | Fitted-record continuation `0x100cc0944` |
| Same | e>N | Failure continuation |

The helper comparison constant reduces from `(0x77a0 XOR 0x77a2)*0x1141 XOR 0x8b3de4d3` to `0x8b3dc651`. The equality continuation restores N's encoded state and sets the loop's scalar entry values. It is an actual back edge through the saved end offset, not an inferred edge based on neighboring addresses. This does not prove the opaque constructor always returns that status or preserves every other frame slot [IL3-IL4].

For every declared N, P and c<=N, e cannot wrap 64 bits. A fitted e is strictly larger than c by at least 10 B and remains <=N. Conditional successful advances therefore preserve the cursor invariant and permit at most floor(N/10) such advances. At maximum N=`0xffffffff`, this bound is 429496729 advances. It excludes constructor cost, early results, failure continuations and unproved aliases. The variable discriminator's H=0 branch can select the result before another constructor/advance, as established in the preceding report.

The loop gate itself tests N>c; it does not separately reject c>N. Consequently its terminal branch cannot be described as a zero-remainder test without IL4. Likewise, restoring N and c does not establish that every scalar/pointer default is reset for a later record. The earlier first-record defaults remain first-record claims.

The inherited result path writes Q through the pointer at SP+`0x568`, then joins `0x100c4dc4c`. The selected subsequent path depends on W20=`0x44877a43` and control cell SP+`0x7b8`=`0x57de1c3e`. Original signed/unsigned comparisons and parity reductions lead through `0x100a61db0`, `0x100c8e248`, and `0x100aac57c` to `0x100a5b1b4`. These frame/control constants are not assigned to a wire field or application operation. Other control-cell cases are outside this reduction [IL4,IL6].

At `0x100a5b1dc`, W23=`0x8b3dc651` selects `0x100bb0184` / index `0x8dde`; other values select `0x100b12c30` / `0x77ae`. This distinguishes the result and failure predecessors of the previously shared continuation. It establishes an internal equality/control convention, not a public errno, XPC error, authorization result or native success.

## Fixed query and linked traversal

The selected setup at `0x100bb0184` passes the address of Q's local slot (SP+`0x898`), an output destination SP+`0x82c`, and exact encoded comparison word **`0xff7657b9`**. It reaches `0x100bb0aa8`, which loads Q, zeros temporary node output SP+`0x718`, saves the caller output pointer at SP+`0x2c0`, and saves a continuation at SP+`0x460`.

The search path saves the encoded query at SP+`0xa6c` and its node-output destination at SP+`0xa70`. The large setup `0x100a18fe4..0x100a19320` retains 207 instructions, including the table continuation saved at SP+`0x520`. These are flattened local interfaces using saved code pointers and branches; no ordinary external call ABI is asserted.

| Object / offset | Established consumer meaning | Remaining boundary |
|---|---|---|
| Q+0 | Initial link loaded at `0x100bb5ab4` | Q+8 remains unknown |
| Node+0 | Next link loaded by the same block after nonmatch | Insertion, cycle prevention and lifetime unknown |
| Node+16 | 32-bit buffer length read at `0x100bb00f8` | Full bounds/representation validation follows later |
| Node+24 | Buffer pointer loaded at `0x100b09100` and `0x100bb00f4` | Complete packing and ownership remain unknown |
| SP+`0xa78` | Saved current node | Restored for output/comparison continuation |
| SP+`0x718` | Local search output | First matching node, or NULL when the link chain ends |

At `0x100bb5a9c`, a link is read from X20+0, saved, tested, and the provisional result X20 is reset to NULL. A present node enters the candidate decoder. At `0x100c1c2d8`, the resulting 32-bit comparison word is compared to the saved encoded query. Equality restores the current node and selects `0x100cbae58`; nonmatch selects `0x100bde374`, which returns to the same link-load block with the current node in X20. Thus Q's head access and node-next access share code but have distinct object roles.

`0x100cbae58` writes X20 through the saved output pointer. A match yields the current node; an absent link yields NULL. The code scans in chain order and stops at the first equality. This establishes traversal semantics under valid object/link assumptions; finite-chain models do not prove the actual chain is acyclic or establish native object identity [IL3-IL4].

## Address-dependent candidate decoding

The candidate buffer is distinct from the raw copied input M. The [preceding constructor report](daemon_xpc_records_report.md) establishes a separate allocated buffer. Its complete writer/read correspondence remains unknown; the decoder output is therefore called D, not wire H [IL6].

The full decoder span is `0x100c9eefc..0x100c9f76c`, **540 instructions /2160 B**. A default 0x800 B block read would stop at 512 instructions before the actual terminator. The new capture uses a larger bound and requires a final branch for every fragment. The decoder itself makes four byte reads, a table-target load, no stores and no calls:

| Byte-read site | Effective address under selected entry contract | Value role |
|---|---|---|
| `0x100c9f134` | Buffer+0 | First byte combined with an address-derived mask byte |
| `0x100c9f198` | Buffer+1 | Second byte combined with a separate retained mask circuit |
| `0x100c9f514` | Buffer+2 | Third byte combined with its retained mask circuit |
| `0x100c9f720` | Buffer+3 | Fourth byte combined with its retained mask circuit |

The pointer bias `0x661a590b302baf96` cancels the first address constant `0x99e5a6f4cfd4506a`; successive constants add 1, 2 and 3. This is proved for every 64-bit buffer-address pattern modulo 2^64, without asserting mapping validity. The large preceding setup preserves X1, X10 and X16 in this selected path. Frame reads and complete alias effects remain IL3-IL4 dependencies.

Each mask circuit contains address arithmetic, alignment to an 8 B block, rotates, additions, Boolean operations and an address-selected byte extraction. These are syntactic data dependencies; the report does not identify a standardized cipher, prove all four circuits equivalent, or prove that changing an address changes the final output. No recovery of protected content or native read is performed.

Let q0..q3 denote the low byte of each stored byte XOR its respective mask. The final shifts/Boolean merge reduce to:

```text
U = (q0 << 24) OR (q1 << 16) OR (q2 << 8) OR q3
D = U XOR 0x8b3dc602
compare D with saved encoded query 0xff7657b9
```

The reduction of the final merge is proved over all 32-bit U values. The retained mask circuits remain opaque. In particular, XORing the query with the earlier scalar encoding constant does not establish a wire H value: that would require the actual constructor writer, address-dependent mask correspondence and matching value domains [IL5-IL6].

## Lookup result and next consumer

| Site / continuation | Established behavior | Frontier |
|---|---|---|
| `0x100c1c2fc` | A candidate comparison sets W23=`0x8b3dc651`; match exits, nonmatch continues | Native/public status interpretation unknown |
| Link absent in `0x100bb5a9c` | W23=`0x74c29ded`, X20=NULL reaches output | No public error-code assignment |
| `0x100bac8ec` | Search status equals `0x8b3dc651` selects `0x100bb00c0` | Found-node buffer/length reads |
| Same | Other status selects `0x100d30ab4` | Shared getter-return continuation |
| `0x100bb00c0` | Reads node from SP+`0x718`, buffer+24 and length+16 | Buffer-present target `0x100ca22c0` requires further validation |
| `0x100c45c98` | Branches through saved SP+`0x460` | Target `0x100c65c9c` under selected setup |
| `0x100c65ca4` | Loads W8 from local SP+`0x82c` | Table index `0x6043` -> `0x100d281ac`; extraction/dispatch meaning unknown |

The temporary node destination is initialized independently from the caller's value destination. A missing record is not assigned a newly decoded value at SP+`0x82c` by the paths analyzed here. Its full initialization, extraction and error handling require the later getter/control paths. Likewise, peer/audit provenance is not established by Q lookup.

No new external API call, Mach send/receive, descriptor, right transfer, XPC reply or IOKit emission occurs in the retained fragments. Local node outputs, saved continuations, Q, buffer pointers, Mach names and audit/peer values remain separate domains. Relevant next work is the constructor's buffer writer, full getter validation/extraction after `0x100ca22c0`, and consumers at `0x100d281ac`, before assigning actual commands or cross-level effects.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| IL1 | Pinned original daemon and preserved preceding captures define addresses and frame meaning. | Rehash originals/dependencies; recapture all fragments and inherited ranges; compare current independent fixups. Require native loaded-image/epoch evidence separately. |
| IL2 | Original table words, authentication metadata and branch state hold. | Verify 43 original branch bindings and modifiers; reject an altered modifier. Hardware PAC remains untested. |
| IL3 | Stack slots and Q/node/buffer objects are valid, live, disjoint where required and not changed by unmodelled aliases. | Recover writers, escaping aliases, insertion/destruction and ownership before assigning native validity or absence of cycles. |
| IL4 | Cursor c<=N, saved end/N slots and selected outer frame/control contract remain intact across helper work. | Prove all constructor writes/aliases; follow other SP+`0x7b8` cases. Do not describe N<=c as zero remainder or assume later-record default resets without this invariant. |
| IL5 | W/X widths, signed outer comparisons, unsigned extents and byte operations match source. | Instruction assertions, SDK compile, five scalar queries and bounded loop/chain models; reject cursor/offset/width/byte-address changes. |
| IL6 | The comparison word D, encoded query, internal status words and wire H are distinct until writer/read correspondence is proved. | Follow full packing/mask circuits and downstream getter/value consumers; reject inference of a wire command or public error from constants alone. |
| IL7 | Prior kext contracts, trace and native observations retain their stated scopes; knowledge-store search remains unavailable. | Preserve prior hashes; do not infer actual Mach identities, successful interaction, authorization or IOKit selector use from local lookup/iteration. |

## Bounded additional context

| Impact | Pattern / consequence | Remaining boundary |
|---|---|---|
| High | Parser completion feeds a fixed encoded linked lookup and a later local value destination. | Actual command meaning, accepted caller, extraction, dispatch and replies remain unknown. |
| High | Node+0 is now established as a traversal link; Q+0 is its initial link. | Full insertion/ownership, Q+8/node+8 and acyclicity are unknown. |
| High | Candidate buffer decoding uses address-fed masks, separate from raw wire parsing. | Mask equivalence, actual relocation behavior and writer/read correspondence are unproved. |
| Medium | Successful loop steps advance by >=10 B and preserve c<=N conditionally. | Unmodelled helper/alias writes can invalidate the premise; the gate itself accepts N<=c as terminal. |
| Medium | Default bounded block extraction omitted the decoder's final 28 instructions. | This increment captures the full span and requires a terminal branch; earlier published fragments remain independently scoped. |

## Verification and quality gates

Thirty-three fragments retain 1441 instructions/5764 B, 43 branch bindings and 40 selected pointer records. No new banks, imports or external call bindings are claimed. Independent current dyld_info output matches 61737 fixup memberships and every selected line. Checks pass 59 selected instruction assertions, nine SDK assertions/one compilation, five unsatisfiable scalar queries, 12870 loop cases, 511 finite-chain cases and eight rejected evidence alterations. Controls alter evidence only; no target code executes or is emulated, no native request is sent, and no IDB/service state changes.

Capture/verification is O(B+F+I+M) time/space for image bytes B, fixups F, retained instructions I and finite model cases M; the current lookup digest construction retains 511 abstract cases. Solver and SDK compilation costs are separate; each scalar query has a 10 s timeout. Conditional record iteration permits O(N/10) fitted advances, excluding unresolved constructor costs. Lookup takes O(k) node visits and O(1) scalar space for a finite acyclic chain of k nodes; no unconditional termination claim is made for arbitrary native links. The 540-instruction decoder is fixed-size local work per candidate; mask semantics remain bounded as stated. Publication/audit is O(total artifact bytes + local links). Extents use B throughout.

QG1: Factual control/data-flow and ABI analysis requires no normative premise.

QG2: IL1-IL7 identify dependent findings and falsification probes.

QG3: The selected loop back edge, result/status path, encoded query, linked traversal, candidate byte boundary and output/return continuations are covered; full interfaces remain under investigation.

QG4: Cursor/extents, >=10 B progress, signed/unsigned comparisons, pointer offsets, decoder span and merge widths are explicit and checked.

QG5: Conditional versus unconditional termination, N=c versus N<=c, first/later defaults, decoded D versus wire H, status literals versus public outcomes, and local outputs versus IPC remain distinct.

QG6: Original instructions, fresh independent fixups, exact saved/table targets, SDK/tool hashes and retained proofs/models provide provenance. Native identities, mask correspondence and unavailable recall are not fabricated.

QG7: Impact-labeled consumer, link, mask, cursor and extraction-scope observations are bounded above. No full-goal, complete native exchange, authorization or final command meaning is claimed.
