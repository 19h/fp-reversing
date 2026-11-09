# FairPlay XPC data, copy widths, and initial record boundary

The protected XPC handler reads dictionary key `data`, allocates using its 64-bit length, copies using the low 32 bits of that length, and reaches a parser requiring an initial 10 B header. Bytes 6-9 decode to a big-endian unsigned 32-bit extent; the first record passes the extent gate exactly when `10 + extent <= low32(length)`. These are conditional original-image semantics [DP1-DP5]. Native delivery, authorization, later command meanings, reply construction, and any connection from this parser to IOKit selector 26 remain unknown [DP6-DP7].

Primary evidence: [original-image capture](triage_evidence/daemon_xpc_payload_source.json), [instruction/SDK/scalar/model checks](triage_evidence/daemon_xpc_payload_checks.json), [capture script](triage_evidence/recover_daemon_xpc_payload.py), [validator](triage_evidence/validate_daemon_xpc_payload.py), [delivery preservation](triage_evidence/daemon_xpc_payload_delivery.json), and [quality gates](triage_evidence/daemon_xpc_payload_quality_gates.json). The pinned thin image is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The [listener/adapter report](daemon_xpc_listener_report.md) supplies the event/peer record, internal selector `0x77a0`, audit destination, and frame provenance. This increment uses sufficient local original-image references; no additional IDA query is required. IDA knowledge-store search remains unavailable in the exposed tools.

```text
event dictionary + separately saved peer / audit destination
  |
  +-- type/dictionary gate
  |
  +-- get_data(event, "data", &length64)
        |
        +-- malloc(length64) --> private copy pointer
              |
              +-- reverse copy of N = low32(length64) bytes
                    |
                    +-- encoded length64 + separate zeroed 16 B allocation
                          |
                          +-- initial N >= 10 gate
                                |
                                +-- BE32(copy[6..9]) + 10 <= N
                                      |
                                      +-- 0x100cc0944: later parsing frontier
```

## Exact call and data mappings

| Site / original slot | Resolved interface or role | Arguments / result |
|---|---|---|
| `0x100b092dc` / `0x1010a0890` | `_xpc_get_type`, modifier `0x365a` | Original event in X0; type returned in X0 |
| `0x100ad12bc` / `0x1010a0408` | `_xpc_dictionary_get_data`, modifier `0xbe7e` | X0 event, X1 `data` at `0x100e86130`, X2 SP+`0x390`; raw pointer returned in X0 |
| `0x100ba9a70` / `0x10109ff58` | `_malloc`, modifier `0x6aa4` | X0 is a full 64-bit load from SP+`0x390`; allocation result stored at SP+`0x820` |
| `0x100c6f154` / `0x10109ff58` | `_malloc`, modifier `0x6aa4` | W0=16 B; result stored at SP+`0x700`; success reaches a 16 B zero store |
| `0x1010aaea8` plus signed bias `0xfffffffff279fd69` | Original biased key pointer | Rebase target `0x10e6e63c7` normalizes to `0x100e86130`, bytes `64 61 74 61 00` |
| `0x1010a74c8` plus signed bias `0xffffffffc53e9a7d` | Paired original global reference | Normalizes to `0x1010c4cd8`, the prior classic-service header; downstream use here remains unknown |

The key pointer and paired global are stored at SP+`0x10` and SP+`0x18` in the entry prefix. All eight selected bank cases are constant over all 256 byte inputs. Both the bank pair/key and original pointer metadata are checked. In particular, the dictionary-type lookup uses **D key `0x78`**, addition `0x1253`, slot `0x1010ab100`; D key `0x54` selects a different object. Imported type-data addends cancel their separate code adjustments: error `0x256d84e2 + 0xffffffffda927b1e = 0 mod 2^64`; dictionary `0x63f36eae + 0xffffffff9c0c9152 = 0 mod 2^64`. These data pointers are type objects, not Mach names [DP2].

The local SDK declaration has result `const void *` and a `size_t *` length output. Its accompanying contract identifies the underlying data and returns NULL for an absent key or a value of another type. This distinguishes a retrieved raw pointer from a newly allocated buffer. Native dictionary mutation, backing storage and object lifetime are unknown. The SDK is local primary interface evidence, not proof of the running daemon's libxpc implementation or peer provenance [DP3,DP6].

## Conditional control and width contracts

| Gate / block | Selected condition | Original target / index |
|---|---|---|
| Core type gate `0x100b09274` | Type is error | `0x100a15240` / `0xcb2f`; separate unanalysed error continuation |
| Same | Type is not error | `0x100b07a54` / `0xcb34` |
| Dictionary gate `0x100b07a54` | Dictionary / other type | `0x100ad1240` / `0xc762`; `0x100b12c30` / `0xa25b` |
| Getter result | Non-NULL / NULL | `0x100ba9a14` / `0xb897`; `0x100b12c30` / `0xb8c2` |
| Data allocation result | Non-NULL / NULL | `0x100a68d94` / `0xb615`; `0x100b12c30` / `0xb66d` |
| Copy gate `0x100a68d94` | N is nonzero / zero | `0x100a80f48` / `0xbf7c`; `0x100aa5588` / `0xbf79` |
| Initial record allocation | Non-NULL / NULL | `0x100c032dc` / `0xb21e`; `0x100c4dc4c` / `0xb1f9` |
| Minimum at `0x100ba9504` | Initial N >= 10 / N < 10 | `0x100a6c060` / `0x2eba`; `0x100bd9558` / `0x2edb` |
| Extent at `0x100a6c118` | Initial `10 + extent <= N` / exceeds | `0x100cc0944` / `0x6aaa`; `0x100bd9558` / `0x6a6b` |

All 31 retained branch bindings include original slot words and matching authentication modifiers. These bind the selected continuations under their local frame assumptions; they do not prove the whole application's CFG or successful hardware authentication [DP2,DP4]. `0x100b12c30` and `0x100bd9558` are continuation frontiers. Their names in this report do not assert a final return, complete cleanup, resource release, or reply status.

Let L be the unsigned 64-bit getter length in B, N=low32(L), and M=malloc(L). Allocation reads L; copy arithmetic reduces exactly to N:

```text
r = N - ((2*N) AND 0x98d8f669)       [mod 2^32]
r == 0  <=>  N == 0
((r + 0x4c6c7b34) mod 2^32) XOR 0x4c6c7b34 == N
```

For N>0, the copy first transfers N mod 8 bytes at descending offsets N-1 through N-(N mod 8), then transfers floor(N/8) groups of eight bytes in descending offset order. The group body is `0x100a35fb8`; all accesses are byte loads/stores, not an 8 B load/store. Its obfuscated third offset reduces to -3. The complete selected copy covers each offset `[0,N)` once under DP3-DP4. For N=0 it skips these loads/stores. The joining blocks `0x100c09f90` and `0x100aa5588` recover the original L from SP+`0x390` and store `L XOR 0x0753df66dd8ff1b7` at SP+`0x498` [DP5].

| Quantity | Width and unit | Consequence within this scope |
|---|---|---|
| Getter length / data allocation | Unsigned 64 bits, B | Full L reaches malloc |
| Copy extent / initial parser extent | Unsigned 32 bits, B; then zero-extended | N reaches the copy and initial remaining-extent comparison |
| Stored encoded length | 64 bits | Encodes L, not N |
| Separate allocation | 16 B | Zeroed on success; semantic structure and full ownership unknown |
| Initial record length at offsets 6-9 | Big-endian unsigned 32 bits, B | Added to 10 in 64-bit arithmetic before unsigned comparison with N |

The six scalar proofs quantify all declared bit patterns, including lengths whose upper 32 bits are nonzero. They prove N<=L arithmetically. They do not prove malloc success, accessible storage, valid XPC delivery, accepted command sizes, or any later relationship between full L and N. For L=0, malloc(0) remains implementation dependent; both allocation-result branches are retained. An L with N=0 reaches the initial empty-result frontier only if both relevant allocations succeed; it is not assigned an application meaning [DP3-DP6].

The following is a partial semantic summary, ending at named frontiers rather than inventing return behavior:

```text
raw = xpc_dictionary_get_data(event, "data", &L)
if raw == NULL: goto 0x100b12c30
M = malloc(L)
if M == NULL: goto 0x100b12c30
N = low32(L)
copy M[i] = raw[i] for i = N-1 down to 0
save encoded(L), M
Q = malloc(16)
if Q == NULL: goto 0x100c4dc4c
zero Q[0..16)
cursor = 0
if N == 0: goto 0x100c8f210
if N < 10: goto 0x100bd9558
extent = BE32(M[6..10))
if uint64(extent) + 10 > uint64(N): goto 0x100bd9558
goto 0x100cc0944
```

The length-decoding instructions are retained at `0x100a6c0a4..0x100a6c114`. Their arithmetic/Boolean combination reduces to the four-byte BE32 value for every possible byte tuple; no magic value, opcode, authenticated field, version, or content interpretation is assigned. The selected fit target begins further parsing of bytes 0-5; its complete semantics and subsequent iterations are outside this increment [DP4-DP6].

## Ports, peer identity, and cross-level boundary

This increment establishes an incoming XPC object and a data field at the existing logical `com.apple.fairplayd.xpc` listener. None of the four newly resolved calls is a Mach send, receive, port extraction, or right transfer. No native Mach name, destination port, descriptor, send disposition, or reply emission is established by this parser prefix. Lower libxpc transport and the previously saved peer/audit destination remain separate evidence layers. The getter at `0x100b27ea8` acquires audit data into SP+`0x3c4`; no downstream authorization use is proved here. The native endpoint observations in the preceding reports are preserved without refresh [DP6-DP7].

The next static frontier is `0x100cc0944` for the first fitting record, followed by record iteration, any tag/command dispatch, consumers of the saved peer/audit token, and reply/cleanup joins. A daemon-to-kext association requires an actual data/control path from those consumers into the already recovered UserClient interface. Shared naming or being in the protected function is insufficient evidence of that association.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| DP1 | Pinned original thin image and preserved listener evidence delimit all addresses and inherited frame meanings. | Rehash originals and dependencies; recapture every retained byte; independently compare current dyld_info fixups. Require loaded-image/epoch evidence for native attribution. |
| DP2 | Original bank/table values, pointer records, import addends and ABI preservation hold. Call and continuation reductions depend on this. | Exhaust 256 inputs per bank; verify original words, exact imports and modifiers; reject a wrong dictionary key or modifier. Hardware PAC remains untested. |
| DP3 | Valid dictionary storage, successful malloc results, disjoint allocations and stable source bytes support copy semantics. | Follow object mutation, aliases, retention, allocation and cleanup before asserting native lifetime. Rejected evidence controls do not execute target inputs. |
| DP4 | The selected dictionary path enters with the listener report's record/selector and frame slots; unmodelled calls do not alter preserved state. Initial cursor is zero. | Recover all predecessors, writes and aliases; follow later cursor updates separately. No later-iteration or whole-CFG result is inferred from the initial cursor. |
| DP5 | Recorded AArch64 W/X widths, modulo arithmetic, unsigned comparisons and byte-address units match the source. Copy and extent formulas depend on them. | Instruction match, SDK compile and six bit-vector proofs; reject width/endian changes. Keep full L, low32 N and encoded L separate. |
| DP6 | API declarations supply interface meaning; application commands, admitted caller, token contents, policy use and reply behavior are unknown. | Follow bytes 0-5 and fitted-record consumers, peer/audit reads, reply creation/send and cleanup before assigning protocol or authorization meaning. |
| DP7 | Prior trace, kext contracts and native endpoint snapshots retain their stated scopes; no new exchange or memory-store recall is established. | Preserve prior hashes/inputs; do not identify task-relative names or kext requests from logical service names or this local parser alone. |

## Bounded additional context

| Impact | Pattern / consequence | Evidence boundary |
|---|---|---|
| High | Allocation, copy and stored length use different width domains. | Static ABI fact only; native size admission and downstream use remain unknown. |
| High | The initial inner record has a 10 B boundary and a BE32 extent at +6. | Wire schema, fields +0..+5, command semantics and later iteration remain unknown. |
| High | Audit/peer acquisition precedes parsing, without an established policy consumer. | Acquisition does not establish authorization or caller identity. |
| Medium | Data allocation/copy and the separate 16 B allocation precede the initial header gate. | Ordering is established; native allocation behavior and complete ownership are not. |
| Low | The key's paired biased global points to the known classic-service header. | This is an architectural touch point, not proof that the current XPC event traverses a classic Mach service. |

## Verification and quality gates

The capture retains 21 fragments, 884 instructions/3536 B, eight bank cases/2048 inputs, four resolved calls, 31 branch bindings, five imports and 34 selected pointers. Independent current dyld_info output matches all 61737 fixup memberships and every selected line. Checks pass 68 selected instruction assertions, eight SDK assertions/one compilation, six unsatisfiable scalar queries, 133 finite copy models, and eight rejected evidence alterations. Controls modify evidence only. No recovered code executes or is emulated, no target IPC is sent, and no IDB or native service state is mutated.

Capture/verification is O(B+F+I+256K) time/space for image bytes B, fixups F, instructions I and bank cases K. Solver and SDK compilation costs are separate; scalar queries each have a 10 s timeout. The recovered copy is Theta(N) time, O(1) auxiliary scalar space and N copied B, with an allocation request of L B plus the later 16 B allocation. Memory validity and allocator overhead are outside that bound. Copy-loop coverage follows the quotient/remainder induction: N=(N mod 8)+8*floor(N/8), disjoint descending tail/group intervals, and termination by a nonnegative counter decreasing by eight. The finite models are corroboration, not a substitute for that argument. Publication/audit is O(total artifact bytes + local links).

QG1: Factual interface and control/data-flow analysis requires no normative premise.

QG2: DP1-DP7 identify assumptions, dependent findings and falsification probes.

QG3: This increment covers the dictionary field, allocation/copy/store widths, first record gate, local branches and the absence of an established port emission within those calls. The larger interface investigation remains active.

QG4: Widths, B extents, initial unsigned bound, BE32 construction and complexity are explicit and checked.

QG5: Full allocation length, copy count, encoded length, initial/later cursor, cleanup frontier/final return, type objects/Mach names and audit acquisition/authorization remain distinct. malloc(0), high length bits and failed allocation branches are retained.

QG6: Original bytes, exact imports, original pointer metadata, independently refreshed fixups, pinned SDK/tool hashes and retained proof queries supply provenance. Native effects and unavailable knowledge-store recall are not fabricated.

QG7: Impact-labeled width, record, audit/peer, allocation-order and global-reference observations are bounded above. No successful daemon/kext exchange or complete-goal claim is made.
