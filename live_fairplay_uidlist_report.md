# Installed FairPlay UIDList marker and context publication

Selected blocks of the installed FairPlayIOKit routine `_PRnut72j9` copy the u32 tunnel marker at +0x6c into the UIDList node field that teardown reads at +4 B. The new-node arm inserts a typed 16 B node at the head of the provider context. An independent u32 discriminator at node +0 B controls the list search. This closes the installed field mapping between insertion and cleanup under a stable tunnel and context epoch. Whole-path reachability from selector 26, native pointer identity, and daemon correlation remain unknown. [Tunnel insertion](live_fairplay_tunnel_report.md) [Current cleanup](live_fairplay_table_cleanup_report.md)

```text
selector 26 X2 -> saved context Q -> Q+0 (list head)
                                         |
P+0x6c -> marker M -> new node +4 B ------+
                   -> cleanup reads +4 B
                   -> M XOR 0x31ae0066 -> shared-table lookup
```

## Build and verification

The audit uses the original build `26C5035r` collection, SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, and matches kernel UUID `90195379-954d-3ca3-baac-327341f14211` and kext UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. The installed routine lies in `[0xfffffe000a676398, 0xfffffe000a6a7ac0)`. The audit compares 232 selected source instruction words and 12 terminal transfer words against the earlier proof inputs. Two changed words at `0xfffffe000a69f97c` and `0xfffffe000a69f980` reconstruct the relocated pool address `0xfffffe00084889a0`. It also checks 15 root instructions, 16 branch fixups and landing words, all 512 byte-bank inputs, and reruns 17 source and six predecessor SMT queries. The full function has an independent identity hash. [Historical publication proofs](userclient_uidlist_publication_report.md) [Installed audit receipt](triage_evidence/live_fairplay_uidlist_audit.json.zst)

## Context, marker, and discriminator

Let Q denote the context pointer from provider X2, C the scratch base, S the source and result base, P the candidate tunnel, M the u32 marker, K the u32 discriminator, and B the prospective new node. Register roles change across dispatcher phases.

| Installed site | Recovered transfer |
| --- | --- |
| `0xfffffe000a6763dc` | Save incoming Q at SP+0x738. |
| `0xfffffe000a69f630`–`0xfffffe000a69f634` | Copy candidate P from C+0x218 to C+0x4c8. |
| `0xfffffe000a69fedc`–`0xfffffe000a69fee0` | Load M from P+0x6c into W24 and store it at S+0xd8c. |
| `0xfffffe000a69fee4`–`0xfffffe000a69fef0` | Reload Q, save it at C+0x118, load Q+0, and store the head at C+0x410. |
| `0xfffffe000a69ff24`, `0xfffffe000a69ff54`–`0xfffffe000a69ff58` | Read K from S+0xc90 and compare it with the current node's u32 at +0 B. |
| `0xfffffe000a69ff98` | On inequality, follow the u64 successor at node +8 B. |
| `0xfffffe000a6a0000`–`0xfffffe000a6a0018` | Capture a matching node and its marker address. Save the previous marker at S+0xc84. |
| `0xfffffe000a69f8bc`–`0xfffffe000a69f8c4` | After the separate success gate, reload M from S+0xd8c and store it through the saved node +4 B address. |

A decode of the compiler-bounded body finds one direct store and eleven direct loads with the exact operand `[sp, #0x738]`. Each reload's next instruction is checked. The direct census covers this addressing form and supplies the following local interfaces. Other addressing expressions, overlapping accesses, aliases, intervening calls and stack-pointer changes remain separate proof conditions. [Current provider transfer](live_kext_selector26_transfer_report.md) [Current context layout](live_fairplay_context_lifecycle_report.md)

| Immediate consumer of reloaded Q | Installed load sites |
| --- | --- |
| Compare Q to zero | `0xfffffe000a67d950`, `0xfffffe000a67eea4`, `0xfffffe000a683f58`, `0xfffffe000a6843cc` |
| Read u32 Q+8 B, the constructor's mode field | `0xfffffe000a67d9bc`, `0xfffffe000a683fdc` |
| Store Q into the record at X0 | `0xfffffe000a683df4` |
| Read u64 Q+16 B, the constructor's task field | `0xfffffe000a688f24`, `0xfffffe000a68c4d8`, `0xfffffe000a6926f8` |
| Copy Q to C+0x118 before loading the list head | `0xfffffe000a69fee4` |

## Allocation, publication, and teardown

The empty-head and exhausted-list paths enter allocation preparation at `0xfffffe000a69f8f0`. The T-bank expression with key `0x3e` produces `0x54`, which yields slot index `0xf13`. The authenticated call at `0xfffffe000a69f990` reaches `_IOMallocTypeImpl` at `0xfffffe000c509774` with modifier `0xd0c8`. The V-bank expression with key 5 produces `0x2d`, which yields pool index `0x13`. The pool fixup at `0xfffffe0008488a38` yields descriptor-plus-12 B. The descriptor at `0xfffffe0008492340` and the cleanup descriptor at `0xfffffe0008491d40` are byte-identical 64 B images with name `site.UIDList`, signature `21`, flags `0x64`, and requested extent 16 B. [Current node cleanup](live_fairplay_context_lifecycle_report.md)

| Condition or effect | Installed branch index or store site | Result |
| --- | --- | --- |
| Null candidate P | `0xb33` | `0xfffffe000a6a00a4`, bypass marker load |
| Null allocation B | `0x51f` | `0xfffffe000a6a00a4`, bypass node stores |
| Nonzero allocation B | `0x521` | `0xfffffe000a69f9ec`, enter node fill |
| Fill K and M | `0xfffffe000a69fa00` | u32 K at B+0 and u32 M at B+4 |
| Save previous head | `0xfffffe000a69fa08`, `0xfffffe000a69fa0c` | Read Q+0 after the allocation returns and store it at B+8 |
| Publish B | `0xfffffe000a69fa10` | Store B to Q+0 after the three node fields |
| Matching discriminator with unequal old marker | `0xbc1` | `0xfffffe000a6a0074`, existing-node resource path |
| Status success at the separate update gate | `0xc0e` | `0xfffffe000a69f8a0`, enter marker update |
| Other status at that gate | `0xf4` | `0xfffffe000a6a00a4`, bypass marker update |

Search takes O(n) time and O(1) traversal state for a stable acyclic list of n valid nodes. Prepend fills 4 + 4 + 8 = 16 B and publishes one 8 B head pointer in O(1) additional operations excluding the allocator. The matching discriminator takes an independently gated resource route. Complete installed-build replacement semantics remain unknown. [Historical existing-node path](userclient_uidlist_replacement_report.md)

The installed writer stores the insertion marker into P+0x6c. With the same P, marker, and context epoch, the UIDList publication carries it to node +4 B. For a marker other than `0x31ae0066`, cleanup uses `M XOR 0x31ae0066` as its u32 lookup key, as insertion does. Cleanup takes its separate node-only arm for marker `0x31ae0066`. The allowed marker domain and the native selection of either arm remain unknown. K's relation to an external identity remains unknown. These blocks pass private kernel values and introduce no Mach-port transfer or message emission. [Current cleanup and lookup](live_fairplay_table_cleanup_report.md) [Mach endpoints and emitters](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| U1 | Fileset, historic proof inputs, and fixups match the pinned identities. The installed mapping depends on this. | Rehash inputs, recover compiler bounds, compare selected words and decode each fixup and landing word. |
| U2 | Selected visits use the same saved-frame epoch, C, S, Q and dispatcher roots. Context and marker flow depend on this. | Trace SP and overlapping or aliased writes across incoming block paths and calls, including X28's change from pool base to bank root. |
| U3 | P is valid, and the ordinary allocator return preserves W24 and the saved cells. The marker-to-node transfer depends on it. | Compare both allocator-result branches and prove the saved roots and callee-saved register lifetime on actual paths. |
| U4 | Q and its links remain valid, and B is valid and disjoint on success. Search, prepend and the complexity bound depend on these conditions. | Check allocation extent, head writers, cycle exclusion, lock coverage and the head reload before publication. |
| U5 | Cleanup receives the same epoch's marker and table header. Entry and pointer continuity depend on it. | Correlate the installed writer, node publication, cleanup lookup, and release using the same context, marker, header and payload. |

High impact applies to the installed marker handoff and the exact node/head publication order. Medium impact applies to the additional mode and task field uses and the alternate existing-node route. Low impact applies to the type name as evidence of external identity.

QG1 covers factual scope. QG2 records the assumptions and falsification probes. QG3 covers the selected search, marker paths, allocator interface, node publication and teardown correspondence. QG4 checks widths and traversal bounds. QG5 covers null results, the special marker and the scope of the direct stack scan. QG6 uses build-pinned original words, fixups and replayed queries. QG7 records the limits on serialization, reachability and daemon correlation. No native target call was performed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_uidlist.py "$CURRENT_COLLECTION"
```
