# Daemon IOKit errors: root return, adapter delta and caller continuation

Both selected IOKit error controls return through the actual preceding root and stack adapter, preserve their distinct root-result words, and select the same caller error branch. The adapter publishes zero stack delta because the original root has restored its biased temporary seed. The caller writes a fixed u64 marker into its earlier input-A span, joins a common preparation block, and reaches an unspecified u64 bank-root pointer at caller `SP+0x600`. The reaching execution stops before using that pointer to form an address. These are source contracts under the inherited private-context and API/free-return premises; a complete external error response and native daemon-kext delivery remain unknown. [ER1-ER8]

```text
prior root R+8 = encoded error; ordinary free return is a premise
  |
  +-> original root guard equality -> root RETAB 0x100309d10
  |                                   |
  |                                   v
  +-> adapter reads restored seed -> Q = delta = 0
                                      |
                               RETAB 0x1004aca7c
                                      |
                               caller SP remains S
                               reads the same R+8
                                      |
                         encoded-result nonzero branch
                                      |
                    input-A[0:8] = 0xe87f552eb3388cb6
                                      |
                      common local-state preparation
                      copy unspecified 8 B unchanged
                                      |
                        load u64 base from S+0x600
                                      |
                        STOP before 0x1004f650c
                        ADD base + low8(selector)
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ER-A1 | The pinned original daemon and parent receipts identify the analyzed build and source epochs. All reaching results depend on them. | Rehash source and receipt dependencies; compare every source word and fixup. Native task/build/connection/provider identity remains unknown. |
| ER-A2 | The inherited valid private caller/frame/object extents, controller values and earlier explicit operand premises remain in force. Reaching paths depend on them. | Restore exact preceding journals, verify both original entry frames, and independently replay the selected post-block and result prefixes. No native entry admission is inferred. |
| ER-A3 | Selected IOKit returns and the ordinary free return have exactly the parent-declared effects and preservation rules. Error-path reachability depends on them. | Keep API=5 and API=0 with embedded status `0xffff5a5e` separate. Replay two independent physical backing/clobber patterns, preserve logical unknowns and reject source access to the retired 32 B allocation. Native API/free effects remain unknown. |
| ER-A4 | The restored source guard and logical return-token contracts qualify private root/adapter return execution. Return reachability depends on them. | Check the actual guard reads, original saved frames, both RETAB targets and all X19-X29 values. Native pointer authentication, signing, scheduling and faults are not reproduced. |
| ER-A5 | Scalar proofs use explicit source-cell contracts, the reaching phase literals and modular u32/u64 arithmetic. Universal slice results depend on that scope. | Re-run eleven nonvacuous UNSAT queries and compare all finite source effects. These slice proofs do not establish arbitrary aliasing or all controller epochs. |
| ER-A6 | Copied unspecified bytes and the unspecified bank base remain logical origins. Unknown/frontier claims depend on preserving that distinction. | Check all eight byte origins at each read/copy, enumerate retained bank-cell writers and stop before address arithmetic. Physical replay backing is not a source definition or evidence of external control. |

## Actual frames, seed lifetime and return delta

Let S be the source caller SP, F=`S-0x9d0` the retained root SP, R=`S+0x10cb8` the caller's root record, Q=`S+0xba18` the separate delta cell, and T=`S-0x50` the adapter's temporary seed cell. These are model addresses with source-derived relative relationships; their numeric private backing addresses are not recovered native addresses. [ER2-ER4,ER7]

The original ingress prefix calls adapter `0x1004ac814` at `0x10084cb04` with `(X0,X1)=(R,Q)`, then calls root `0x10049f358` at `0x1004aca58` with `(X0,X1)=(R,T)`. The root reserves `0x980` B below T. The adapter uses a 64 B fixed frame and, in these four parent contexts, a 16 B dynamic reserve. Its saved FP is `S-0x10`. The previous general adapter-reserve proof remains separate from these finite actual reserves. [ER2-ER3,ER7]

| Cell / source PC | Reaching source effect | Lifetime evidence |
| --- | --- | --- |
| T, `0x1004ac9a4` | u64 seed `C-0xb0` | Original adapter write; C=`0xc48d2124b50100b9` in these contexts. |
| T, `0x10049f4a8` | u64 increment by `0xb0`, restoring C | Original root write before the later nested processing/API path. |
| T, `0x1004aca5c` | Read low u32 of restored C | No intervening overlapping source write across the retained ingress, preparation, processing, post-block, result and return journals. |
| Q, `0x1004aca68` | u64 delta zero | Actual adapter publication, separate from the root result R+8. |
| R+8, `0x10084cb18` | Read the preceding encoded root error | Same source record and field; no new source write to that field in this continuation. |

The root reads its saved guard at `0x100309cdc` and the guard reached through the import cell at `0x100309ce8`; their private source values are equal. The branch at `0x100309cf0` falls through. The original epilogue restores X19-X29, LR and SP=`F+0x980=T`, then RETAB `0x100309d10` returns to `0x1004aca5c`. Independent replay checks the actual saved values rather than substituting a fresh return frame. [ER3-ER7]

The adapter's original instructions `0x1004aca5c..0x1004aca68` implement:

```text
d32   = (u32(T[0:4]) - u32(C)) mod 2^32
delta = zero_extend_64(d32 mod 2^16) << 4
Q[0:8] = delta
```

Thus the restored T=C gives delta=0. The equation covers arbitrary input low words under its cell contract; the eight retained paths establish actual cancellation under their inherited premises. The adapter restores its own saved X19-X22, FP and LR, leaves X23-X28 unchanged, restores SP=S, and RETAB `0x1004aca7c` returns to `0x10084cb08`. The audit compares all X19-X29 against the original adapter entry. The caller then applies the separately stored Q delta to SP and reads R+8. [ER3-ER7]

## Caller error recognition and state rejoin

The caller gate at `0x1008c1710` compares the encoded root word against `0x8b3dc651`, encoded zero. Under its reaching phase W19=`0x5d32`, the original table selection is universal over u32 status values. Each branch's original slot and IA diversity are checked independently. [ER3-ER7]

| Returned root word | Decoded error interpretation in parent | Gate index / slot | Original destination |
| --- | --- | --- | --- |
| `0x8b3dc654` | API status 5 XOR `0x8b3dc651` | `0x5d32` / `0x101068880` | `0x1008c26d4`, diversity `0x0a9e` |
| `0x74c29c0f` | Embedded `0xffff5a5e` XOR `0x8b3dc651` | Same index and slot | Same error head |
| `0x8b3dc651` | Encoded zero, source equation and prior isolated control only | `0x5d45` / `0x101068918` | `0x10085ead4`, diversity `0x0a9e` |

This increment executes the first two rows across two epochs and prefix/extended modes. It does not add a complete zero/zero root return. The parent zero/zero paths still stop before a different helper. [ER2-ER4]

At `0x1008c26e8`, the error head stores u64 `0xe87f552eb3388cb6` at S+`0x5c48`. This is the same span whose pointer was stored in R+`0x10` as input-A before the root call. Its application-level meaning is unknown; it is not established as an external response, port, right or public ABI field. The error head then chooses index `0x5d45` and branches at `0x1008c26fc` to `0x10085ead4`. The error path therefore reaches the immediate destination also selected by encoded zero, after an additional write and with a distinct incoming state. Sharing that destination does not make the whole paths equivalent. [ER3-ER7]

The common block copies eight logically unspecified bytes from S+`0x4a20` to S+`0x8ad0` and zeroes the two-byte cell S+`0x3a06`. Subsequent preparation stores a pointer to the latter cell at S+`0x6c48`. The copy is verified byte for byte without assigning values or semantics to its source. Both errors retain the same selected branch sequence; their distinct root-result words remain in R+8. [ER4,ER7]

## Local bookkeeping and strict unknown frontier

The u64 cell S+`0x16d0` starts at zero under the inherited caller fixture. Source `0x1008c1730` subtracts `0x480`, then `0x10080e26c` adds `0x40`: its final bits are `0xfffffffffffffbc0`, signed interpretation -1088. Before that increment, source forms `S+0xc070-0x480=S+0xbbf0` and publishes it at S+`0x8e8`. This is local arithmetic; no allocation, native free, ownership or adjustment of live SP is established by the negative value. Live SP has already returned to S. [ER3-ER7]

At `0x1004f64d8`, source publishes pointer `0x1010c67dc` at S+`0x918`, reads that source-state u32, and copies it to S+`0x4c94`. The retained value varies with the preceding source context. It is not a universal constant. [ER4,ER7]

| Epoch | Prefix-mode value | Extended-mode value | Both error controls |
| --- | --- | --- | --- |
| 0 | `0x83` | `0x87` | Equal within the same parent context |
| 1 | `0x84` | `0x88` | Equal within the same parent context |

The last completed instruction is `0x1004f6508`, `LDR X24,[SP,#0x600]`. It reads eight unspecified bytes from S+`0x600`. No overlapping source write exists in the retained ingress-to-return journal chain. This is a missing upstream definition in the analyzed context; native initialization and external controllability are unknown. It is separate from the eight-byte copy at S+`0x4a20`. [ER3-ER4,ER7]

The next instruction, `0x1004f650c`, would compute:

```text
address64 = (bank_base64 + zero_extend_64(selector32 & 0xff)) mod 2^64
```

Its equation is source-proved in isolation, but the reaching trace stops before executing it. The following `LDRB` at `0x1004f6510` is therefore also unexecuted. Original later source shows another bank-root read from S+`0x5f8` at `0x1004f6518`; that read has not been reached. No bank pointer, table result or subsequent target is filled to continue the path. [ER3-ER6]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| ER1 | Original daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; every retained source word is compared with original image bytes. |
| ER2 | [Parent result report](daemon_iokit_result_report.md), parent checks SHA256 `8602bdf334f6f52a96e4fe5be4528d89b4653369bda02c17b607e64b6f4f1525`, and pinned preceding ingress/preparation/processing/post-block receipts. |
| ER3 | [Extractor](triage_evidence/recover_daemon_iokit_error_return.py): exact predecessor restoration, source-only continuation, retired-span guards, strict unresolved stop and explicit source slices. |
| ER4 | [Compressed checks](triage_evidence/daemon_iokit_error_return_checks.json.zst): eight cases, 4,200 new source visits, 472 read events and 328 write events; no new API-return model. Logical SHA256 `191d641b67e9200cb7f906a0b96f3c89715cfeb1936a910cb4febdbfa9b6cc83`. |
| ER5 | Eleven nonvacuous UNSAT equations: root frame restoration; adapter delta; restored-seed cancellation; adapter frame restoration; caller delta application; same-record result load; encoded-result branch; error marker/rejoin; arbitrary common-block copy/zero; u64 bookkeeping; unexecuted bank-address dependency. |
| ER6 | Original root/adapter/caller/error/common/frontier bytes and format-12 branch fixups; source cell and phase contracts qualify the equations. The bank-address equation does not add a reaching instruction. |
| ER7 | [Independent A64 auditor](triage_evidence/audit_daemon_iokit_error_return.py) and [compressed audit](triage_evidence/daemon_iokit_error_return_audit.json.zst): temporal seed writers, original entry/return frame comparisons, guard equality, field identities, exact branch sequence, unknown origins and independent CPU effects. Logical audit SHA256 `122c82e86a193613de78446f60a398f9e84124a8614594115bc130129e1b820d`. |
| ER8 | [Publication verifier](triage_evidence/verify_daemon_iokit_error_return_publication.py): receipt/source pins, solver results, exact interface joins, replay coverage, publication delta, preserved originals and decoded-path hygiene. Associated files suffice; no new IDA access is required. |

Two physical backing/clobber patterns per case produce 16 independent new-source replays, `8*2*525=8,400` visits. They check 6,880 read bytes, 4,320 write bytes, 7,648 register effects, 96 NZCV effects and 656 write effects. The arbitrary common-block copy accounts for 128 unspecified copied-byte writes across those replays. The earlier post-block and error-result prefixes are separately re-executed for 31,632 visits; older predecessor journals are restored and source-word checked, not newly CPU-executed. These totals are not combined into the new-source count. [ER4,ER7-ER8]

Extraction/audit use O(receipt bytes+C*(private-state bytes+V+E)+I+Q) time/space, excluding solver complexity, with at most 20,000 visits per new continuation and 30 s per solver query. Here C=8 reaching cases, V=525 visits per case, E the retained effects, I the captured source/fixup extent and Q the query representation. Independent CPU replay adds two physical patterns. Large JSON and the manifest are losslessly roundtripped zstd level-22 archives. [ER3-ER8]

No new Mach port name, right operation or message emission occurs in this retained continuation. There are no new BL/BLR/BLRAA/BLRAB/SVC instructions. Earlier IOKit/free imports remain separate declared-return premises. The marker is a private source store, and the subsequent common block has not produced an external response. Native delivery, ownership, authorization, complete error handling and daemon-kext transaction pairing remain unknown. [ER3-ER4,ER7]

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Recover the caller bank roots upstream of S+`0x600` and S+`0x5f8`. | Actual writer/source epoch and cell identity, original bank bytes and a continuous reaching path; do not replace the unknown pointer with a convenient table. |
| High | Complete caller error response after the common preparation. | Preserve the error marker, root word and differing incoming states through the remaining source to actual response publication or return. |
| High | Resolve the daemon zero/zero helper. | Decode the actual pending record, follow count and span use, and establish bounds and result/copyback effects. |
| High | Establish native daemon-kext result delivery. | Matched build/task/connection/provider epoch, actual API return/copyout and the same daemon consumer; source scalar compatibility alone is insufficient. |
| Medium | Establish marker and copied-field semantics. | Earlier writers and later consumers, valid extents, aliases and lifetime; no public ABI meaning follows from these local stores alone. |
| Medium | Generalize the finite error paths. | Other statuses/controller epochs, source guards and nonzero delta cases, distinguishing universal slice results from whole-path reachability. |

- **QG1**: Pass. Factual source/ABI/data/control-flow analysis requires no normative content.
- **QG2**: Pass. ER-A1..ER-A6 identify dependent results and falsification probes.
- **QG3**: Pass for this increment. Actual root/adapter returns, temporal seed cancellation, caller result recognition, local rejoin and strict unknown frontier are covered. The full goal remains active.
- **QG4**: Pass. All extents/offsets are bytes; u32/u64 modular arithmetic, frame restoration, distinct result/delta cells and source/replay/prefix counts are explicit.
- **QG5**: Pass. Distinct root errors, shared target versus incoming state, per-context state words, unspecified pointer versus copied bytes, source equations versus reaching execution and private versus native effects remain distinct.
- **QG6**: Pass. Original bytes/fixups, pinned journals, eleven source equations, independent CPU effects and publication/preservation/path checks provide scoped provenance.
- **QG7**: Pass. Bank-root origin, complete error response, zero/zero helper, native delivery, field semantics and generalization are impact-ranked above.
