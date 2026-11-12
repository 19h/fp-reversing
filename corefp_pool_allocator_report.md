# CoreFP selector-gated pool allocation and holder-list contract

Original routine `0x1bc12c` is a selector-gated pool allocator under decoded operation `0x2b9b`. It acquires the reset/root token, tests the same selector for exact equality to 1, searches a holder list and can request backing from `malloc` at `0x1bcf5c`. With an explicitly empty private holder and successful declared allocation, its original instructions insert the backing node, split a block, fill bytes and publish an interior pointer through record+0. This establishes a local allocation role and a conditional writer of the preparation field at image+`0x1d32e18`.

The routine does not activate the selector. Native holder construction, incoming caller admission, preparation-object compatibility with the protected root, successful protected processing and daemon/kext pairing remain unknown. The original raw holder profile stops before dereferencing `0x176cb4e3`. The full goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_pool_allocator.py), [checks archive](triage_evidence/corefp_pool_allocator_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_pool_allocator.py), [audit archive](triage_evidence/corefp_pool_allocator_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_pool_allocator_publication.py) retain the evidence. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; offsets are hexadecimal and extents are bytes (B). Primary evidence consists of original image bytes, decoded chained fixups and current SDK declarations. No live IDA corroboration is claimed in this increment.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PA1 | The pinned image, compiler bounds and frozen readers identify the source. All local source results depend on them. | Compare the complete 4236 B body, every executed byte and reaching authenticated pointer row; preserve the three supplied inputs. |
| PA2 | A private 32 B aligned record with decoded operation `0x2b9b` supplies the analyzed entry. Record/result claims depend on this diagnostic entry. | Independently reconstruct all 15 initial CPU/RAM states and raw record words. Prove the address-key reduction over the full u64 address domain; identify the unique entry fixup. Actual incoming callers remain unresolved. |
| PA3 | Exact selector/token values and a separately declared empty holder delimit activation and list state. Allocation claims depend on these premises. | Compare selector 0/2/255 bypasses, selector 1, busy token and original raw holder. Only the explicit empty-holder controls replace endpoints with the source-derived sentinel. No source activation or native initialization is supplied. |
| PA4 | `malloc` NULL or a distinct 8192 B private arena models backing. Successful suballocation claims depend on that declared backing. | Check ten exact allocation requests, five NULL returns and five backed returns, including volatile-register clobber. Verify every write extent, list endpoint, output pointer and all final RAM. No native allocator or original raw pointer executes. |
| PA5 | PAC and sequential CASAL models retain their frozen semantics. Control/cleanup results depend on those boundaries. | Check every reaching load, original key/diversity, CASAL compare/replacement and restored callee-saved state; stop before a second failed-token attempt. Concurrent ordering and native ownership remain unknown. |
| PA6 | Finite layout formulas and literal call candidates retain their stated scope. Broader role attribution depends on those limits. | Check successful request values 0/1/32/128, the 4799/4800 threshold, every reverse-fill byte and all 537 adjacent modifier/call pairs. Four different callee rows share IA `0x478b`; no candidate target follows from the modifier alone. |

## Entry record, shared state and original control flow [PA1-PA6]

The complete function spans `0x1bc12c..0x1bd1b8`, 4236 B. Its authenticated entry row is `0x1d037d0`, key IA, diversity `0x478b`. This identifies the callee row without establishing an incoming callsite.

For record address R, define `K(R)=((R XOR 0xcf834db9ae8c9498)*0x9e8a2055) mod 2^64`. The original pre-multiply expression is `(((R AND 0x569daa3f03dab736)<<1)-R+0x296255c0fc2548c9) XOR 0xe6e1187952a9dc51`. An independently retained UNSAT query proves equality with the reduced XOR over all u64 addresses. Multiplication by the same constant preserves equality modulo 2^64.

| Record field | Source contract |
| --- | --- |
| `R+0`, u64 | Result pointer stored at `0x1bd194` on completed paths; other 24 B retained |
| `R+8`, u64 | `n=(load_u64(R+8)+K(R)+0xb055c0a249dc0450) mod 2^64`; interpreted here as a requested extent only for retained small controls |
| `R+0x10`, u32 | `(load_u32(R+0x10)+low32(K(R))) mod 2^32 =0x2b9b` |
| `R+0x14..31` | Diagnostic fill retained; no argument semantics assigned |

```text
entry 0x1bc12c, operation 0x2b9b
  -> update two obfuscation-state cells
  -> 0x1bc344 CASAL: compare 0x5d96, replace 0xa94ef
       mismatch -> retry prefix -> bounded stop
       match -> selector image+0x1d44409 == 1?
                  no  -> result 0 -> restore token -> return
                  yes -> decode request / derive extents
                       -> holder head == holder+0x30 sentinel?
                            yes -> malloc at 0x1bcf5c
                                     NULL -> result 0 -> restore -> return
                                     backed -> insert node -> search again
                            no  -> inspect node extent, links and trailer
                       -> selected split / reverse fill / metadata stores
                       -> result interior pointer -> restore token -> return
```

The token is image+`0x1d33108`, shared with the [reset](corefp_optional_reset_report.md) and earlier protected-root paths. Selector equality is literal at `0x1bc3d8`; 0, 2 and 255 bypass allocation. This function makes no selector store. Original state updates at `0x1bc22c` and `0x1bc234` target image+`0x1d33778` and image+`0x1d37f68`; they are separate from the holder, selector and token. The phase derived from the selected tag is W9=`0x1cd5`, and independently checked original table rows resolve acquisition, success, selector-one and selector-other branches.

| Role / source load | Constant bank output | Original pointer row | Selected target |
| --- | --- | --- | --- |
| First state pointer, `0x1bc1b8` | `0x94` | `0x1d0cf08` | `0x1d3377c`, then subtract 4 |
| Second state pointer, `0x1bc208` | `0x8d` | `0x1d120a8` | `0x1d37f68` |
| Dispatch base, `0x1bc2c0` | `0x2e` | `0x1d108e8` | `0x1c81944`, then subtract 4 |
| Token, `0x1bc33c` | `0x18` | `0x1d065d0` | `0x1d33108` |
| Selector, `0x1bc3d0` | `0x02` | `0x1d0fe78` | `0x1d44409` |
| Holder, `0x1bc938` | `0x02` | `0x1d133e0` | `0x1d32dd8`, then subtract 8 |
| Backing allocation, `0x1bcf34` | `0xec` | `0x1d037e0` | `_malloc`, IA `0xd4d0` |
| Cleanup, `0x1bd16c` | `0xd6` | `0x1d03570` | `_free`, IA `0x7c9f` |

For each bank the auditor independently enumerates all 256 inputs to `x XOR B[A[x] XOR c]`, then verifies its pointer row. The eight bank lemmas cover 2048 inputs. Their complete A/B bytes, biases and selected rows are retained. Both imported call targets are source-resolved; retained profiles invoke only the allocation edge.

## Holder list, backing and suballocation [PA1,PA3-PA6]

Let H=image+`0x1d32dd0` and S=H+`0x30`. An explicitly empty private holder sets both H+`0x48` and H+`0x50` to S. These are supplied diagnostic initializations, not a recovered initializer. The original bytes at H+`0x48` instead contain `0x176cb4e3`, as in the previously stopped protected-root preparation route.

| Field / source site | Established local role |
| --- | --- |
| `H+0x48`, read `0x1bc9fc` | One list endpoint; compared to S to select the empty path |
| `H+0x50`, reads `0x1bcfdc` / `0x1bd05c` | Opposite endpoint used for reciprocal-link checks and insertion |
| Node+`0x18` / node+`0x20` | Reciprocal list pointers; source checks and rewrites them |
| `0x1bd058`, `0x1bd060` | Initialize new backing node links |
| `0x1bd064` | Publish the new node at H+`0x50` |
| `0x1bd06c` | Write through the prior endpoint's +`0x18`; when empty, this writes H+`0x48` |
| `0x1bcc30`, `0x1bcc38` | Original unlink stores; source-resolved, not reached by the retained split profiles |
| `0x1bce50`, `0x1bce68`, `0x1bce70` | Reduce retained free-node extent and write the new split metadata |
| `0x1bce98`, then `0x1bd194` | Form split-node+`0x18` and publish the interior pointer in R+0 |

Consequently the exact preparation field image+`0x1d32e18` has list-endpoint semantics here and a conditional source writer. This closes the earlier absence of any valid-pointer writer under private premises. It does not prove the protected root can consume this arena as its preparation object, nor establish a native initialized epoch. The first slot's reset free field H+8 remains distinct: this routine's successful profiles do not publish their backing allocation there.

At `0x1bc5c0..0x1bc5cc`, source computes signed-u64 maximum between `(n+201) mod 2^64` and 5000, then stores that allocation request. For retained nonnegative n through 5000 this equals `max(n+201,5000)` B. The full wrapping/signed input domain has not been characterized. Current arm64e SDK syntax-only assertions verify eight-byte pointers/size_t, four-byte u32 and `void *malloc(size_t)`.

| Private control | `malloc` request | Published result | Outcome |
| --- | --- | --- | --- |
| Selector 0 / 2 / 255 | None | 0 | Complete return |
| Busy token | None | No result store | Stop before second CASAL |
| Selector 1, original raw holder | None | No result store | Stop at `0x1bca38` before node+8 read |
| Empty holder, n=0 / 32 / 4799, malloc NULL | 5000 B | 0 | Complete return |
| Empty holder, n=4800, malloc NULL | 5001 B | 0 | Complete return |
| Empty holder, n=5000, malloc NULL | 5201 B | 0 | Complete return |
| Empty holder, n=0 / 1, backed arena | 5000 B | Arena+`0x1354` | Complete return; 100 reverse-fill stores |
| Empty holder, n=32, backed arena | 5000 B | Arena+`0x1340` | Complete return; 120 reverse-fill stores |
| Empty holder, n=128, backed arena | 5000 B | Arena+`0x12e0` | Complete return; 216 reverse-fill stores |
| Empty holder, n=32, volatile clobber | 5000 B | Arena+`0x1340` | Same final record/holder/arena bytes |

For the five successful profiles only, define `p=(max(n,15)+28) AND ~3`, arena A and literal C=`0x2fecaf1f3ee407fa`. The independently specified finite oracle checks split-node N=`A+5000-p-36`, returned pointer N+24, encoded words `[C+(N-A), C-p-12, 0x0fd0175a324022ad]` at N, and holder+`0x28` increment p+12. The remaining backing node at A retains both links to S; H+`0x48` and H+`0x50` both become A. Extent/header words are obfuscated scalars, not pointer types.

Before metadata overlays, `0x1bcd74` writes p+60 bytes in descending address order ending at A+4975. Byte j derives from `((t+j) XOR 0xba)*(t+j+17) mod 256`, t=`0x62017f78`, with the generated sequence stored in reverse. The oracle checks all bytes after the 24 B split metadata overlays, every store address/width, all 88 B of other arena stores and every final RAM page. Returned payload ranges for the retained nonzero requests remain within declared backing. No full-domain packet-size theorem, zero-fill contract or native allocation ownership is asserted.

## Incoming candidates, ports and bounded continuation [PA1-PA6]

A complete original `__text` scan finds 537 aligned literal `MOV X17,#0x478b; BLRAA X8,X17` pairs in 65 compiler-bounded functions. The audit retains every 8 B pair and containing entry. Four authenticated callee rows share the modifier:

| Original pointer row | Target |
| --- | --- |
| `0x1d03538` | `0x2f445c` |
| `0x1d036a8` | `0x5c87d4` |
| `0x1d03718` | `0x326f30` |
| `0x1d037d0` | `0x1bc12c` |

The 537 sites remain candidate callsites, not established callers of this allocator. Modifier matching alone cannot distinguish these targets; each needs its reaching pointer load, bank root and record producer.

No retained path invokes Mach send/receive, port allocation, a MIG helper or a descriptor transfer. `malloc` backing identities, holder links and returned interior pointers are process-local modeled addresses. Incoming/outgoing native port identities, right ownership, emitted-message pairing and daemon/kext interaction receive no new evidence from this routine.

| Impact | Bounded next investigation | Falsification / completion condition |
| --- | --- | --- |
| High | Resolve reaching loads and record construction at selected IA `0x478b` candidates. | Establish an original call to the unique allocator row with its source-produced size/tag; reject sibling-row matches. |
| High | Locate selector-set-to-1 and holder sentinel/endpoint initialization. | Require source writes establishing both selector and valid same-epoch holder state; current private overlays do not satisfy this. |
| High | Compare preparation-root consumers with the allocator's actual node layout. | Trace original writes/reads across the shared H+`0x48` field before assigning object compatibility or protected-processing readiness. |
| Medium | Follow allocation failure, list-integrity rejection and `_free` edge. | Source pointer/size/retirement contract must be established without treating original raw bytes as backing. |
| Medium | Characterize packet sizing and wrapping/signed controls beyond retained n. | Obtain source-lifted proofs with explicit bounds; finite packet formulas remain provisional outside the checked inputs. |
| Low | Correlate established local lifetimes with prior daemon/MIG evidence. | Require matching source handoffs and epochs; no cross-layer identity follows from a common allocator. |

## Validation and quality gates

Independent fresh replay passes 15 profiles, 20573 original instruction visits, 2633 data reads, 1940 writes, 854 PAC models, 25 API/CASAL models and 118 state points. Ten declared allocation attempts split into five NULL and five backed results. Thirteen profiles return completely; the busy-token and original-raw-node profiles stop before their declared boundaries. The auditor independently reconstructs 15 initial CPU frames and 2056192 B each of initial/final sparse RAM. It imports no new producer.

Complete source checking covers 4236 B, plus the separate literal-call inventory. Eight bank lemmas, 33 exact instruction assertions, one universal pre-multiply UNSAT query, SDK syntax-only declarations and independent record/holder/arena oracles pass. Conservative producer/replay cost is `O(C*(B+P*F+V*J+R))` time/space with 12000 original visits per profile; bank enumeration adds `O(256*K)`, K=8, and literal scanning adds linear text-byte work. SMT is bounded to 30 s/query. No native target/API/IPC or IDB mutation executes.

- **QG1**: No normative premise is required; local contracts and evidence limits are stated.
- **QG2**: PA1-PA6 define assumptions, dependent results and falsification probes.
- **QG3**: Routine role, record ABI, state/control flow, allocation/cleanup interfaces, port limits and continuation are covered.
- **QG4**: U8/u32/u64 widths, modulo arithmetic, B extents, arena bounds and finite oracle scope are explicit and reproducible.
- **QG5**: Original raw state, declared empty state and source-produced node epochs remain distinct. The function reads the selector without activating it; modifier peers and unexecuted edges are not assigned caller/runtime status.
- **QG6**: Pinned original bytes/fixups, current SDK declarations and fresh independent replay provide provenance; no live corroboration is claimed.
- **QG7**: Impact-ranked continuation is bounded; native admission, compatibility, ownership and cross-layer pairing remain unknown.
