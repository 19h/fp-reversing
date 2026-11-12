# CoreFP protected-root adapter and caller-word ABI

Upstream continuation: the [root-record ingress report](corefp_root_ingress_report.md) establishes original caller0x5f4584, source root-field production and the use of adapter output as an SP adjustment before ingress result forwarding. It also resolves the sibling0x77d398 prefix and supplies conditional local bank targets for0x9d4064/0x1174224; the historical candidate table below records what this earlier increment alone established.

Original adapter `0x8fcfa0..0x8fd1e0` passes its entry X0 record unchanged to protected root `0x8e81c8`, through authenticated pointer slot `0x1d05150` at callsite `0x8fd1b8`. It replaces entry X1 with a private stack word initialized to the caller's u64 value minus `0x100`. On child return, it writes `16 * ((child_word - initial_caller_word) mod 65536)` into the original caller word. The result is an eight-byte integer store; its broader interpretation as a size, position or status is unknown.

Twenty-five coherent private executions and independent original-byte replays complete the selected failure paths. The root's early `+0x100` restores the internal word to the original seed; the adapter then writes **zero to the external word**, including u64 wraparound cases. The earlier [direct-root release report](corefp_lookup_release_report.md) correctly observed `+0x100` on the word supplied directly to the root. This increment establishes that an adapter caller observes a different word and result. Record markers, residual X0 and this external output remain separate channels.

No native target/API/IPC executes, and no IDB changes. Public entry reachability, native record producers, successful protected processing and daemon/kext pairing remain unknown. The full interface goal remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_root_adapter.py), [checks](triage_evidence/corefp_root_adapter_checks.json), [independent auditor](triage_evidence/audit_corefp_root_adapter.py), [audit receipt](triage_evidence/corefp_root_adapter_audit.json), [IDA snapshot](triage_evidence/corefp_root_adapter_ida.json) and [publication verifier](triage_evidence/verify_corefp_root_adapter_publication.py) retain source bytes, complete private journals, solver queries and publication checks. Logical JSON paths resolve to `.json.zst` storage. The frozen [cold metadata](corefp_cold_metadata_report.md) and [lookup release](corefp_lookup_release_report.md) contracts supply the explicit external models.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses below are CoreFP preferred-base-zero offsets. Integers are unsigned unless stated; arithmetic wraps at the specified width. Extents are in bytes (B).

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RA1 | The pinned original images identify the analyzed code and fixups. All source claims depend on this identity. | Verify image hashes, all 22 retained function/stub extents and original chained-pointer rows. Compare 828 code bytes with IDA; check the separate eight-byte decoded pointer representation. Native image selection is unknown. |
| RA2 | Entry X0 points to the frozen diagnostic 48 B private root record; entry X1 points to an independent readable/writable eight-byte word. Failure compositions depend on this input. | Independently reconstruct the unsimplified address key, operation `0xc1f7`, decoded field at +24 equal to zero, two private referents and all initial RAM. Field +16 remains diagnostic `0xa5` bytes. No upstream native record producer or successful-path admission is established. |
| RA3 | Entry SP is aligned and backed; the child preserves the ordinary callee-saved registers used by the adapter. General wrapper formulas depend on these conditions. | Cover all sixteen dynamic padding values and compare SP/X19-X30 restoration at all 25 outer returns. Full initial/final CPU and touched RAM are checked. Native stack checks, interrupted frames and nonconforming children remain outside scope. |
| RA4 | Once, allocation, bootstrap, locks and PAC use the frozen sequential private models. Coherent failure results depend on them. | Execute original once callbacks; compare heap/static lock, caller-register clobber, primary/fallback discovery, certificate-allocation failure and unlock results 0/5. No native ownership, PAC authentication or synchronization result is inferred. |
| RA5 | Bootstrap names and unchanged-ID daemon translation retain their explicit fixture meanings. Port-related observations depend on that fixture. | Check 27 bootstrap calls and repeat 22 daemon source rejections using the frozen independent driver. Full daemon CPU/RAM, native namespace/right translation and kernel endpoint identity remain unknown. |
| RA6 | The examined root failure paths have no further write to the internal word after the early increment. The zero-output composition depends on that path condition. | Check every read/write and exactly two internal-word stores, at `0x8fd114` and `0x8e830c`. A later child write would change the formula's input; zero output also admits nonzero deltas divisible by 65536. |
| RA7 | Literal IA-diversity census scope is the complete aligned original `__text`, with an immediately adjacent `MOV X17,#0x41d4` and `BRAA/BLRAA`. Candidate counts depend on this scope. | Independently rescan instruction words and retain the four containing compiler functions. Other register constructions, indirect dispatch and computed targets are excluded; equal diversity does not identify a callee. |
| RA8 | Finite executions and universal local identities have different scopes. All extrapolations depend on this distinction. | Independently replay all 92184 client visits, check 25 compact oracles and six UNSAT source queries. Pointer-bank selection is observed in these executions; a universal concurrent-state target theorem and complete native reachability remain unknown. |

## Adapter control and data flow [RA1-RA4,RA6,RA8]

The adapter contains one child call and an ordinary return; no local conditional branch changes the selected straight-line wrapper arithmetic. Its fixed frame consumes 64 B. Let `s = load_u64(entry_X1)` and `a = (s * 0x2edd + 1) mod 2^64`. The source also writes `a` to an image cell selected through its original pointer banks. The dynamic padding is `p = 16 * (1 + (a >> 60))`, hence `p` is one of `16,32,...,256` B. The internal word is at `entry_SP - 64 - p`.

```text
external word E contains s              entry X0 = record R
        |                                      |
        +-- adapter 0x8fcfa0 -------------------+
              fixed frame 64 B; padding p B
              internal I := s - 0x100 (u64)
              X0 := R (unchanged); X1 := &I
              0x8fd1b8 -> slot 0x1d05150 -> root 0x8e81c8
                0x8e830c: I := I + 0x100
                selected failure: no further I store
                record R+0 := raw failure marker
                matching-pointer unlock; residual X0
              0x8fd1bc: read low32(I)
              0x8fd1c8: E := 16 * ((I - s) mod 65536)
              restore frame; return residual child X0
```

| Original site | Width / operation | Recovered role |
| --- | --- | --- |
| `0x8fcfb8` | `X19 := X1` | Preserve original external-word pointer |
| `0x8fd098` | 8 B load into X21 | Preserve original seed `s` |
| `0x8fd0ec..0x8fd100` | u64 multiply-add; high-nibble extraction; u32 shift/add | Compute image-cell value and 16 B aligned padding |
| `0x8fd104..0x8fd114` | SP adjustment; 8 B store | Construct private internal word `s-256 mod 2^64` |
| `0x8fd1ac` | 8 B compensated pointer load | Load decoded target from original slot `0x1d05150` in every retained run |
| `0x8fd1b0..0x8fd1b8` | X1 replacement; IA diversity `0x41d4`; `BLRAA` | Call root with the original record and the internal word |
| `0x8fd1bc..0x8fd1c4` | 4 B load; u32 subtraction; 16-bit extraction shifted by 4 | Compute low16 delta multiplied by 16, zero-extended to u64 |
| `0x8fd1c8` | 8 B store through saved X19 | Replace the external word with the computed value |
| `0x8fd1cc..0x8fd1dc` | Frame restoration and `RETAB` | Restore SP/registers; preserve residual child X0 |

The output ranges from `0` to `0xffff0`, in multiples of 16. The upper 48 bits of the child word have no effect on this output. `child_word=s` and `child_word=s+65536 mod 2^64` both produce zero. Six solver obligations prove the source padding identity, output identity, cancellation, conditional zero result, output periodicity, and combined range/alignment for all u64 operands. The output does not identify whether the child succeeded.

Minimal arithmetic pseudocode, conditional on normal child return and the stated memory/ABI preconditions:

```text
s = load_u64(E)
a = (s * 0x2edd + 1) mod 2^64
p = 16 * (1 + (a >> 60))
I = stack_word_below_fixed_frame(p)
store_u64(I, (s - 256) mod 2^64)
child(R, I)
store_u64(E, 16 * ((load_u32(I) - low32(s)) mod 65536))
return residual_child_X0
```

The wrapper's local arithmetic and fixed instruction count are O(1) time/space, with 16..256 B dynamic padding plus its 64 B frame. Child work is additional. The source bank/image-cell mutations are retained in the complete function and journals; the pseudocode isolates the word-transfer contract and does not replace those mutations.

## Complete failure compositions [RA1-RA6,RA8]

| Profile group | Count | Additional condition | Final record +0 | External word | Residual X0 |
| --- | --- | --- | --- | --- | --- |
| Primary / fallback / static / volatile-clobber | 4 | Certificate allocation returns null | `0x45e2a20f` | 0 | 0 |
| Unlock error | 1 | Unlock model returns 5; ledger remains held | `0x45e2a20f` | 0 | 5 |
| Primary / fallback lookup error | 2 | Last bootstrap result is 5 | `0x45e2a2e3` | 0 | 0 |
| All padding values | 16 | Seeds chosen through inverse odd multiplier modulo `2^64` | `0x45e2a20f` | 0 | 0 |
| Seed `0x100` / `0xffffffffffffffff` | 2 | Zero internal initializer / u64 wrap boundary | `0x45e2a20f` | 0 | 0 |

The first seven profiles use seed zero. Across all 25, exactly one eight-byte external-word store occurs at `0x8fd1c8`. Before child return the external word still contains the original seed. The internal word has exactly the initializer store and the root increment store. All complete executions retain original PC continuity between adapter, root, lookup and cleanup, with explicit imported API/PAC models.

These observations refine [LR9 in the direct-root report](corefp_lookup_release_report.md): the root parameter is the adapter's private word when this adapter calls it. They do not establish successful root behavior or the caller's interpretation of zero.

## Caller census and IDA representation [RA1,RA7,RA8]

There is one original rebase row whose target is root `0x8e81c8`: slot `0x1d05150`, encoded word `0x800841d4008e81c8`, pointer format 12, key IA, diversity `0x41d4`, address-diversity zero. IDA's eight-byte slot read is `c8818e0000000000`, the decoded preferred-base target, rather than the original chained word. The auditor checks both representations explicitly. Conventional IDA xrefs show the root's data reference from this slot and no incoming reference to the slot. Those xrefs do not enumerate the obfuscated computed caller set.

| Literal modifier site | Callsite | Containing compiler-function extent | Target established in this increment |
| --- | --- | --- | --- |
| `0x77d394` | `0x77d398` | `0x77d190..0x77d3c0` | unknown |
| `0x8fd1b4` | `0x8fd1b8` | `0x8fcfa0..0x8fd1e0` | `0x8e81c8`, via source reaching load and original fixup in 25 executions |
| `0x9d4060` | `0x9d4064` | `0x9d34d4..0x9d5f4c` | unknown |
| `0x1174220` | `0x1174224` | `0x1173af0..0x1174684` | unknown |

| Original slot | Rebase target | Shared IA diversity |
| --- | --- | --- |
| `0x1d04ed8` | `0x59fb30` | `0x41d4` |
| `0x1d050e0` | `0x656b80` | `0x41d4` |
| `0x1d05150` | `0x8e81c8` | `0x41d4` |
| `0x1d05158` | `0x779ff0` | `0x41d4` |

Neither this root nor this adapter is a direct exported address. Indirect reachability from an export remains unknown. The IDA memory query for `8e81c8` returns zero facts/notes, without truncation; that is a query result, not evidence that all prior knowledge is absent. The separate 252 B IDA code read at `0x9d3f70` corroborates one candidate region's bytes without resolving its target or field semantics.

## IPC implications and bounded continuation

This increment adds no incoming/outgoing native Mach port or emission site. It composes the existing modeled primary/fallback lookup and cleanup under one more original caller. The 22 daemon children repeat the supplied unchanged-ID rejection; no successful primary reply or client/kext endpoint identity follows.

| Impact | Bounded next question | Discriminating evidence |
| --- | --- | --- |
| High | Which upstream routines construct the root record, particularly fields +16, +20, +24 and +32? | Resolve the three remaining candidate reaching loads, then trace original stores and their source epochs; shared IA diversity alone is insufficient. |
| High | Which original producers consume the adapter's external output and distinguish it from record/X0 results? | Establish a caller-specific pointer and postcall use; include deltas differing by 65536 as a collision control. |
| High | Does an upstream input produce a nonnull optional-input pointer in the coherent cold path? | Connect an actual producer to the [cold seed/context frontier](corefp_cold_seed_report.md) before interpreting the stopped optional read. |
| Medium | Is root selection invariant under admitted image-state changes? | Prove bank-selector cancellation over the actual state domain; these finite cold executions do not establish that theorem. |
| Medium | Can the recorded daemon and kext contracts be joined in one matched image/epoch? | Establish request translation and right/connection lineage across both sides, rather than infer pairing from matching names or local stores. |

## Verification and quality gates

Independent replay checks 25 initial CPU frames, 6328320 B of initial touched RAM, 92184 original client visits, 19505 reads, 10374 writes, 1450 PAC models, 437 API/model events, 150 frozen points, 100 handoffs, 50 lock events, 100 adapter points, 27 bootstrap calls and 23 certificate-allocation attempts. It compares 6328320 B of final RAM and all 25 outer returns. The frozen independent daemon driver checks 22 rejection children / 814 original daemon visits; it does not replay complete daemon CPU/RAM.

The source inventory retains 22 complete compiler functions/import stubs, totaling 121572 B. Six UNSAT certificates and 28 exact instruction checks support the compact local contracts; 828 code bytes and an eight-byte decoded pointer are checked against IDA. Full original `__text` is independently scanned for the stated literal-call pattern. Publication checks decoded archives, the manifest delta, original-input preservation, dependency hashes, local links and path hygiene, including retained RAM payloads and commit metadata.

For the producer/auditor, a conservative time/space upper bound is O(C*(B+P*F+V*J+R)), where C is profiles, B retained/source bytes, P touched pages, F original fixups, V visits, J journal records and R retained RAM. Per-page reconstruction scans fixups; reaching-load searches can scan journals. Each client run is bounded to 30000 visits, each daemon child to its frozen bound, and each solver query to 30 s. This is not a native performance estimate.

- **QG1**: Factual technical analysis; no normative premise is needed.
- **QG2**: RA1-RA8 enumerate assumptions, dependent claims and falsification probes.
- **QG3**: Adapter ABI, coherent failure composition and bounded caller census are covered. The full investigation remains incomplete.
- **QG4**: Byte extents, u32/u64 wrap, low16 truncation, 16 B alignment and conservative complexity are explicit and reproducible.
- **QG5**: Direct-root/internal/external words, raw record marker, X0, pointer representations and periodic output collisions are distinguished. Native and successful-path questions remain explicitly unknown.
- **QG6**: Original images/fixups, independent replay, exact instruction checks, solver queries and IDA readback are retained as separate evidence classes.
- **QG7**: Impact-ranked continuation is bounded by concrete missing producer, consumer, state and cross-level lineage evidence.
