# Operation 1/5 middle-span staging and hardware-provider handoff

The operation 1/5 middle-span path stages 16 bytes from working context `P+0x134`, copies that window into a working IV buffer, and calls `performHWAESOnBuffer` with `P+0x184` as the opaque key-data pointer. The exact nominal provider symbol identifies `IOAESIV *` and `IOAESKeyData *` argument roles. Both operations supply numeric `IOAESOperation` value 1 on this path; its public enum meaning and the operations' public names remain **unknown**. [HS1-HS8]

The source copies middle-span chunks through the cached global byte pointer, capping each copy at 81920 B. The hardware wrapper receives the saved **total** middle-span count, not the current chunk count. Those are distinct source contracts. Actual descriptor capacity, provider validation, device effects, successful cryptography and daemon request lineage remain **unknown**. This analysis does not infer an accepted native extent or a native failure from that count difference. [HS2-HS8]

[Evidence](triage_evidence/lskd_hardware_staging_checks.json.zst), [extractor](triage_evidence/recover_lskd_hardware_staging.py) and [publication audit](triage_evidence/verify_lskd_hardware_staging_publication.py) retain 12 spans / 312 instructions / 1248 B and 17 original authenticated slots. Thirty-six UNSAT obligations cover 33 source pieces / 12986 lifted instruction instances; four bank cuts account for 12800 instances and exhaust all 1024 low-byte inputs with arbitrary upper24 bits. One SAT control separates low32 result testing from full64 nonzero. No provider, target or IDB operation executes. No new Mach-port acquisition, message emission or right transfer is established; the recovered touch points are frame/global memory, kernel copy calls and a provider virtual method.

```text
full-split operation: B = (low32(original X4) & ~15) - H >= 16
  A518008 -> A5722B8
    P+134 -- 16-byte helper --> bodySP+280
    saved continuation 12c -> A55A878 -> A54A9E0
    bodySP+280 -- memcpy(16) --> bodySP+270 [working IV]
    P+184 -> saved key-data pointer
    initialized flag SP+6c == 0 -> A526A20, offset p=0

  loop:
    C = min(B-p, 81920)
    prepared_source+p -- memcpy(C) --> cached global bytes
    performHWAESOnBuffer(P+184, bodySP+270, B, 1)
      -> nominal IOAESAccelerator::performAES [external effect open]
    nonzero wrapper W0 -> private failure -> finish
    zero wrapper W0:
      cached global bytes -- memcpy(C) --> prepared_destination+p
      p += C; p<B -> loop; otherwise -> private zero -> finish

  finish A591E64 -> saved A527B24 -> re-encoding/release/result route
```

Address suffixes and field offsets are hexadecimal; byte counts are decimal. The diagram describes source control/data flow under the following premises, not a native transaction.

## Assumption register and primary provenance

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| HS1 | Pinned original KC and normalized image identify the selected build | Instructions, constants, bank bytes, slots and symbols | Rehash retained spans; independently decode original fixups; match the native image separately |
| HS2 | Prior preflight, byte-span, context-return and reader-lineage template/frame identities apply | P, prepared pointers, B, body SP/FP, phase and bank roots | Replay frozen obligations; bind actual reaching caller/frame and original argument epochs |
| HS3 | Source scalar, unsigned conditions, modular32/64 arithmetic and fixed-cell semantics describe retained instructions | Counts, dispatch, argument and status certificates | Regenerate fail-closed lifts and replay queries; compare independent instruction/register audits |
| HS4 | Context, control storage, the designated frame data windows and borrowed ranges are accessible with the required nonaliasing/nonwrapping bounds | Context-window copy, IV staging, source/copyout arguments | Check actual backing and aliases; verify the frame data windows do not overlap live control cells |
| HS5 | Calls return under the AArch64 ABI and preserve required callee-saved registers and relevant frame/global identities | Loop composition, zero control flag and finish selection | Inspect callee effects and aliases; clobber caller-saved registers in a separate execution experiment |
| HS6 | Original provider/descriptor/cached-byte globals and nominal vptr describe the intended object epoch | Typed provider handoff and global-buffer role | Match live class, slots, descriptor length/capacity, backing and ownership; static globals do not prove coherence |
| HS7 | External memcpy follows its copy contract; provider effects/results remain unspecified; normal guard/PAC, cached release and D=0 premises hold for the final return | IV bytes, completed copied ranges and conditional outer status | Recover actual API completion and mutation contracts; verify cursor/guard/PAC and lock epochs separately |
| HS8 | Each copied pass has its own entry snapshot; complete overlap, crypto and daemon transport are outside these cuts | Interpretation/completeness limits | Join all passes with actual alias and serialization constraints; recover the named wrapper's daemon-facing caller |

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. All retained bytes match both sources. Supplied C lines 98474-98515 and 69081-69175 corroborate the context-window and initial-copy blocks while omitting source register/memory semantics. The original three supplied inputs remain unchanged. [HS1-HS3]

The provider wrapper matches the frozen [four-wrapper source](triage_evidence/kext_aes_handoff_contracts.json.zst). Original KC nlist supplies the exact `IOAESAccelerator::performAES(IOMemoryDescriptor *, IOMemoryDescriptor *, unsigned long long, IOAESIV *, IOAESOperation, IOAESKeyData *, unsigned long long, unsigned long long, void (*)(void *, int), void *)` type sequence. This establishes parameter roles, not private structure extents or valid key material. [HS1,HS6]

## Context window, frame layout and dispatch

The prior frame relation is FP=bodySP+0x340. At `a5722bc`, `SUB X15,FP,#0xc0` therefore selects bodySP+0x280. Source sets encoded count `C0-16`, with `C0=0xc9e6da8e97b74733`, and preserves source X14=P+0x134. The established phase/pointer/copy chain decodes a 16-byte pass and preloads `TABLE[12c] -> a55a878`. The previous bounded helper certificate covers length 16 in both source-selected directions; application here uses the designated frame data window and requires its separation from control storage. [HS2-HS5]

| Location | Width / extent | Recovered role / source |
| --- | --- | --- |
| P+134 | 16 B | Source IV window, staged by A5722B8; ends immediately before state word P+144 |
| bodySP+280 | 16 B | Context-window snapshot, FP-c0 |
| bodySP+270 | 16 B | Working IV passed to the hardware wrapper, FP-d0 |
| bodySP+60 | 8 B | Saved working context pointer P |
| bodySP+a0 | 8 B | P+184, opaque key-data pointer; pointed structure size unknown |
| bodySP+120 | 4 B | Saved total middle-span byte count B |
| bodySP+6c | 4 B | Control flag initialized to zero at A518008 |
| bodySP+78 | 8 B | Saved final continuation A527B24 |

The nonzero B gate selects `TABLE[87e] -> a54a9e0`; zero selects `850 -> a591e64`. The earlier full-split arithmetic proves B>=16, so zero is not the selected full-split case. A54A9E0 calls memcpy with `(bodySP+270,bodySP+280,16)` at `a54aa64`, then selects `906 -> a526a20` when the initialized control flag remains zero. A nonzero flag selects `8c8 -> a50fad0`, an alternate frontier whose complete semantics are not certified here. [HS2-HS5,HS7]

## Copy sites and hardware ABI

All four byte-bank source cuts resolve their target independently of controller low-byte values. B-bank frame roots come from the reader-lineage certificate, E-bank roots from that certificate plus the context-return certificate, and G-bank roots from the post-flag frame stores. Original chained metadata retains all selected targets. [HS1-HS3,HS5]

| Call instruction | Resolved target | Source arguments |
| --- | --- | --- |
| a54aa64, BLRAA / 1103 | a508cf4, memcpy/memmove thunk | dst=bodySP+270, src=bodySP+280, count=16 |
| a526aa0, BLRAA / 1103 | Same thunk | dst=*CCC7848, src=prepared_source+zero_extend32(p), count=C |
| a526b00, BLRAA / e246 | a5083d8, performHWAESOnBuffer | key=P+184, IV=bodySP+270, count=B, operation=1 |
| a5366d0, BLRAA / 1103 | Same copy thunk | dst=prepared_destination+zero_extend32(p), src=*CCC7848, count=C |

The copy thunk is `BTI C; B a69f334`. That stub branches through original slot `0xfffffe000847c4c8` to `0xfffffe000c647f10`, where exact kernel aliases `_memcpy` and `_memmove` share the address. This identifies the API binding. It does not newly execute or reconstruct that implementation. [HS1,HS7]

The hardware wrapper loads provider cell `0xfffffe000ccceb08` and descriptor cell `0xfffffe000ccceb10`. Under nominal provider vptr `0xfffffe0008588380`, virtual +0x890 selects original slot `0xfffffe0008588c10`, target `0xfffffe000abff358`. Authentication modifiers are retained as source metadata; no hardware authentication or dynamic-class match is claimed. [HS1,HS6]

| performAES ABI at call a508440 | Source value |
| --- | --- |
| X0 | Provider global value |
| X1, X2 | Same descriptor global value twice |
| X3 | zero_extend32(B), total middle-span bytes |
| X4 | bodySP+270, typed IOAESIV pointer |
| W5 | Numeric operation 1 |
| X6 | P+184, typed IOAESKeyData pointer |
| X7 / SP+0 | Source/destination offsets 0 / 0 |
| SP+8 / SP+16 | Completion callback/context NULL / NULL |

Unlike the separate `performHWAESOnGlobalBuffer` wrapper, this wrapper forwards the operation without XOR 1. The IV pointer is reused across chunk iterations; provider-side mutation and its chaining meaning remain unknown. No context writeback of the IV window is established by these retained caller cuts. [HS1-HS3,HS6-HS8]

## Loop, pointer preparation and status

For 0<=p<B, with B and p divisible by 16, source selects C=min(B-p,81920). The certificate proves 0<C<=81920, C divisible by 16 and p<p+C<=B without u32 wrap. Thus the copy-counter schedule terminates after ceil(B/81920) iterations if every call returns and the saved total/offset values persist. Its target work is O(B) copied bytes plus O(ceil(B/81920)) external submissions; hardware work is unspecified. Auxiliary target storage is fixed-size frame/global storage. [HS3-HS5,HS7]

The total count B is preserved in W27 and passed to the hardware wrapper on every iteration, while W22 supplies C to the copy calls. The source does not replace B with C or B-p at a526af4. The earlier initialization requested nominal capacity 81920 B, but this certificate does not match an actual descriptor/backing epoch or establish the provider's accepted count domain. Reconciling submission count, descriptor validation and copy range is a remaining high-impact interface question. [HS3,HS5-HS8]

Copyout pointer preparation tests whether adding p changes any bit selected by `0xffc0000000000000`. If so, it replaces high16 bits with `0xc8a2`; otherwise it uses the sum. This is an exact source branch, with native pointer/tag/authentication interpretation unknown. The source/copyout pointer-validity premises must cover that prepared result. [HS3-HS4,HS6]

The provider wrapper tests W0, returns numeric zero when it is zero, and otherwise returns `0x00000000ffffffea` after its returning logging call. Raw nonzero provider codes are collapsed to signed32 -22. The chunk caller selects private `0x06371eb6` on failure and private `0x06371ecc` after successful copyout. A591E64 reloads phase and the saved final continuation without replacing W21. The prior return path then stores conditional outer u32 `0xffffffea` or `0`, respectively. [HS3,HS5,HS7]

Prefix/suffix copies precede this middle path. Earlier successful middle chunks also precede a later failure. No rollback or atomic-output contract is established, and no complete-operation overlap guarantee follows from the earlier per-pass copy proof. [HS7-HS8]

## Reproduction, bounded follow-up and quality gates

The extractor's `--verify` regenerates exact source certificates. The publication audit replays 36 new and 221 prior UNSAT obligations, one new and five prior SAT controls, checks original bytes/fixups/nlist and frozen wrapper equality, independently audits register/call boundaries, and validates the manifest delta and path scrub. Source/expression work uses O(N+I+256R) time/space for consumed source/index bytes N, instruction instances I and bank rules R; SMT solver cost is separate. Counts and widths are explicit in bytes; arithmetic is modular32/64 except stated bounded mathematical relations.

| Impact | Bounded follow-up | Discriminating evidence |
| --- | --- | --- |
| High | Reconcile hardware total count and copied chunk count | Provider descriptor validation, native capacity/backing and actual caller count domain |
| High | Recover the operation's public caller and daemon linkage | Original wrapper callers, IOKit serialization, argument lineage and returned-status consumers |
| High | Establish provider buffer, IV and completion effects | Actual provider class, synchronous/completion contract, IV updates and resulting copyout bytes |
| High | Establish serialization and whole-operation aliases | Shared-buffer lock epoch, concurrent users and one snapshot across prefix/suffix/middle passes |
| Medium | Recover alternate nonzero-control-flag route | Reaching writers of SP+6c and A50FAD0 effects; keep it separate from the initialized-zero route |
| Medium | Establish key-data structure and lifetime | P+184 producers, structure extent, ownership and provider field reads |
| Low | Compare same-target dispatch aliases | Slot-specific authentication diversities and caller phase requirements |

**QG1**: No normative claim is required. **QG2**: HS1-HS8 specify assumptions, dependencies and falsification probes. **QG3**: The increment covers context/IV staging, chunk-copy arguments, hardware ABI, loop and conditional status; complete native transport and crypto remain open. **QG4**: Byte units, widths, truncation, bounded count arithmetic and algorithm costs are explicit. **QG5**: Total versus chunk counts, context versus frame windows, API versus native effects, alternate flag route and partial-output possibilities remain distinct. **QG6**: Original source, chained pointers, exact nlist, supplied C, frozen certificates and reproducible queries provide primary provenance. **QG7**: Impact-ranked continuation bounds remaining data, control, environmental and architectural interfaces.
