# Boot-state logging handoff and nonzero timer return

Subsequent evidence: the [original early-main signing case](kernel_main_pointer_signing_report.md) preserves this frozen modeled regression and replaces its walker return model with 306644 original helper visits, 1845 signer calls and 6362 pointer stores. The projected instruction/read/write streams and complete final private state match this case; two other models and native lifecycle/transport limits remain.

Eight words from the returned private boot initializer now reach a separately declared main/startup case. The original logger reads the real root header instead of the retained poison value, the original outer printf returns, a console wrapper invokes logging again, and the nonzero timer initializer returns to main at `0xfffffe000c639e40`, before its CPU-initializer BL. The case executes 515187 source visits, emits two 47 B messages into private ring storage and produces thresholds of 24000 and 2400 ticks. This is conditional image-state composition: the inherited registration and selector returns remain models, six address-range words remain poisoned, and no continuous cold entry or native FairPlay transaction is established. [BH-A1-BH-A7]

```text
published returned boot image, exact page-digest hydration
  -> existing declared startup fixtures
  -> eight boot words take precedence before main starts
  -> main loads header as module-walker model argument
  -> 1029 original registry callbacks return
  -> first logging join and 47 B ring message
  -> real root header filetype read -> image lookup returns zero
  -> outer printf returns
  -> console-wrapper flag gate -> second logging join/message
  -> nonzero threshold conversion and timer initialization
  -> main at c639e40, before CPU-initializer BL

frozen poisoned case: still stops before the first header dereference
```

Primary evidence is original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [source/state checks](triage_evidence/kernel_boot_logging_handoff_checks.json.zst), [independent audit and case](triage_evidence/kernel_boot_logging_handoff_audit.json.zst), the published [returned boot case](kernel_boot_initializer_execution_report.md) and the frozen [poisoned logging case](kernel_early_logging_execution_report.md). The [recovery](triage_evidence/recover_kernel_boot_logging_handoff.py), [producer](triage_evidence/probe_kernel_boot_logging_handoff.py), [independent replay](triage_evidence/replay_kernel_boot_logging_handoff.py), [audit](triage_evidence/audit_kernel_boot_logging_handoff.py) and [delivery verifier](triage_evidence/verify_kernel_boot_logging_handoff_delivery.py) reproduce this increment. Original inputs and prior evidence JSON remain unchanged; no IDB was queried or changed.

The capture preserves 200 predecessor bodies and adds three bodies, for 203 functions / 16990 words / 67960 B. The additions contain 295 words / 1180 B. Original symbols identify `0xfffffe000c5e73a4` as `_kprintf` in `com.apple.kernel` (`n_type=15`, section 18). Exact names for the lookup and range-membership helpers are unknown; their recovered roles follow the source and concrete calls. [BH-A1-BH-A3]

| Source | Recovered interface / qualification |
| --- | --- |
| `0xfffffe000c639a94` / `0xfffffe000c639a98` | Main loads primary header and passes it in X0 to the early module-signing walker; this case retains its no-RAM return model |
| `0xfffffe000c48fc90` / `0xfffffe000c48fc98` | Logger loads primary header and reads u32 filetype at header+12 |
| `0xfffffe000c478d18` | Address-to-image lookup: indexed interval table, three kernel ranges, fallback module list |
| `0xfffffe000be763b4` | Membership test against the same three base/length pairs |
| `0xfffffe000bd64f70` | Observed return from the original outer printf to timer initialization |
| `0xfffffe000c5e73a4` | Console/diagnostic wrapper with flag-gated DAIF/locking branch and common logging call |
| `0xfffffe000bd64fd8` | Nonzero-threshold 16 B vector store to `0xfffffe000ca921c8` |
| `0xfffffe000c639e40` | Original timer return to main; CPU-initializer BL not executed here |

The returned boot image is hydrated from original bytes, the corrected format-8 fixup view and the eight actual published values retained by the complete boot CPU case. All 4967 previously mapped boot pages are rehashed against that case's final page digests. A later requested page outside that set must contain neither a fixup nor one of the published words, so its raw bytes are unchanged by the qualified boot transformation. This establishes exact byte custody under the published logical-PAC case; it does not reconstruct native signature bits. [BH-A1-BH-A3]

Startup retains its original declared private RAM, tree, input arguments, initialized destinations, poisoned regions and logical system-register premises. Those fixture records execute in their original order. Eight additional initialization records then restore the boot words, before the first main instruction. Their 64 B domain is exactly `0xfffffe0007f8b528`, `0xfffffe0007f8b548`, `0xfffffe0007f8b568`, `0xfffffe0007f8b5a8` and the four u64 words at `0xfffffe0007e6d160..0xfffffe0007e6d178`. Each replaces eight `0xa5` bytes. An additional 16 B destination at `0xfffffe000ca921c8` retains original bytes before main and makes its later original store observable. No memory is repaired during execution. This precedence policy is an explicit new initial-state premise across separate boot/main call frames. It does not claim that the fixture overrides themselves were produced by native boot. [BH-A2-BH-A4]

| Comparison against frozen poisoned case | Exact result |
| --- | --- |
| Identical source prefix | 510723 visits |
| Identical prefix stores / private RAM / system / vectors | All |
| Header-read value changes | Two u64 reads, both at slot `0xfffffe0007f8b528` |
| Changed read PCs | `0xfffffe000c639a94`, `0xfffffe000c48fc90` |
| Changed boundary GPR at old stop | X8 only: poison becomes root header |
| Inherited API-result model changes | No new result model; module-walker argument X0 changes to root header |
| Registry callbacks preserved | All 1029 entries and returns |
| Old mapped-page comparison | Exact after masking the declared 64 B boot-word domain |
| Additional new-case source visits | 4464 |

Both changed reads return bytes `0040000700feffff`, the little-endian root header `0xfffffe0007004000`, in place of `a5a5a5a5a5a5a5a5`. The main load supplies that pointer to the modeled call at `0xfffffe000c47cce0`; its other seven arguments, result, register clobbers and no-RAM premise remain exact. Actual execution of the already recovered [module-table signer](kernel_initializer_pointer_signing_report.md) is therefore still required for that particular early-main call. The later header dereferences at `0xfffffe000c48fc98` both read `0x0000000c` from `0xfffffe000700400c`. The source compares filetype against 12 and enters its address-to-image lookup arm. [BH-A3-BH-A5]

The lookup canonicalizes X0 by sign-extending input bit 55 and replacing its low 47 bits with input bits 0..46. A nonzero u32 count at `0xfffffe000cba2638` admits a locked search of 24 B interval records through the pointer at `0xfffffe000cba2640`. A record has start/end at +0/+8 and an object pointer at +16; admission uses the unsigned half-open interval start <= address < end. The candidate chain follows record+16, object+32 and next-object+80. The source success tail subsequently loads a header value at an unaligned +156 field. Those populated-table paths are source observations/local obligations; the concrete case has count zero and skips the table lock/search. Object type, populated-table lifetime and native synchronization remain unknown. [BH-A1, BH-A3, BH-A5]

| Kernel range | Base u64 slot | Length u64 slot | Concrete premise |
| --- | --- | --- | --- |
| 1 | `0xfffffe0007e6d9c8` | `0xfffffe0007e6dad8` | Both remain `0xa5a5a5a5a5a5a5a5` |
| 2 | `0xfffffe0007e6daf8` | `0xfffffe0007e6daf0` | Both remain `0xa5a5a5a5a5a5a5a5` |
| 3 | `0xfffffe0007e6dae8` | `0xfffffe0007e6dae0` | Both remain `0xa5a5a5a5a5a5a5a5` |

Each range test uses unsigned base <= address < `(base + length) mod 2^64`. These are different globals from the four root-range words published by the boot initializer. Their actual producers have not been composed. With the retained poison values, the end wraps to `0x4b4b4b4b4b4b4b4a`; the queried kernel addresses fail membership. A null fallback-list pointer at `0xfffffe000cb51b00` then selects zero. The captured fallback source uses 136 B records, address/size fields at +80/+88, a thread-aware lock protocol and slow-path calls; this case skips that traversal because the pointer is null. No conclusion about a populated native module registry follows from these zero results. [BH-A3-BH-A5]

| Original query | X0 input | Return |
| --- | --- | --- |
| First address-to-image lookup | Format address `0xfffffe0007052b8b` | Zero |
| Kernel-range membership helper | Caller PC `0xfffffe000bd64f70` | Zero |
| Second address-to-image lookup | Format address `0xfffffe0007052b8b` | Zero |

The outer printf returns to `0xfffffe000bd64f70`. The timer then calls the console wrapper at `0xfffffe000c5e73a4`. Source tests bit 0 of bytes `0xfffffe0007f8b640` and `0xfffffe0007f8b641` to bypass its DAIF/locking branch. That bypass belongs to the inherited fixture profile; native flag initialization is not established here. Its common logging call reaches the early logging block again. Both joins have phase 3, satisfy the previously proved phase-below-19 relation and leave DAIF absent from the logical system map. Each contracts the same nine original words under that relation; 18 words are contracted across two joins. No new system-register value or callback-result model is supplied. [BH-A2-BH-A5]

Both messages are `[  203.613264]: Longterm timer threshold: 1 ms\n`, 47 B each. Independent integer timestamp calculations from each join's recorded stamp/timebase match every character callback. Original stores produce 94 ring bytes and advance the ring index from 0 to 94 within capacity 131072 B. Both sets of logging calls return. The ticket word advances to `0x02020144`, ownership clears and preemption count returns to zero. Entry, post-format and fallback counters are checked separately. These are private ring writes and call effects, not native console delivery or Mach-port emissions. [BH-A3-BH-A5]

The completed nonzero timer path converts 1000000 ns using the declared source-produced 24000000 Hz timebase:

```text
1000000 ns * (24000000 ticks/s) / (1000000000 ns/s)
  = 24000 ticks
24000 ticks / 10 = 2400 ticks
```

Both are exact integer results in this case. The u64 pair is stored at `0xfffffe000ca92100` / `0xfffffe000ca92108`. The subsequent original timer/self-link/lock/callback and auxiliary conversion stores are compared against independent formulas over the complete declared global regions, including the new 16 B destination. The callback pointer and its logical PAC operands are retained by replay; the callback is not invoked. The boundary is main at `0xfffffe000c639e40`, immediately before a later CPU-initializer call, rather than a return from all of main. [BH-A2-BH-A5]

Fifteen new nonvacuous QF_AUFBV obligations cover filetype gating, canonicalization, null/count/list gates, zero-result publication, range bounds, table interval/object-chain relations and console flag gates. Five retained logging relations are rederived from the same captured bytes. The symbolic model adds signed bit extraction explicitly; concrete replay still executes the original SBFX/BFXIL instructions. Local obligations do not prove arbitrary registry admission, pointer ownership or malformed-metadata safety. [BH-A1-BH-A5]

Independent replay checks the complete new source/read/write sequence, logical transfers, API-model inputs/results, callback journals, both joins, consumer/printf-return checkpoints, GPRs/SP/NZCV, vectors, system map, private RAM and every final mapped page. The implementation imports no new producer executor. Two original-word NOP controls remove the header-filetype load or lookup zero-result assignment. Both retain the same logical initial bytes/registers/fixtures; positive original pages are eagerly mapped before each control to align the recorded page domain. The first takes the wrong filetype branch; the second returns a nonzero value despite empty registries and failed ranges. Both are rejected at explicit discriminating boundaries and retain compact journal digests. [BH-A3-BH-A5]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_boot_logging_handoff_checks.json` | faab8273afb0f7f79132ec2aed42844a4e51513a44ca72b81f5ea7247abb4d3b |
| `kernel_boot_logging_handoff_audit.json` | 22a13863ece092e9641c0893cb5cf804ec80992eedc08aa3c15e523be21cf70d |

No new incoming/outgoing Mach right, message ID or port-emission site is established. The new architectural touch points are primary-header consumption, module-image lookup/range classification, repeated early logging and nonzero timer publication. The full daemon/provider/kext interface goal remains active. [BH-A6-BH-A7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BH-A1: Pinned original collection and frozen dependencies define source/data | Names, addresses and helper layouts | Rehash all captured bodies and raw records; reject input/dependency drift |
| BH-A2: Published logical boot execution and source proof semantics define transferable bytes | Boot-word custody, local relations, PAC/join treatment | Rehydrate all 4967 page digests and rederive 15 new/five retained queries; native signatures and cold entry unknown |
| BH-A3: Explicit fixture order, private frames and logical system values define the new case | Prefix comparison and completed timer path | Compare every predecessor prefix event/state with the exact declared deltas; fresh independent replay |
| BH-A4: Nine added pre-entry records represent precedence and destination tracking | 64 B handoff plus 16 B timer destination | Preserve prior fixture records in order; verify original destination bytes and no mid-execution repair |
| BH-A5: Empty registries, poisoned range pairs and inherited console flags bound this profile | Three zero query results, two ring messages and timer completion | Source range formulas, full-global oracle and both rejected mutations; populated/native lookup outcomes unknown |
| BH-A6: Registration/selector returns remain inherited models | Early-main module-walker argument and continuity limits | Exact one-argument delta with unchanged results; replace walker model with original signing execution in a separate composed case |
| BH-A7: Private logging/timer return is not native transport | Mach and full-goal limits | Establish actual rights/messages/statuses and callback lifecycle across matched epochs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Execute the actual early module walker/signing call with this boot header | Replace its no-RAM model, account for all table stores and exact call/frame custody |
| High | Recover and compose the three kernel-range producers and module registry population | Original writers, initialization order, byte ownership and populated-query witnesses |
| High | Continue main from the CPU-initializer BL | Original caller admission, per-CPU/system effects and subsequent callback phases |
| High | Join FairPlay class lifecycle and daemon/provider/kext transport | Constructor invocation, object/port identity and matching transaction evidence |
| Medium | Qualify console flag and DAIF branches | Actual flag producers, native interrupt/lock ownership and delivery effects |

Recovery and page hydration are O(collection + source + mapped-page bytes). Continuous execution/replay and event/global comparisons are O(V+R+W+P); retained semantic API timelines sort O(J log J). Storage is linear in journals, mapped pages and private RAM. Solver search is separate with a 30 s query limit. This increment rebuilds the later case and consumes digest-bound prior boot results; it does not claim another execution of the 43400376-visit boot initializer.

**QG1**: Factual technical analysis; no normative content required. **QG2**: BH-A1-BH-A7 state dependencies and falsification probes. **QG3**: Conditional boot-image handoff, exact prefix changes, original consumers/helpers, repeated logging, timer return and transport limits covered; full goal active. **QG4**: Widths, 24/136 B layouts, 64/16 B domains, modular bounds, visits and tick conversion explicit. **QG5**: Source-produced bytes/fixture overrides, actual calls/modeled returns, local proofs/concrete execution and private/native effects distinguished. **QG6**: Pinned bytes, complete replay, independent global formulas, predecessor comparison and mutations retained. **QG7**: Impact-ranked bounded continuation included.
