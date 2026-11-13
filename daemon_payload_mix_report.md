# Daemon payload-driven first mixing pass

Current generated-stream increment: The [complete generated-stream report](daemon_generated_stream_report.md), following the second-pass and first-output increments, establishes actual downstream use of this payload-dependent initialization: complete32 B output, repeated full-state refills and a caller arena copy before private overwrite. The explicit status-pointer mismatch and inherited epoch limits remain; native transport pairing is unknown.

The warm arena path reaches a complete 624-iteration state-mixing pass. Three payload words, the payload address and overlapping source-text bytes determine four repeating XOR masks on a private 16 B key record. Every key word undergoes 156 mutations and returns to its initial value; the 2496 B generator state changes. The recovered equations describe the pass compactly, and two source executions retain every intermediate state. The next stage begins at `0x100abba18`; its execution and eventual Mach/IOKit use remain unknown. [PM1-PM5]

```text
inherited arena + entropy/clock returns + first iteration
  -> G[624 u32], private key[4 u32], i=2, j=1, remaining=623
  -> mix G[i] with G[i-1], key[j], j
  -> increment i; at 624: G[0]=G[623], i=1
  -> increment j modulo4
  -> key[j] XOR= fixed mask[j]
     j=0: low32(payload address)
     j=1..3: payload word + address + source-text decoder
  -> decrement remaining
     nonzero -> repeat
     zero -> original authenticated transfer -> 0x100abba18
```

| Evidence | Primary artifact and boundary |
| --- | --- |
| PM1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_payload_mix.py) retains source regions, fixups and packed full-state intervals. |
| PM2 | [Arena split report](daemon_arena_split_report.md), [checks](triage_evidence/daemon_arena_split_checks.json.zst) and [audit](triage_evidence/daemon_arena_split_audit.json.zst): source-filled payload, conditional warm caller state, imported return premises and the first mixing iteration. |
| PM3 | [New checks](triage_evidence/daemon_payload_mix_checks.json.zst): two parents, each with 623 further iterations and two final-exit intervals; no new API returns or memory bytes are supplied. |
| PM4 | [Independent auditor](triage_evidence/audit_daemon_payload_mix.py) and [audit receipts](triage_evidence/daemon_payload_mix_audit.json.zst): original opcode/state replay, complete array/key comparison after every iteration, comparison-record decoding and eight nonvacuous obligations. |
| PM5 | [Clock/comparison report](daemon_clock_record_report.md): private comparison-leaf representation and separately declared clock fields; the new audit rechecks each actual call record. |
| PM6 | [Publication verifier](triage_evidence/verify_daemon_payload_mix_publication.py): source/dependency pins, packed receipt integrity, exit-load provenance, manifest delta, preserved inputs and raw/typed/decoded path hygiene. |

## State, recurrence and source locations

G=`0x1010c784c` is an array of 624 little-endian u32 words:624*4 B = 2496 B. Q=SP+`0x220`=`0x680005ff00` is the private four-word key record. P=`0x650011521c` is the 64 B payload returned from the inherited 88 B arena reservation. These placements belong to the source model; native allocation ownership is not established. [PM1-PM4]

The initial key record before the inherited first iteration is `[0xffffffff,0,0,0]`. At the new extraction boundary, key1 has already been XOR-mutated to `0xb50bf7c4`. Parent cases 0 and 7 use initial expansion returns 0 and`0xffffffff`, respectively, and different retained ABI clobber profiles. Both declare zero clock fields, a subsequent random word 0 and a final random word`0xffffffff`. Their caller/controller, arena-header and imported-return premises remain inherited. This increment supplies zero additional bytes and executes zero native target APIs. [PM2-PM4]

For each mixing iteration, using modulo2^32 arithmetic:

```text
G[i] = u32((G[i] XOR u32((G[i-1] XOR (G[i-1] >> 30))*1664525))
           + key[j] + j)
i = i+1
if i == 624:
    G[0] = G[623]
    i = 1
j = (j+1) mod4
key[j] = key[j] XOR mask[j]
remaining = remaining-1
```

The full pass starts with i=1,j=0,remaining=624. It visits destination indices 1 through 623 and then1 again. It finishes with i=2,j=0,remaining=0. The inherited report supplies iteration1; the new receipts execute iterations 2 through 624 and the final source exit. A symbolic source obligation covers arbitrary u32 state/key words and valid i=1..623,j=0..3. This establishes the indexed recurrence, rather than fitting an equation to a single output array. [PM1-PM4]

| Source location | Established operation | Extent or condition |
| --- | --- | --- |
| `0x1009c46dc..0x1009c4714` | Indexed mix and i increment | One u32 state word per iteration |
| `0x1009c4808 -> 0x100427514` | Decode comparison623 < incremented i | True at i=624; then reset to 1 |
| `0x100c0bb74..0x100c0bba4` | Copy G[623] to G[0] | Original obfuscated predicate simplifies under wrap indices |
| `0x100c0bbb8` | Set i=1 | State-array wrap |
| `0x100b6bb74 -> 0x100444d6c` | Decode comparison incremented j >3 | True at j=4 |
| `0x100a7d924..0x100a7d970` | Wrapped key0 XOR low32(P) | Source phase/field premises retained |
| `0x100a7d978` | Set j=0 | Key-record wrap |
| `0x100a0769c..0x100a07710` | Nonwrap key-word mutation | j=1,2,3 |
| `0x100aaefc0..0x100aaf00c` | Decrement remaining, select fixup, transfer | Source-selected first-pass exit |

Descriptive roles are indexed first-pass mixer, key-record mutation, state wrap and counter/dispatch. They identify block functions with original addresses; complete function boundaries, native reachability and cryptographic purpose remain unknown. [PM1-PM4]

## Payload/address/text-dependent key masks

For j=1,2,3, let A=P+4*j, w=LE32(payload+4*j), T=`0x100822c80`+4*j and Z be the shared 48-bit source-text word at T. The old-record transform simplifies universally:

```text
u32(r - ((r<<1) AND 0x377b9daa) + 0x1bbdced5)
    = r XOR 0x1bbdced5
```

The source consumer is therefore key[j] XOR delta, where:

```text
delta = u32(low32(A)*0xc40ba787) XOR w
        XOR (phase AND 0xc68e91c5) XOR (flag AND 1)
        XOR 0x1bbdced5 XOR low32(Z) XOR low32(Z>>16)
        XOR 0xe2715a91
```

The symbolic obligation allows arbitrary old record, payload word, address, phase, flag and shared 48-bit text. Sharing Z preserves the two-byte overlap between the 4 B text reads. Every retained nonwrap iteration has phase=3 and flag bit0=0. Under the retained immutable payload/text and fixed P, delta is constant for each j. The wrapped key0 block has its own arbitrary-record/arbitrary-pointer source proof under the observed phase/field premises. [PM1-PM4]

| j | Input read or dependency | Source-text read addresses | Concrete XOR mask |
| --- | --- | --- | --- |
| 0 | low32(P); no payload dereference | None in wrapped key update | `0x0011521c` |
| 1 | LE32(P+4)=`0x622e905c` | `0x100822c84`, `0x100822c86` | `0xb50bf7c4` |
| 2 | LE32(P+8)=`0x966ae4b8` | `0x100822c88`, `0x100822c8a` | `0x07c5f740` |
| 3 | LE32(P+12)=`0x5a26a874` | `0x100822c8c`, `0x100822c8e` | `0xa2674a96` |

The pass dereferences only the12 B payload span[P+4,P+16). It never reads payload word 0 through this decoder; the j=0 update uses the pointer value. The three overlapping text pairs cover 14 unique bytes. The new623 iterations make467 payload-word reads per case; the inherited first iteration adds one, yielding468 reads over the full pass. Payload bytes remain unchanged. These access bounds apply to the retained first pass; subsequent stages may access other bytes. [PM1-PM4]

Across624 iterations, each key position receives156 identical XOR mutations. Since156 is even, every key word returns to its initial value. This restoration does not undo the intervening generator-state updates. The new tail has 155 key1 mutations and 156 mutations for each other position; the inherited first key1 mutation supplies the missing count. The parity identity is proved for arbitrary u32 record and delta. [PM2-PM4]

| Parent case | Initial expansion return | Final key words | SHA-256 of final 2496 B state |
| --- | --- | --- | --- |
| 0 | `0x00000000` | `[0xffffffff,0,0,0]` | `f3de3d308dd01a77e89ebcf99d005d02b6ede0cf32107fc6af12e48d365052de` |
| 7 | `0xffffffff` | `[0xffffffff,0,0,0]` | `552f2570531d73dcd1158d5f340b7728991dc1d585d0be9baa5f1a723f7ecb3d` |

The equal masks and restored keys coexist with different final arrays. The cases vary multiple inherited controls, so this comparison alone does not isolate a native entropy causal effect. It corroborates deterministic recurrence composition under their exact source states. [PM2-PM4]

## Branch records and emitted control transfer

Each new mixing interval calls two private40 B comparison records. The auditor reconstructs source-defined bytes at the actual call time, decodes unsigned64-bit operands and 32-bit mode/result fields, checks the leaf's result store and maps the decoded index through the pinned fixups. Across both cases,623 < incremented i is true2 times and false1244 times; incremented j >3 is true312 times and false934 times. These are internal comparison/dispatch records. They do not establish an externally supplied ABI. [PM3-PM5]

| Remaining before decrement | Resulting counter | Index | Fixup slot | Target | IA modifier |
| --- | --- | --- | --- | --- | --- |
| n!=1 | u32(n-1) | `0x1a22` | `0x101047000` | `0x1009c46dc` | `0x35e7` |
| n=1 | 0 | `0xa559` | `0x10108c9b8` | `0x100abba18` | `0x35e7` |

The arbitrary-u32 counter obligation preserves the wraparound case n=0: decrement yields`0xffffffff` and selects continuation. Retained execution reaches n=1 and takes the exit. Source `0x100aaeffc` loads X9 from the selected table slot, `0x100aaf004` sets X17=`0x35e7`, and `0x100aaf008 BRAA X9,X17` emits the final control transfer. The next interval inherits the exact load origin and complete register state. Hardware pointer authentication does not execute. The final cut precedes the first instruction at`0x100abba18`. [PM1,PM3-PM4,PM6]

## Assumption register

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| PM-A1: Pinned image and fixups identify this specimen | All source semantics and destinations | Check image SHA-256, opcode at every visit and used fixup targets; distinguish logical authentication from hardware PAC. |
| PM-A2: Two frozen parent boundaries apply | First-pass entry and caller reachability | Exact GP/Q/SP/NZCV/known-byte/owner joins to parent cases 0 and 7; native controller/epoch join remains unknown. |
| PM-A3: Parent API-return and clock-field premises apply | Seed array and key entry | Retain the declared returns and unknown clock padding; no new return is supplied in this increment. |
| PM-A4: Fixture compaction preserves all source-known bytes | Resumed full-state execution | Compare byte maps before/after every interval and preserve owner extents; do not convert allocator backing into initialization. |
| PM-A5: Payload/text and P remain fixed during the retained pass | Constant masks and payload access bounds | Check all payload reads, phase/flag values, source text, absence of payload writes and complete key states after every iteration. |
| PM-A6: State indices and wrap fields satisfy the stated domain | Recurrence and G[623] copy | Prove the indexed equation for i=1..623,j=0..3; independently replay the actual state-wrap block and index reset. |
| PM-A7: Full scalar/AdvSIMD lift matches original semantics | Independent replay and source equations | Check all GP/Q/NZCV states, source byte reads/writes and authenticated origins; fail on unsupported operations. |
| PM-A8: Last target load survives the exit cut | Final dispatch provenance | Reconstruct the original indexed load and check exact joined X9, index, modifier and absence of intervening X9 replacement. |
| PM-A9: First-pass completion does not imply routine or transport completion | Cross-layer conclusions | Preserve cut at 0x100abba18; later state transformation, material use, ownership and native daemon-kext pairing remain unknown. |

## Verification and bounded continuation

The new receipts contain 1250 intervals,379704 original instruction visits,68842 reads,22430 writes,11214 logical edges and 2492 internal calls. Independent replay covers complete scalar/vector/flag states and byte effects. The compact recurrence checks 777504 intermediate state words and 4984 key words across 1246 iterations, plus exact parent/intermediate/exit joins and final arrays. Eight nonvacuous obligations pass: six original-source obligations covering recurrence, index, nonwrap mutation, wrapped mutation, state wrap and counter partition, plus two algebraic identities covering affine-to-XOR simplification and even-parity key restoration. [PM3-PM4,PM6]

For N=624 words and K=624 full-pass iterations, the recovered recurrence costs O(K) time and O(N+4) stored words. Full-state validation costs O(K*N) time. Packed extraction/replay adds O(receipt bytes+source visits+byte effects), with per-interval register states and packed receipts retained; JSON decoding uses storage proportional to the largest receipt collection. Each solver query has a 30 s limit. All word arithmetic is modulo2^32; pointers are64-bit; extents/counts are exact. No native API, IPC, malloc/free, concurrent target operation, hardware PAC or IDB mutation executes. [PM1-PM6]

| Impact | Next evidence | Architectural purpose and current boundary |
| --- | --- | --- |
| High | Recover source stage beginning0x100abba18 and subsequent output | Determine complete generator/material semantics and actual downstream use |
| High | Establish a coherent caller/controller/constructor epoch | Frozen metadata and source joins do not prove native reachability or ownership |
| High | Trace completed material into existing Mach/IOKit emission sites | Establish a concrete daemon-kext data dependency before pairing transactions |
| Medium | Compare this key mutation with earlier encoded-key callers | Shared array dimensions/mix coefficient do not prove identical pointer decoding or caller lifetime |
| Medium | Vary P and source-defined payload words under explicit premises | Separate address/text decoding from payload contributions; native relocation and entropy claims remain unknown |
| Low | Add descriptive mixer/key-wrap/state-wrap navigation labels | Preserve original addresses and incomplete function boundaries |

No additional incoming/outgoing Mach port, right disposition, send/receive emission site, UserClient selector or native pairing is established here. Existing [Mach port mappings](mach_ports_report.md) and [ABI mappings](interface_abi_report.md) remain the transport evidence. This report establishes a compact local data-flow predecessor for later correlation. The full interface goal remains active. [PM1-PM6]

**QG1** passes: factual source/interface analysis. **QG2** passes: PM-A1-PM-A9 include dependent results and falsification probes. **QG3** passes for the complete first-pass increment; the full objective remains incomplete. **QG4** passes: widths, modulo arithmetic, exact extents/counts and complexity are explicit. **QG5** passes: restored key words, changed state, inherited first iteration and later unknown stages are distinct. **QG6** passes after pinned source, independent replay, nonvacuous solver, original-input and publication checks. **QG7** passes: bounded continuation covers complete routine, source epochs, representation variation and cross-layer use.

Decoded checks SHA-256: `28c45f52155b22f2e6e30e6864489159e0f87477543a3fe3f0c8761dc9d5b829`. Decoded audit SHA-256: `48e9c204e37cabc3688f1450869bc1e79fc4449348f48bb20eb165bf03e826e2`.

The subsequent [second-pass/gate report](daemon_second_mix_report.md) completes 623 further indexed updates for both retained parents, forces state word0 to0x80000000 and reacquires the same 4 B gate released before entropy collection. Both key and payload remain unchanged. The new cut is before 0x100a3881c; subsequent output use and native pairing remain unresolved.
