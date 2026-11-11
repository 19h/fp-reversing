# Global event-wait table startup and publication

The original collection contains the startup producer missing from the [AES event-registration report](aes_event_registration_report.md). An authenticated startup entry selects a routine that reads the option name `wqsize`, computes a bucket count and allocation extent, publishes a returned root, and initializes 24 B queue records. Their byte+5 bit0 satisfies the earlier registration/wake validity test. This establishes a conditional source initialization contract. Actual startup invocation, successful allocation, publication visibility and a matched live waiter remain unknown. [ET1-ET7]

```text
__BOOTDATA,__init_entry_set: numeric phase 14, rank 0, argument 0
  -> authenticated callback 0xfffffe000c6319e4
  -> option-reader return snapshot
       +-> nonzero W0: use u64 stack output for "wqsize"
       `-> zero W0: derive rounded u32 budget from a global parameter
  -> budget / 24 -> CLZ -> u32 power-of-two count
  -> publish count
  -> allocation call -> return pair W0, X1
  -> publish X1 as root
  -> initialize each 24 B record
  -> initialize a separate global record and remaining callback tail

AES wait/wake -> hash(full event) -> root + 24*index
  -> byte+5 bit0 check -> lower registration/wake interfaces
     [same completed startup and table lifetime required]
```

Evidence: [source and certificates](triage_evidence/event_wait_table_checks.json.zst), [extractor and scalar lift](triage_evidence/recover_event_wait_table.py), [independent byte-memory interpreter](triage_evidence/audit_event_wait_table.py), [publication audit](triage_evidence/verify_event_wait_table_publication.py). Primary collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Reference bytes suffice; no new IDA access is required.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ET1 | The pinned collection, compiler ranges, sections and original chained pointers identify this build. | Rehash and re-decode all five bodies, startup record and selected pointers. No exact nlist name identifies the callback or its two callees. |
| ET2 | Startup dispatch invokes this record with the required surrounding initialization and serialization. | Establish dispatcher ordering, actual phase completion and absence of early readers. Registration alone does not prove invocation. |
| ET3 | The option reader returns the declared W0/output snapshots; the default parameter and option have a valid startup epoch. | Recover the complete parser acceptance language and global parameter writers. A literal option name does not prove external acceptance of every u64 value. |
| ET4 | The selected budget satisfies 24 <= B < 24*2^27 B; table pointers have valid backing, no wrap and stable upper address-region bits. | Check the runtime budget, allocated extent and source pointer-tag guard. Exact modular outputs outside this domain do not establish safe allocation geometry. |
| ET5 | The allocation call returns successfully with usable X1 backing and the recorded ABI. | Establish allocator status, returned extent, ownership and lifetime. The caller enters initialization without testing the returned W0/X0. |
| ET6 | Root/count remain stable through initialization and later wait/wake uses; consumers observe completed record stores. | Correlate startup, table epochs and memory visibility. Neither a publication barrier nor a concurrent-reader exclusion proof is supplied by the selected routine. |
| ET7 | Only original-source semantics, scalar SMT and private finite arrays are evaluated. | Obtain native startup, allocation and same-event waiter/wakeup observations. No target option parser, allocator, scheduler, device, IPC, atomic or IDB operation executes. |

## Startup registration and environmental input

Five complete compiler-bounded functions contain 1,022 instructions / 4,088 B: the callback, option reader, allocator and two event wrappers. The callback's 110 instructions / 440 B are retained in full. Its startup record at `0xfffffe000cbebbf8` is an aligned 24 B entry in `__BOOTDATA,__init_entry_set`; the leading u32 words are 14 and 0, the authenticated format-8 pointer at+8 targets `0xfffffe000c6319e4`, and the final u64 argument is zero. Numeric registration is established. The [startup-dispatch report](startup_dispatch_report.md) recovers the original phase-name literal `mach_ipc`; actual native dispatch remains unobserved. [ET1,ET2]

| Interface / item | Original address | Exact source fact |
| --- | --- | --- |
| Option reader call | `0xfffffe000c631a1c` -> `0xfffffe000c5e48a4` | X0=u64[global `0xfffffe0007f8b6e8`]+0x6c; X1 points to `wqsize`; X2=stack+8; W3=8; W4=0 |
| Output cell initialization | `0xfffffe000c6319f8` | Stack output u64 is zeroed before the call |
| Option-result branch | `0xfffffe000c631a20` | Zero W0 selects default arithmetic; nonzero selects the output u64 |
| Default parameter | `0xfffffe000caa30c4` | Read as u32; file word is 2560, current value and writer epoch unknown |
| Count publication | `0xfffffe000c631a78` | u32 store to `0xfffffe0007e66e00` |
| Allocation call | `0xfffffe000c631ab0` -> `0xfffffe000bdc08e0` | X0=original `_kernel_map` global value; X1=extent; X2=0; W3=0x200103; W4=0x11; X5=0 |
| Allocation return setup | `0xfffffe000bdc1094` / `0xfffffe000bdc1098` | W0 receives W27; X1 receives X26; this does not prove successful allocation |
| Root publication | `0xfffffe000c631ab8` | u64 store of returned X1 to `0xfffffe0007e66df8` |

`_kernel_map` has an exact nlist definition at `0xfffffe0007f860a8`. No unmatched allocator or option-reader API name, flag enum or parameter meaning is assigned. These are startup/environment and kernel-memory touch points; no Mach port or message emission is added. [ET1,ET3,ET5]

## Width-preserving sizing contract

Let T denote the u32 default parameter. All arithmetic below states its source width; B and Q are unsigned u64. The default path computes:

```text
P32 = (T * 24) mod 2^32
D32 = ((floor(P32 / 5) + 16383) mod 2^32) AND 0x7fffc000
B64 = zero_extend(D32)
Q64 = floor(B64 / 24)
C64 = clz64(Q64)                 [clz64(0) = 64]
N32 = 0x80000000 >> (low32(C64) AND 31)
L32 = (((24 << ((NOT low32(C64)) AND 31)) mod 2^32)
       + 16383) mod 2^32
L32 = L32 AND 0xffffc000
```

The source implements division by 5 with a widened multiply by `0xcccccccd` and shift34; division by24 uses the high half of a u64 product with `0xaaaaaaaaaaaaaaab`, then shift4. Certificates prove the source products and the integer Euclidean-decomposition division identities. CLZ is checked over zero and all64 nonzero bit-length intervals. AArch64 variable u32 shifts use the low5 shift-count bits; the exact expressions retain that behavior. [ET1,ET3,ET4]

Under 24 <= B < 24*2^27 B, Q lies in1..2^27-1, C in37..63, and N is the greatest power of two not exceeding Q. The source extent is then exactly `ceil((24*N)/16384)*16384 B`: it covers all records with less than16384 B slack, and N<=2^26 supplies the prior hash path's nonnegative signed32 stride bound. Source alignment is16,384 B; no host or runtime page-size substitution is used. [ET4]

Every default D is16,384 B aligned and <=0x7fffc000 B. A nonzero D therefore lies in the stated budget domain. Nonzero default output is an explicit premise; it does not follow for every u32 T. The override bypasses this default bound, so the budget-domain premise remains separate from parser success. Outside the domain, the retained modular expressions are authoritative; the greatest-power and allocation-coverage interpretations are not generalized. [ET3,ET4]

For the original file parameter2560, the source fallback calculation is reproducible: P=61,440; floor(P/5)=12,288; B=16,384 B; Q=682; N=512; record bytes=12,288 B; L=16,384 B; slack=4,096 B. This is a file-seeded arithmetic example, not a native boot observation. [ET3,ET7]

## Record initialization and readiness boundary

The count store precedes the allocation call. After that call, the root is stored before the first queue record. Within the retained post-call prefix through the record-loop exit, no instruction reads W0/X0; the source branches on the published count and loop index, not on the returned allocation status. Lower allocator failure handling and real backing remain separate evidence requirements. [ET2,ET5,ET6]

For each u64 loop index j<count, the source reloads the root, forms root+24*j, and checks upper address-region equality before the selected unmodified-pointer store path. A failed guard replaces the pointer's upper16 bits with0xc8a2; the contract here assumes the guard succeeds. Records are not reached through the signed32 hash-address construction during initialization. [ET4,ET6]

| Record offset | Final bytes / value | Original stores |
| --- | --- | --- |
| +0..+3 | u32 9 | u64 seed9 store at `0xfffffe000c631af0` |
| +4..+7 | u32 0x144 | u32 store at `0xfffffe000c631af8`, overwriting the upper half of that seed |
| +8..+23 | 16 zero bytes | paired u64 stores at `0xfffffe000c631af4` |
| +5 bit0 | 1 | Derived from the final little-endian 0x144 field |

The complete24 B record is `090000004401000000000000000000000000000000000000`. The registration wrapper checks byte+5 bit0 at `0xfffffe000bd6e004` / `0xfffffe000bd6e008`; wake checks it at `0xfffffe000bd6e24c` / `0xfffffe000bd6e250`. Passing this guard does not establish lock state, thread admission, nonempty membership or successful wakeup. [ET4-ET6]

The initially chained root points to `0xfffffe000cbca628`, whose zero prefix was recorded previously. The recovered callback replaces that root with returned X1. Thus the zero file prefix and later initialized records describe different source states. The callback also writes a separate record at `0xfffffe000cb4ff08` with low word12, word+4=0x144 and sixteen trailing zero bytes. Its role is not merged with the AES hash table; the remaining callback tail is retained but not given a complete semantic interpretation. [ET1,ET5,ET6]

A bounded locator scans the kernel's three executable segments for the table page's ADRP and matching nearby immediate-offset stores, finding the two publication sites above. This is a source locator, not closure over aliases, other addressing forms, kext code or indirect writers. It cannot establish immutability or singleton table epochs. [ET6]

## Validation and bounded continuation

Ninety-one new UNSAT certificates cover14 straight-line source pieces /65 instructions, including64 CLZ intervals. The independent interpreter imports neither this generator nor Z3. It checks263 default budgets,367 budget geometries,27 option-return routes,12 whole allocation canvases containing1,198 records,6 wrapper-validity routes,9 allocator return pairs and3 special-record canvases:687 cases. Full canvases compare prefix guards, every initialized byte, allocation slack and suffix guards; overlapping u64/u32 stores are checked at byte granularity. [ET1-ET7]

Generator `--verify`, original-byte/boundary/symbol/slot recapture, certificate replay, preceding47 event-registration certificates, compressed archive round trips, exact publication ownership, original-input preservation and decoded path hygiene qualify this increment. Reproduce with `PYTHONPATH="triage_evidence${Z3_PYTHONPATH:+:$Z3_PYTHONPATH}" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_event_wait_table.py --verify`, followed by the independent interpreter and publication auditor in that dependency environment.

Extraction and locator work are O(B+I+P) time/space for collection bytes B, instructions I and bounded nearby probes P. Finite interpretation is O(cases*visits+compared bytes) time and O(code+private bytes) space. Table initialization is O(N) stores and O(1) scalar state, excluding allocator behavior. SMT has separate solver cost and15 s query limits. No scheduling duration is measured.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Startup dispatcher ordering and completed phase14 | Establishes when consumers may use the initialized table. |
| High | Allocation status/backing, root/count epoch and pointer-region validity | Connects selected source stores to an actual table allocation. |
| High | Same daemon/request/provider/event/thread epoch through interrupt and scheduler | Establishes authentic cross-layer completion rather than component correspondence. |
| Medium | Complete option-reader acceptance language and default-parameter writers | Resolves environmental control and actual budget provenance. |
| Medium | Reader serialization, aliases and nonliteral table writers | Tests publication visibility and epoch stability beyond the bounded locator. |

**QG1**: Descriptive source, environment, ABI and data/control-flow analysis requires no normative judgment.

**QG2**: ET1-ET7 record premises, dependent results and falsification probes.

**QG3**: Startup registration, environmental input, width-preserving geometry, allocation ABI, count/root/store order and queue-validity linkage are covered; native and broad cross-layer work remains active.

**QG4**: u32/u64 widths, modular shifts, exact byte stores, allocation units and the file-seeded calculation are reproducible.

**QG5**: Registered/invoked, file/runtime, count/root/readiness, guard/admission and private/native states remain distinct.

**QG6**: Original collection bytes, compiler/section metadata, authenticated chain membership, scalar certificates and independent byte interpretation provide primary provenance.

**QG7**: The impact-ranked continuation table bounds the remaining initialization, environment, serialization and daemon/kext joins.

## Source ordering and callback-return qualification

The [startup-dispatch report](startup_dispatch_report.md) establishes unsigned phase/rank comparison, the authenticated callback ABI, 42 rank-zero entries in `mach_ipc`, and cursor advance after callback return. A completed phase14 traversal includes this callback under sorted-table, returning-call and exclusive-cursor premises. It does not establish successful allocation, initialized-table visibility or native AES use (SD1-SD7).
