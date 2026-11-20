# Discovery status routing after FairPlayIOKit cleanup

For outer phase `0xb306`, `fairplayd` consumes the saved discovery marker and a separate saved flag after cleanup. A marker unequal to `0x8b3dc651` with a zero flag returns to the discovery gate at `0x100639894` with W8 set to 1. The same marker with a nonzero flag is copied to S+0x804 B. An exact marker match selects `0x10062aad0` regardless of the flag. These are private daemon dispatches. The archived Mach exchange identifies the earlier failed type-0 open and port releases. The native caller PC, flag and selected continuation remain unknown. [Original-byte audit](triage_evidence/audit_daemon_class_status_route.py) [Audit receipt](triage_evidence/daemon_class_status_route_audit.json.zst) [Archived port retirement](archived_iokit_open_retirement_report.md)

## Outer phase source and caller ABI

The original adapter at `0x10061748c` passes the incoming record pointer Q in X0 and a local cursor address in X1. Its call at `0x1006176d0` uses index `0xcdd0`, slot `0x1010a0d70` and IA modifier `0x4230` to reach `0x100559b7c`. The index derives from the ordered byte banks at `0x101031da0` and `0x100e99900`, key `0x0a` and additive term `0xcce6`. The cursor adapter and outer routine use the following memory fields. [Audit receipt](triage_evidence/daemon_class_status_route_audit.json.zst)

| Source site | Input or output | Recovered operation |
| --- | --- | --- |
| `0x100617618`–`0x10061761c` | Local u64 cursor | Store the old caller cursor minus `0xe0` modulo 2^64. |
| `0x100559cb4`–`0x100559cbc` | Local u64 cursor | Add `0xe0` before dispatch. |
| `0x100559cc0`–`0x100559d14` | Q+0x34 B, u32 | Form K as the low 32 bits of `(Q XOR 0x7e103facb521e742) * 0x74cae98d`. Set W6 to the field minus K modulo 2^32. |
| `0x100559d1c`–`0x100559d20` | Q+0 B, Q+8 B, Q+0x18 B, u64 each | Load the three operands used in the null test. |
| `0x100530328`–`0x100530468` | Q+0x38 B and Q+0x14 B, u32 each | Add K to each field modulo 2^32. In both nonnull controls the first decodes to `0xb306`. The second distinguishes the two observed allocator routes. |
| `0x10053043c` | S+0x2ec B, u32 | Save W6. S is the retained outer SP. |
| `0x10062b370` | Q+0x10 B, u32 | In the selected one-null controls, publish `0x74c29d88` and take the ordinary guard-checked return. |
| `0x1006176d4`–`0x1006176e0` | Original caller cursor, u64 | Store `((new_local_cursor - old_caller_cursor) & 0xffff) << 4`. In all three one-null controls the cursor output is zero. |

With W6=`0xb306`, all three operands nonnull selects index `0xb337`, slot `0x1010938a8`, IA `0x46e9` and target `0x100530328`. Independently nulling any one operand selects index `0xb306`, slot `0x101093720` and target `0x10062b370` through the same branch at `0x100559df4`. For the two nonnull controls, decoded Q+0x14 B `0x66257669` selects slot `0x101099e38` and target `0x10061b2f8`, ending at the 49 B allocation request at `0x10061b384`. The adjacent value `0x66257668` selects slot `0x101099e58` and target `0x100541690`, leading to a 16 B request at `0x1004a8c54`. Both controls execute the original phase store before the request. The evidence stops before either allocator returns. The native producer of Q and the uninterrupted join from these requests into discovery remain unknown. [Audit receipt](triage_evidence/daemon_class_status_route_audit.json.zst)

## Post-cleanup routing

The previously mapped cleanup restores W24 from S+0x2ec B at `0x100620a30`. The next dispatch computes index `(0xb306 - 0x932b) = 0x1fdb` and W10=`(0xb306 XOR 0xb31d) * 0x345 = 0x5847`. It loads M into W21 from S+0x62c B at `0x1006220e4` and F into W8 from S+0x89c B at `0x1006220e8`. The latter cell takes the earlier admission flag from W8 at `0x1006398b4`. [Cleanup and marker production](daemon_class_lock_release_report.md) [Audit receipt](triage_evidence/daemon_class_status_route_audit.json.zst)

| Transfer PC | Condition | Table index and slot | Target and effect |
| --- | --- | --- | --- |
| `0x1006220f4` | W24=`0xb306` | `0x1fdb`, `0x101049dc8`, IA `0xd2fe` | `0x1004c620c`, evaluate M and F. |
| `0x1004c6260` | M differs from `0x8b3dc651`, F=0 | `0x5847`, `0x101066128`, IA `0xcd37` | `0x1004c8958`, set W8=1 and reload the prior gate inputs. |
| `0x1004c89a4` | Redispatch arm | `0x5c26`, `0x101068020`, IA `0x4abe` | `0x100639894`, with W9=`0x65a1`, X19 from S+0x8c8 B and W11 from S+0x914 B. |
| `0x1004c6260` | M equals `0x8b3dc651` or F differs from 0 | `0x5868`, `0x101066230`, IA `0xcd37` | `0x10051ac30`, test M again. |
| `0x10051ac74` | M differs from `0x8b3dc651` | `0x183f`, `0x1010460e8`, IA `0xfe2b` | `0x10052b5e8`, store M at S+0x804 B at `0x10052b5f0`. |
| `0x10051ac74` | M equals `0x8b3dc651` | `0x485d`, `0x10105e1d8`, IA `0xfe2b` | `0x10062aad0`, isolated source control stops at entry. |

The two primary-open-failure replays recover the same private marker `0x74c29dee`. F=0 reaches the gate predecessor. F=1 copies that marker to S+0x804 B. The context-skip control with F=1 copies `0x74c29dba`, and the null-cache control with F=`0xffffffff` copies `0x74c29d88`. The redispatch control reaches the original gate with fixture values of zero in the reloaded X19 and W11. The previous gate audit established that admission to its class-call route requires a nonnull X19 and the marker mismatch. A second IOKit lookup therefore remains unknown. The exact-marker route uses its own source control. The recorded context-skip path translates the class routine's internal `0x8b3dc651` to `0x74c29dba` before cleanup. [Discovery gate and admission](daemon_class_lock_gate_report.md) [Audit receipt](triage_evidence/daemon_class_status_route_audit.json.zst)

## Evidence limits and follow-up

The primary image is the pinned arm64e `fairplayd`, Mach-O UUID `204741e9-b89f-32b4-9321-51f3975c7cac`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The archived RAX text, SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`, supplies the order of Mach IDs 2862 and 2962 and the following port releases, with application result `0xe00002c2`. Those IDs and the port lifetimes retain the prior archive attribution. Native lock activity, port creation in these continuations and the link to a particular kernel failure site remain unknown. [Archive provenance and ports](archived_iokit_open_retirement_report.md)

| Open join | Impact | Discriminating evidence |
| --- | --- | --- |
| Caller and delivery of an admitted record | High | Trace the original caller of `0x10061748c` and carry its record fields through an ordinary allocation return into discovery. |
| Whether the redispatch actually starts another lookup | High | Trace the source and epoch of S+0x8c8 B and S+0x914 B, then execute the restored-state gate. |
| Downstream consumer of the preserved marker | Medium | Follow S+0x804 B from `0x10052b5f0` to its first read and observable result. |
| Exact-marker route and native attribution | High | Identify a sourced discovery path yielding M=`0x8b3dc651` after cleanup, and match daemon caller and port sequence in one execution. |

## Assumptions and verification

| Assumption | Dependent result | Stress test |
| --- | --- | --- |
| A1. The pinned image provides the instruction bytes and logical chained-pointer targets. | All site, slot and target mappings. Hardware PAC remains unknown. | Decode and verify 107 original chained words. Re-derive each selected target and modifier from the running registers. |
| A2. Q, its operands and the original cursor cell are declared private fixture memory. | Outer phase producer, allocation frontiers and cursor ABI. | Vary one operand at a time through NULL, vary the decoded marker by one, and prove the key, phase and cursor equations over fixed-width words. |
| A3. The discovery replay starts on the retained frame with declared environment, cache and external results. It supplies the separately verified W6 phase at the original store and controls F at the first gate entry. | Reconstructed cleanup and phase-specific continuation. The uninterrupted adapter-to-discovery frame and native F origin remain unknown. | Hold the failed-open result fixed while changing F, then exercise context skip and null cache with nonzero F. Prove both branch predicates for arbitrary 32-bit M and F, and verify the exact-marker target in isolation. |
| A4. The archived text captures the transport at its logged trap boundary. | Correlation of failure and release order with the modeled IOKit path. | Use the previously decoded open, reply and release boundaries. A native daemon-PC trace could distinguish these modeled successors. |

Five entry replays, four cleanup replays and one isolated dispatch control record 228 logical transfers. Eight fixed-width bit-vector obligations pass. The deterministic replay takes O(V) time in V instruction visits and retains O(T) transfer records for T observed transfers, excluding the mapped image, fixture memory and solver. Reproduce with `python3 -B triage_evidence/audit_daemon_class_status_route.py` in the existing Capstone, Unicorn and Z3 environment with the pinned image. [Audit generator](triage_evidence/audit_daemon_class_status_route.py) [Compressed receipt](triage_evidence/daemon_class_status_route_audit.json.zst)
