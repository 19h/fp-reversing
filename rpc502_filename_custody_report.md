# RPC 502 filename custody through the daemon worker

The daemon passes the incoming filename address by reference through its private RPC 502 records. The worker uses the address to construct a separate pathname. The original tail-copy loop executes for both file opens in the two archived runs. Two archived private runs reach application return with status `0xffff5bd9` and no recorded release call covering the filename page. The installed callback's error cleanup takes over after that return under the separate Mach receive and descriptor premises. Custody after an application-success return remains unknown. [Installed filename delivery](live_fairplay_request_ool_report.md) [Installed error cleanup](live_fairplay_request_release_report.md)

```text
MIG X1 (filename VA)
    |
    +-> application NUL scan
    |
    +-> R+0x08 -> worker SP+0x998 -> worker SP+0x5650
                                               |
                               byte reads and pathname construction
                                               |
                    stack pathname buffer <----+
                              |
                          open(..., 0)
                              |
                    worker returns error
                              |
              callback owns descriptor cleanup
```

## Source lineage and pathname storage

| Site | Original data movement |
| --- | --- |
| `0x1000238e8` | The wrapper stores X1 in frame+0x30, which is its private record R+0x08. The adjacent X3 store holds the CPU argument. |
| `0x1007fc58c`, `0x1007fc594` | The protected entry loads R+8 into X8 and saves it at worker SP+0x998. |
| `0x1004b9ad4`, `0x1004b9ad8` | Transfer the same u64 pointer from worker SP+0x998 to SP+0x5650. |
| `0x1005c6780`, `0x1005c6784` | Reload the filename pointer and read a byte at pointer+index. |
| `0x10083ec3c`, `0x10083ec44` | Read a selected filename byte and store it through a different base in the pathname builder. |
| `0x100d94494` | Both file opens use the same private stack pathname address `0x700734c0`, first with a 35 B `.sinf` pathname, then with a 38 B `.v5.supf` pathname. Counts exclude the NUL. The source calls use flags 0. |

The worker ABI fixture supplies a 23 B NUL-terminated filename at `0x70001000`, backed by the emulated stack. This is the private equivalent of the address passed in X1 by the MIG stub, with the mapping produced by kernel receive modeled separately. The pathname address is outside the observed 4,096 B filename page. Each open uses the pathname bytes present at its own call. The pathname bytes differ between the two calls. The earlier read observer captures the original filename bytes through the first open. A full worker memory-access journal for that page remains unknown. [Application and MIG ABI](daemon_rpc502_report.md) [Path construction](rpc502_sidecar_report.md)

## Read and release observations

The earlier byte observer records 73 one-byte reads through the first open. The entry scan reads offsets 0 through 22, the protected scanner reads 6 through 22, its slash test reads 6 through 21, and the pathname tail copy reads 6 through 22. The retained whole-worker journals contribute control-flow visits at the corresponding instructions. Together they record 29,969,824 visits across the two cases, recalculated from 64,548 distinct original instruction words. The effective address and value of every read in those complete runs remain unknown.

| Read instruction | Earlier byte observer | Each archived full run |
| --- | --- | --- |
| Entry and follow-on NUL scan | 23 recorded reads | 23 visits before first open |
| Protected scan and slash check | 33 recorded reads | 45 visits before first open |
| Pathname tail copy | 17 recorded reads | 17 visits before first open, 17 between the two opens, zero thereafter |

The second tail-copy visit group precedes the supplemental open at source-visit index 5,718,626 in both full cases. The final tail-copy visit is at index 5,717,303. These are zero-based instruction ordinals across modeled startup and worker. The difference between the earlier and full scan counts limits transfer of exact effective offsets across the datasets.

The archived release calls comprise six frees and one unmap in each worker. Their call sites and arguments match the recorded imported-call transitions. None retires the filename page. The release inventory covers the named VM deallocation and message-destroy imports alongside free and unmap. The worker's file mappings and temporary heap owners have separate call arguments. The wrapper writes reply-output fields before decoding the error at `0x100023ad4`. In the joined error path, the caller keeps the incoming descriptor available for its selected request-destroy call. [Worker resource ledger](rpc502_ownership_report.md) [Selected callback release contract](live_fairplay_request_release_report.md)

## Assumption register and checks

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| F1 | The pinned original arm64e slice and its fixups are the intended daemon. Preferred PCs and wrapper layout depend on this identity. | Rehash the original slice and compare the installed image's code and binding evidence. |
| F2 | The private startup, file, API and logical PAC models define the two archived worker paths. Whole-path execution claims depend on those modeled paths. | Compare checkpoints and terminal states to the archived runs, or correlate a regular native request with the same path. |
| F3 | The earlier byte observer and long archived cases use the same fixture filename address. The early offsets apply to the short observation, while the complete journal records control-flow visits and release arguments. | Compare instruction EAs and byte widths with an independently watched interval. Compare the early independent read observer and the whole-worker instruction executions at the recovered sites. |
| F4 | The archived record has an identified collision in Base64 symbols. Restoring the three symbols in memory must give valid zlib streams and canonical equality across the original and replay archives. | Check both archive digests and reject a different marker count, invalid checksum or different retained/replay observations. |
| F5 | Joining worker error to the separately verified callback assumes an ordinary receive, unchanged descriptor and an eligible error status. Native mapping retirement depends on the actual VM call. | Correlate the same filename address, extent, application status and callback descriptor through a regular observed transaction. |

A legacy text substitution touched alphabet symbols inside the compressed Base64 transcript of the first case in each archived corpus. The audit reconstructs the three symbols in memory, verifies the zlib checksum and requires full equality of the original and replay archives. A new instrumented run did not match the archived result and provides no certified additional memory accesses. The two archives stay unchanged. The evidence stores the archive digests and symbol counts.

The observation cost is O(V + B + E) time for V source visits, B archive and source bytes, and E captured event records. Working space includes the loaded archives and largest decoded archived worker record. Instruction counts and byte widths describe the finite runs. File, Mach and VM behavior in these archives remains modeled. The successful application route and native ownership remain unknown. High impact attaches to tracing the incoming address and enumerating the recorded release sites in the two complete worker paths, and to resolving subsequent ownership on application success. Medium impact attaches to distinguishing the changing pathname buffer from the original filename backing when matching observations.

The audit uses the repository's Python dependencies and the pinned thin executable.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_rpc502_filename_custody.py "$FAIRPLAYD_THIN"
```

Quality gates QG1–QG7 cover descriptive scope, five assumptions with falsification probes, the selected pointer and cleanup interfaces, byte widths and explicit observability bounds, owner separation, primary image and journal provenance, and remaining work by impact. [Audit script](triage_evidence/audit_rpc502_filename_custody.py) [Compressed receipt](triage_evidence/rpc502_filename_custody_audit.json.zst)
