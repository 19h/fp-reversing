# Running FairPlay client image identities

Both user clients in the FairPlayIOKit registry capture are attributable to processes running the installed `arm64e` slices. The process-reported Mach-O slice offset and CodeDirectory hash independently select the same row of each universal file. This establishes which preferred-address maps apply to the two processes in the capture on build `26C5035r`. The actual image bases and task-local Mach names remain unknown. [Registry attribution](daemon_iokit_native_registry_report.md) [Installed adid address maps](adid_selector26_installed_report.md)

| Registry creator | PID | Client registry ID | Slice offset in file | Matched image UUID |
| --- | --- | --- | --- | --- |
| `adid` | 910 | `0x10000130b` | `0x38c000` B | `4d24325f-3529-39b1-bbf8-64bbcf406049` |
| `fairplayd` | 3903 | `0x100001702` | `0x340000` B | `204741e9-b89f-32b4-9321-51f3975c7cac` |

## Evidence join

The audit queries `csops` with `CS_OPS_PIDOFFSET` and `CS_OPS_CDHASH` for each IORegistry creator PID. Both operations return zero for both processes. The file offset is decoded as a signed little-endian 64-bit value. Each returned 20 B hash matches a unique installed slice. The audit parses each slice's embedded signature, hashes the CodeDirectory using its declared algorithm, and checks the result against `codesign` for that architecture. Both attributes are read again after the file comparison. Process start times and registry snapshots agree across the checks. [Apple XNU csops definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h#L683-L738) [Apple XNU CodeDirectory and hash widths](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)

The live `fairplayd` CodeDirectory hash also matches the supplied thin image. Its UUID matches, and the fresh full-file comparison finds 262 differing bytes, all within the embedded CMS signature slot. The observed `adid` slice has the same digest as the installed arm64e slice used to verify the eleven retained IOKit windows. The primary `adid` selector 26 call has preferred PC `0x10001f908`. The covered `fairplayd` direct and descriptor calls have preferred PCs `0x1002069c4` and `0x100293074`. Establishing the executable identity leaves reachability, runtime slide and call occurrence open. [Daemon selector 26 call sites](daemon_selector26_return_report.md)

`PROC_PIDARCHINFO` returned zero bytes and `EPERM` for both daemons and eight bytes for the querying process. The successful code-signing queries provide the slice evidence even though the architecture query and process-map inspection were unavailable. No selector request, reply payload or Mach right was observed in this capture.

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The IORegistry creator PIDs still name the same processes during capture. | Registry-to-process association. | Compare registry IDs, process start times and the two repeated attributes before accepting the association. |
| The live offset and hash uniquely select one installed slice for each process. | Image UUID and preferred addresses. | Enumerate all slice offsets and directory hashes, including alternate CodeDirectories, and require both matches to select one row. |
| The installed arm64e UUID and source bytes correspond to the prior static analysis. | Applicability of the earlier call-site maps. | Compare the pinned daemon bit-for-bit outside its CMS slot and the installed `adid` digest with the slice used in the source-window audit. |

File parsing and hashing use O(B) time and O(B) auxiliary space for B executable bytes. The observation has high impact on correlating a future native trace with the static reports. A current runtime slide and a matched method exchange remain the next evidence needed for runtime PC and message attribution. [Audit script](triage_evidence/audit_fairplay_live_slice_identity.py) [Compressed observation](triage_evidence/fairplay_live_slice_identity_observation.json.zst)
