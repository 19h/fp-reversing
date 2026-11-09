# Username-path history scrub and publication closure

The one-time history rewrite retains all77 commits and removes username-bearing path components from738 historical data objects. An independent implementation scans all6846 stored objects,including unreachable objects and2183 decoded Zstandard blobs,with zero offending objects. It scans12401173691 logical bytes. Eighteen scrubber controls and independent positive/negative detector controls pass. Target-defined ABI paths and ordinary non-path identifiers remain technical evidence. [PR1-PR6]

The current publication prepares710 files with username-path redaction. It also includes37 older JSON evidence artifacts that were present locally but absent from Git because of the JSON ignore rule,while retaining the supplied C export as a local primary input under its recorded hash and existing ignore/tracking policy. Large JSON artifacts use `zstd --ultra -22 -q -T1`;logical hashes are computed over decoded bytes. The current root inventory hashes sanitized content. Older nested manifest/dependency hashes and scientific validation results retain their pre-redaction epoch;they are not all recomputed or asserted current. The new mode1 source certificates are recaptured and replayed after redaction. [PR2-PR5]

Evidence: [pre-rewrite scan](triage_evidence/username_path_scrub_history_before.json), [rewrite ledger](triage_evidence/username_path_scrub_history_rewrite.json), [current-file preparation ledger](triage_evidence/username_path_scrub_current_files.json), [independent stored-object audit](triage_evidence/username_path_scrub_history_audit.json), [pre-redaction research receipt](triage_evidence/daemon_mode_one_scatter_pre_redaction_audit.json), [scrubber](triage_evidence/scrub_username_paths.py), [independent detector](triage_evidence/verify_username_paths_history.py), [publication tool](triage_evidence/publish_username_path_scrub.py), [current scientific report](daemon_mode_one_scatter_report.md).

Username path components are replaced with equal-length underscore components,including recognized escaped,URI,UTF16,hex and anchored Base64 representations. The runtime username is not persisted in these ledgers. Git author names/emails and non-path identifiers are outside the requested path scrub. Source instruction bytes and their original binary identities remain the scientific evidence;sanitized metadata receives new artifact hashes. Two source locators use `Path.home()` to select the same reference binaries without embedding a username. Redacted external Markdown locators may resolve through the current home directory at audit time;their text does not disclose the original username.

One historical IDA database blob contained username paths and received equal-length metadata redaction. Its loadability is unknown and is not inferred from the byte replacement. The three currently tracked database snapshots are removed from the new index;the live local databases are retained without being rewritten. The ignore rule and publication enumerator exclude IDA databases and sidecars. Original binary recapture and source/SMT checks establish the new research result independently of the archived database.

The scientific preservation audit separates exact matches,deterministic username-path transformations and nine explicit owned report/publisher/reference-locator changes. This does not equate metadata redaction with rerunning historical experiments. The post-redaction root inventory and current source checks provide the current verification boundary. The unavailable historical external SDK reference remains explicit;the installed SDK is not substituted as equivalent. [PR3-PR6]

The stored-object audit cited here covers the rewritten77-commit history before adding the new report. Staged content is checked separately,and a final stored-object audit after the generated commit is performed outside the self-referencing inventory. Publishing replaces the old branch through an exact old-tip lease;remote identity is verified afterward. These scans cover the replacement local object database and published refs;server-side deletion or retention of old unreachable objects is unknown. Future turns need to scrub newly written/committed files;this completed one-time historical migration does not call for repeating the entire history rewrite.

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| PR1 |Runtime username denotes the requested path component |Independent positive controls;inspect recognized path encodings;non-path negative controls must remain unchanged |
| PR2 |Fresh isolated Git import preserves the commit graph and dates |Compare77 commit nodes,parent topology and author/committer timestamps before publication |
| PR3 |Logical archive decoding and replacement preserve unrelated bytes |Check decoded before/after hashes,exact transformation ledgers and decompression roundtrips;do not assign the old hash to sanitized bytes |
| PR4 |Current scientific claims are source certificates,not native observations |Recapture original artifact and replay66 UNSAT queries plus finite address/permutation certificates after redaction |
| PR5 |Historical proof results retain their earlier epoch |Reject any assertion that all older generators/checks were replayed;use current root hashes for sanitized artifact identity |
| PR6 |Local live IDBs and concurrent user work remain separate from publication |Exclude databases from current index and publisher;preserve live files and stop integration if owned source files changed concurrently |

| Impact | Bounded finding / opportunity | Verification boundary |
| --- | --- | --- |
|High|Missing ignored evidence is now publishable and referenced by content hash|Current logical inventory and explicit owned-path staging |
|High|Username disclosure also occurred in archives and an archival database|Independent decoded/all-stored-object scans;archived database loadability remains unknown |
|Medium|Historical artifact hashes differ after metadata rewriting|Root inventory is current;nested hashes preserve pre-redaction provenance |
|Medium|Source locators are portable without persisted username paths|Runtime home-derived paths and original binary hashes |

QG1: No normative judgment is required.

QG2: PR1-PR6 register assumptions and falsification probes.

QG3: History,current files,archives,commit messages,missing evidence and live-database exclusion are covered;the broader daemon/kext interface objective remains active.

QG4: Counts,logical/stored byte distinctions,hash domains and compression arguments are explicit. Scan work is O(total decoded bytes+objects);storage is bounded by concurrent largest-object processing.

QG5: Historical versus fresh validations,metadata versus machine code,archived versus live databases and current versus historical hashes are distinguished.

QG6: Original/rewrite ledgers,independent stored-object audit,current root hashes and fresh scientific certificates ground the claims. Zero matches refers to the audited path encodings and object set.

QG7: Impact-ranked publication gaps,archive disclosure,hash epochs and portable locators bound this migration. It adds no native FairPlay exchange or full-goal completion claim.
