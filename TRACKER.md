# HView-Linux implementation tracker

Last update: September 10, 2026.
Read this file first when a session resumes.
Read [PLAN.md](PLAN.md) for the complete requirements and source references.
Read [VERIFICATION.md](VERIFICATION.md) for the final function and Linux-difference matrix.
Read [UPSTREAM_REVIEW.md](UPSTREAM_REVIEW.md) for the historical and current Windows source comparisons.

## Current state

- Current scope: all implemented functions in Windows commit `469f13d0959d5bed7fbf068a7c4a5858be16d0a8`.
- Current Windows source: clean local `master` at `469f13d0959d5bed7fbf068a7c4a5858be16d0a8`.
- Current Linux branch: local and remote `rust-rewrite` at `1a3877a459aa7bea0f4e6f9d3249b1adb4554fdc`.
- Accepted Linux application baseline: D07 source at `5e4ef68`.
- Current authorization: scoped application work on L02.1 only.
- Planning status: L01.1, L01.2, and parent L01 are `Complete`.
- Application implementation: L02.1 is authorized and `Pending`. All other application items remain `Pending` and unauthorized.
- Detailed plan: two current children are `Complete`; 83 children are `Pending`.
- Next action: Plan L02.1 with Astra xhigh. Assign its bounded implementation to Sol xhigh under the recorded authorization.
- Review gate: L02.1 is authorized. Do not add another approval gate for L02.1.
- Accepted platform decisions: retain scoped HEM functions, closely match the Windows terminal, and support raw-device editing.
- Device policy: use read-only defaults and explicit writable mode. Permit a user-controlled override for mounted, in-use, or nonexclusive devices.
- Product policy: do not block a supported, valid, local operation only because the operation is risky.
- Error policy: return accurate errors for invalid or unsupported requests and operating-system or I/O failures.
- Path policy: preserve valid Linux pathname bytes. Keep operational paths separate from escaped display text.
- Scanner policy: enforce the Windows limits with aggregate memory and descendant containment or return a capability error.
- Source comment policy: add educational block comments to each logical section in every changed source file.
- Historical evidence: the D03 release and D04 through D07 extension remain accepted evidence for their earlier scope.
- Record owner: the main task maintains planning, verification, and publication evidence.
- Execution owner: Sol xhigh performs all execution and code generation.
- Sol xhigh creates documentation, application code, tests, and build scripts. Sol xhigh also runs all checks.
- Reviewer: Astra xhigh performs all planning and review.
- Publication: commit and push reviewed goals only to `origin/rust-rewrite`.
- Astra High accepted the detailed 85-goal plan after text review; all implementation goals remain pending until explicit user authorization.
- Current modified records: `PLAN.md`, `TRACKER.md`, and `UPSTREAM_REVIEW.md`.
- Project folder: `/home/sweet_cicero/Projects/HView-Linux`.
- Repository: [HView-Linux](https://github.com/lukecloud-cyber/HView-Linux).

The current source review used local checkouts only.
The review did not run the Windows application, HEM modules, or real devices.
The review did not run a current full PTY or isolated-package suite.
The current Rust suite has one environment-limited ACL fixture failure.
See [UPSTREAM_REVIEW.md](UPSTREAM_REVIEW.md) for the exact failure and source evidence.

## Status rules

Use `Pending`, `Active`, `Implemented`, `Complete`, or `Blocked` for each task.
`Implemented` means the code exists but required checks or review remain.
`Complete` means the code, required checks, and Astra xhigh review pass.
`Blocked` requires a specific cause and a next action.
Do not count source baseline tests as Linux implementation checks.

After each change, update the affected task and the current state.
Record the source files, commit when available, check command, result, and review result.
If a check fails, record the failure and the remaining action.
If requirements change, update both this tracker and the plan.
Before stopping, record uncommitted changes and a concrete resume action.

## Current parity tasks for user review

Dependencies identify required contracts before task acceptance.
The dependencies in this parent table summarize parent groups.
Task numbers do not create additional dependencies.
The coverage column describes existing source only.
Each task stays at its recorded status until its checks and Astra acceptance pass.

| ID | Upstream work | Coverage | Dependencies | Required task | Required acceptance |
|---|---|---|---|---|---|
| L01 | P01-P07, X03 | Complete records | None | Record the accepted HEM, terminal, device, path, and process-control contracts. | Record scoped application authorization and identify the first dependency-ready application item. |
| L02 | S01, REQ01 | Missing | L01 | Add bounded regular-file access with stable ownership and `u64` positions. | Check files above 64 MiB, 4 GiB, and memory limits. Check both ends and source changes. |
| L03 | S02, D07, REQ01/10 | Partial | L02 | Add logical spans and current edit transactions. Retain exact buffered undo state. | Check 256 records, 130 MiB history, 65 MiB changed memory, and 4,096 spans. Check atomic refusal. |
| L04 | S02, R03/R04 | Scale missing | L03 | Extend guarded Linux saves to logical spans and sparse files. | Check metadata, ACLs, identities, holes, races, reopening, failures, and recovery paths. |
| L05 | S03, REQ01/13 | Missing | L02, L03 | Add shared Text indexes, resumable scans, and suffix invalidation. | Check cold and warm seeks, cancellation, 64 KiB rows, 4 KiB carry, and bounded checkpoints. |
| L06 | S04 | Missing | L02 | Add cancellable workers, source stamps, progress, and Linux input polling. | Check Escape, queued keys, resize, errors, races, stale results, and no partial results. |
| L07 | D01/D05/D10/D11, B01/B07, REQ02/15 | Partial x86 | L02, L06 | Add architecture domains, typed decode errors, ARM engines, and current raw overrides. | Check AVX, ARM/Thumb, ARM64 decoding and assembly refusal, reuse, fallback, widths, alignment, AUTO, Real16, and syntax. |
| L08 | D02/D03, B02/B03, REQ04 | Partial PE | L02, L07 | Add checked PE, ELF, and Mach-O metadata and mappings. | Check current edits, malformed ranges, address domains, aliases, high offsets, and supported machines. |
| L09 | B05/B06, REQ04/05 | Missing | L02, L07 | Add NE, LE, LX, TE, TE64, NLM, LAN, and DSK support. | Check each format, malformed records, mixed widths, required tables, and buffered or paged agreement. |
| L10 | D04/D06, REQ06, UX01 | Partial | L03, L07-L09, L15 | Add current branch controls, marker actions, histories, and assembly previews. | Check visible targets, exact return, high addresses, invalid targets, previews, cancel, apply, and resize. |
| L11 | D15, REQ10 | Partial Fill/XOR | L03, L04, L14 | Add selection, block I/O, copy, move, insert, delete, and shared transactions. | Check overlap, boundaries, aliases, undo, annotation relocation, staged output, limits, and device refusals. |
| L12 | D13, REQ08/10 | Missing | L03, L04, L06, L11 | Add the 64-bit crypt interpreter and prepared edit application. | Replay reference vectors. Check large offsets, cancellation, incomplete units, atomic errors, and all route limits. |
| L13 | D08 | Missing | L03, L04, L06 | Add verified patches, streaming hashes, and portable SHA-256 support. | Check identity, grammar, limits, export refusal, round-trip, one undo, and one redo. |
| L14 | D09, D15 | Missing | L03, L13, L15 | Add bounded annotations, source binding, relocation, and exact history snapshots. | Check 256 records, 1,024-byte text, CRUD, guards, jumps, splices, undo, redo, and cancellation. |
| L15 | UX01, P01/P04 | Partial foundation | L01 | Match Windows appearance closely with semantic colors, dialogs, fixed footers, and current controls. | Check standard and small sizes, clipping, restoration, Enter cycle, F4 choices, reachable keys, and theme or font differences. |
| L16 | P02, S12, REQ01/13 | Partial | L03-L05, L15 | Add four Text codecs, grapheme layout, input, movement, and Text transactions. | Check invalid units, input, widths, delimiters, edits, history, saves, and files above memory. |
| L17 | D12, S05/S07, REQ07/13 | Partial byte search | L02, L06, L07, L16 | Add bounded byte, encoded, and instruction search with continuation pages. | Check overlap, repeat, current spans, page crossings, grammar, cancellation, and all architectures. |
| L18 | S04/S07/S11 | Partial basic tools | L06, L08, L09, L16 | Add Unicode Strings, cancellable entropy, values, GUIDs, UUIDs, and templates. | Check offsets, result limits, invalid text, NaN bits, dependent lengths, pointers, and browser limits. |
| L19 | S08 | Partial compare | L04, L06, L13 | Add stable comparison peers, independent spans, alignment, pages, and patch export. | Check all difference types, repeated anchors, unresolved spans, peer changes, cancellation, jumps, and export refusal. |
| L20 | D14, REQ09 | Missing | L02, L07, L15 | Add the 64-bit calculator, retained results, base conversion, and history. | Replay 111 vectors. Check wrapping, shifts, division, tails, overlays, 68-byte input, and 64 history entries. |
| L21 | DatRef/Refer, D12 | Missing | L08, L09, L15, L17 | Add Code and Hex reference searches with independent state and local domains. | Replay raw, PE, NE, ELF, LE, and LX cases. Check controls, widths, pages, and cancellation. |
| L22 | Names, X03 | Missing | L04, L08, L09, L15 | Add Names domains, imports, manager actions, and source-bound companions. | Check grammar, CP437 input, 256 entries, shifts, filters, deletion, source changes, Save As, and errors. |
| L23 | P06, R01/R09 | Partial | L01, L07, L15, L16 | Add current configuration and CLI compatibility. Retain Linux discovery and headers. | Check 256 KiB files, keys, offsets, invalid values, quoting, duplicates, paths, boundaries, and atomic failure. |
| L24 | P02/P03, REQ11/13 | Partial | L04, L15, L23 | Add picker controls, bounded traversal, visit history, and marks. | Check sort, hidden files, masks, links, errors, recovery folders, limits, 256 visits, and path identity. |
| L25 | S09, REQ13 | Partial legacy SAV | L07, L13, L14, L16, L22, L24 | Add current SAV extensions and version-six sessions. | Read versions 1-6. Check Unicode, identities, guarded writes, legacy data, unknown data, Real16, and paged limits. |
| L26 | S14, R05, REQ12/13 | Partial playback | L04, L06, L15, L16 | Add ten macro slots, exact events, banks, delays, and Linux controls. | Check slot and bank limits, Unicode, prompts, overflow, abort, retention, queued keys, and delay cancellation. |
| L27 | S13/P03, REQ11 | Missing | L04, L06, L17, L24 | Add selected multi-file replacement, journals, rollback, and startup recovery. | Check file and result limits, aliases, interrupted publication, locks, corrupt journals, targets, and retained recovery. |
| L28 | S10 | Missing | L01, L04, L06, L15 | Add bounded YARA-X execution and Linux child-process controls. | Check rules, unsaved bytes, diagnostics, includes, paths, overrides, cancellation, descendants, and resource limits. |
| L29 | X01, legacy extras | Missing | L03, L04, L06, L08, L09, L15 | Add location export and confirmed PE checksum adjustment. | Check reports, debugger text, destination refusal, checksum vectors, no-op, cancel, and undo. Do not launch tools. |
| L30 | P07, REQ03 | Missing | L01-L04, L11, L24 | Add raw-drive, partition, and logical-volume access. Use read-only defaults, explicit writable mode, and a user-controlled override. | At commit, identify the device and range. Warn once about filesystem damage, partial writes, and limited recovery. Preserve fixed length, actual bounds, validation, permissions, neighboring bytes, flushes, read-back, and accurate failures. Do not unmount or bypass privilege controls. Test disposable devices only. |
| L31 | X03, retained REQ14 scope | Missing | L01, L03, L04, L08, L09, L11, L15, L22 | Inventory retained HEM functions and requirements. Implement accepted portable functions in established modules. | Check each retained workflow. Record each excluded Windows-specific module and its reason. Do not build a speculative plugin framework. |
| L32 | P05, R06-R13 | Extension pending | L01; final after L02-L31 | Extend native packaging, notices, Linux CI, and current probes. | Check ABI features, hashes, prerequisites, GNU libraries, isolation, missing libraries, notices, and the current glibc floor. |
| L33 | All requirements | Historical evidence only | L02-L32 | Complete parity verification and update all final records. | Pass Rust checks, PTY suites, platform checks, isolated packaging, Linux-difference review, and final Astra acceptance. |

## Detailed current goals

The child-goal dependencies govern implementation order.
The parent summaries above and the historical sequences do not reduce these dependencies.
A parent ID in a dependency field means that all children of that parent must pass.
Each implementation child also depends on L01.2, even when the dependency field does not show L01.2.
Planning-only goals L01.1, L31.1, and L31.2 do not depend on L01.2.
Each parent becomes `Complete` only after all children pass their checks and Astra acceptance.
The 85 current children are not a fixed maximum.
L31.2 can add named HEM implementation children when the inventory finds an uncovered workflow.
All children inherit the current source limits and the required Linux adapters.
Sol xhigh performs all execution and check runs.
Astra xhigh must accept each child before its status becomes `Complete`.

### L01: implementation contracts and authorization

All L01 children use the platform decisions in PLAN.md and the HEM and platform boundaries in UPSTREAM_REVIEW.md.
The user accepted the HEM exclusion, terminal direction, and device override.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L01.1 | Complete | Record implementation contracts. | Native path, legacy OEM, scanner containment, and source-comment contracts have durable records. | None | Documentation checks and Astra xhigh acceptance passed. | Planning only. No application file changed. |
| L01.2 | Complete | Record application implementation authorization. | The user authorized L01.2 and scoped application work on L02.1. | L01.1 | Documentation checks and Astra xhigh acceptance passed. | Planning only. Do not start L02.1 during this documentation child. |

### L02: bounded regular-file storage

All L02 children use `W:src/main.rs:8445`, `W:src/paged.rs:20`, and `W:src/paged.rs:213`.
Linux currently reads the complete file at `L:src/main.rs:810`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L02.1 | Pending | Add owned bounded file reads. | Whole-file loading prevents files larger than memory from opening. | L01.2 | Check 64 KiB windows, `u64` offsets, short reads, EOF, and files above 64 MiB and 4 GiB. | Regular files only. Preserve actual I/O errors and bounded allocation. |
| L02.2 | Pending | Connect bounded storage to the file lifecycle. | Views and reopen paths must retain the same source identity across file changes. | L02.1 | Check first and last bytes, limited-memory opening, file switches, reopening, replacement, truncation, and source changes. | Preserve native pathname identity. Keep buffered behavior where upstream uses it. Do not add paged-only analysis routes. |

### L03: logical spans and edit transactions

All L03 children use `W:src/paged.rs:74`, `W:src/paged.rs:473`, `W:src/paged.rs:578`, and `W:src/editor.rs:13`.
Linux stores one `Vec<u8>` at `L:src/editor.rs:81`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L03.1 | Pending | Add logical edit spans. | Large edits need current bytes without copying the complete source. | L02 | Check replacement, insertion, deletion, EOF, span splitting, merging, checked lengths, and reads across boundaries. | Preserve 65 MiB changed memory and 4,096 spans. Check limits before mutation. |
| L03.2 | Pending | Extend operation history. | Logical spans must retain exact undo and redo state like buffered edits. | L03.1 | Check 256 records, 130 MiB history, cursor and length restoration, grouped nibbles, redo invalidation, and no-op preservation. | Reuse the existing history behavior. Refuse oversized operations atomically. |
| L03.3 | Pending | Connect transactions to the edit lifecycle. | Save, cancel, and file switching can otherwise leave stale edit state. | L03.2 | Check all existing edit callers, baseline reset, canceled edits, source changes, and buffered or paged agreement. | Keep disk saving in L04. Add no separate transaction framework. |

### L04: guarded large-file saves

All L04 children use `W:src/save.rs:383`, `W:src/save.rs:402`, `W:src/save.rs:455`, `W:src/paged.rs:1424`, and `W:src/paged.rs:1465`.
Reuse the Linux save paths at `L:src/save.rs:707` and `L:src/save.rs:736`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L04.1 | Pending | Stream logical spans into staged saves. | The existing Linux save path must write large edited sources with bounded memory. | L03 | Check replacements, growth, shrinkage, unchanged ranges, sparse holes, and destination bytes. | Preserve guarded replacement and exclusive Save As publication. |
| L04.2 | Pending | Preserve Linux save identities and metadata. | Streaming saves must keep existing metadata rules and reject a changed target. | L04.1 | Check mode, owner policy, ACLs, source identity, symlinks, aliases, directory synchronization, races, and reopening. | Preserve true permission errors. Run the named-user ACL fixture where UID 1 is mapped. |
| L04.3 | Pending | Verify save failure and recovery states. | A staged-publication failure must leave defined source, backup, and editor states. | L04.2 | Check failures before and after publication, cleanup, backup retention, reopen failure, and exact recovery messages. | Use disposable files. Do not claim atomic recovery after an unrecoverable operating-system failure. |

### L05: bounded Text indexes

All L05 children use `W:src/text_index.rs:138` and `W:src/text_index.rs:183`.
Linux currently rescans buffered rows at `L:src/editor.rs:596` and `L:src/editor.rs:722`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L05.1 | Pending | Add bounded Text checkpoints. | Repeated long-distance Text movement otherwise rescans the complete prefix. | L02 | Check cold and warm seeks, row boundaries, 64 KiB rows, 4 KiB grapheme carry, and checkpoint bounds. | Build the source and index contract here. Full Text codecs and rendering belong to L16. |
| L05.2 | Pending | Add resumable scans and suffix invalidation. | Cancellation and edits must not retain indexes for old bytes. | L05.1, L03, L06 | Check resume, cancellation, source changes, edits before checkpoints, retained prefixes, and rebuilt suffixes. | Publish only valid index state. Preserve upstream scan and checkpoint bounds. |

### L06: cancellable work

All L06 children use `W:src/analysis.rs:12`, `W:src/analysis.rs:84`, and `W:src/workbench.rs:192`.
Linux tools currently run synchronously at `L:src/workbench.rs:356`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L06.1 | Pending | Add cancellable work and source stamps. | Background results can become stale when the source or edit state changes. | L02 | Check cancellation, errors, progress, generation changes, stale-result rejection, and complete-result publication. | Reuse one shared worker contract. Do not publish partial results as completed results. |
| L06.2 | Pending | Connect work to Linux input polling. | Long operations must process Escape and resize without losing queued keys. | L06.1 | Check Escape, idle resize, normal input, queued keys, completion races, and error restoration. | Preserve the existing Linux terminal adapter. Do not import Windows console events. |

### L07: architecture domains

All L07 children use `W:src/format.rs:16`, `W:src/format.rs:2762`, `W:src/decoder.rs:192`, `W:src/decoder.rs:286`, `W:src/decoder.rs:390`, `W:src/assembler.rs:55`, and `W:src/assembler.rs:68`.
Reuse the Linux native loader at `L:src/native.rs:23`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L07.1 | Pending | Define architecture and decode domains. | Format, decoder, and assembler choices need one checked architecture contract. | L02, L06 | Check widths, byte order, alignment, typed errors, decoder reuse, invalid-byte fallback, and x86 AVX cases. | Keep Capstone 5.0.9 and Keystone 0.9.2. Keep Intel as the default. |
| L07.2 | Pending | Add ARM and Thumb engine behavior. | The current x86-only paths cannot inspect ARMv6, Thumb, or ARM64 sources. | L07.1 | Check ARMv6 and Thumb decoding and assembly, ARM64 decoding, alignment, and missing-engine behavior. | ARM64 assembly remains unsupported. The Linux host remains x86-64 GNU. |
| L07.3 | Pending | Extend raw architecture overrides. | Explicit raw domains must override format metadata consistently in all consumers. | L07.1, L07.2 | Check grammar, AUTO, base overflow, widths, byte order, format override, file or VA mapping, and transient state. | Preserve separate Real16 behavior and explicit AT&T display. Keep Intel assembly input. |

### L08: PE, ELF, and Mach-O metadata

All L08 children use `W:src/format.rs:3255`, `W:src/format.rs:3698`, `W:src/format.rs:4128`, `W:src/format.rs:6152`, and `W:src/format.rs:6362`.
Linux has partial PE support and raw ELF fallback.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L08.1 | Pending | Extend PE metadata and checked mappings. | Existing PE tools need high offsets and current logical bytes. | L02, L07 | Check edited headers, bounded reads, directories, gaps, aliases, virtual-only bytes, malformed ranges, and buffered or paged mapping agreement. | Keep browser routes within upstream support. Do not add runtime rebasing. |
| L08.2 | Pending | Add supported ELF metadata and mappings. | Linux currently treats ELF data as raw bytes. | L02, L07 | Check supported machines, ARM machine 40, entry points, segments, high offsets, malformed ranges, and current edits. | Little-endian only. Exclude ET_CORE, symbols, runtime rebasing, and general relocation analysis. |
| L08.3 | Pending | Add supported Mach-O metadata and mappings. | Thin Mach-O images need checked address navigation like the other supported formats. | L02, L07 | Check supported machines, load commands, entries, sections, malformed ranges, current edits, and high offsets. | Thin little-endian Mach-O only. Do not add fat or big-endian variants. |

### L09: legacy and compact executable formats

All L09 children use `W:src/format.rs:221`, `W:src/format.rs:523`, `W:src/format.rs:1564`, `W:src/format.rs:1673`, `W:src/format.rs:1744`, `W:src/format.rs:1900`, `W:src/format.rs:2000`, and `W:src/format.rs:2136`.
Linux currently rejects legacy formats and has no TE detection.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L09.1 | Pending | Add NE format behavior. | Segmented NE images require separate checked address and width rules. | L02, L07 | Check detection, segments, entries, required tables, mixed widths, malformed records, and buffered or paged agreement. | Implement only current NE source behavior. |
| L09.2 | Pending | Add LE and LX format behavior. | Object and page mappings differ from PE and NE mappings. | L02, L07 | Check both formats, object and page tables, mixed widths, entries, malformed ranges, and buffered or paged agreement. | Preserve upstream mapping limits and unsupported cases. |
| L09.3 | Pending | Add TE and TE64 format behavior. | Stripped firmware headers need adjusted offsets and architecture selection. | L02, L07 | Check both widths, stripped offsets, sections, entries, malformed ranges, and buffered or paged agreement. | Preserve checked bounds and current source routes. |
| L09.4 | Pending | Add NLM, LAN, and DSK behavior. | Required NetWare formats currently stop at format rejection. | L02, L07 | Check all three formats, required records and tables, entries, malformed inputs, and buffered or paged agreement. | Do not infer undocumented loaders or executable behavior. |

### L10: branch controls and assembly previews

All L10 children use `W:src/decoder.rs:538`, `W:src/format.rs:2876`, `W:src/main.rs:6230`, and `W:src/main.rs:7753`.
Linux already has the D04 navigation and D06 preview foundations.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L10.1 | Pending | Extend branch controls and histories. | Existing branch actions must match current markers and every supported address domain. | L03, L07, L08, L09, L15 | Check visible targets, marker actions, direct follow, exact return position, history bounds, high addresses, invalid targets, and domain changes. | Preserve current Linux Enter overlap behavior through L15. Do not add indirect-target analysis. |
| L10.2 | Pending | Extend assembly preview transactions. | New architecture and span paths must show the exact proposed edit before application. | L10.1 | Check bytes, changed instructions, retained tails, overlap, EOF growth, decode disagreement, cancel, apply, undo, and resize. | Preview changes no bytes. Disk save remains separate. ARM64 assembly remains unsupported. |

### L11: selected-block operations

All L11 children use `W:src/block.rs:28`, `W:src/block.rs:126`, `W:src/main.rs:3354`, and `W:src/main.rs:3677`.
Linux currently provides Fill and XOR only.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L11.1 | Pending | Add selection and fixed-length block actions. | Shared selection state must give copy, fill, and XOR the same checked range. | L03, L14, L15 | Check selection bounds, empty ranges, overlap, buffer limits, exact bytes, and one-step undo or redo. | Preserve the regular-file 64 MiB block limit. Add no implicit disk writes. |
| L11.2 | Pending | Add move, insert, and delete actions. | Structural block changes must relocate bytes and annotations as one operation. | L11.1 | Check overlap directions, insertion points, EOF, arithmetic overflow, annotation relocation, no-op behavior, and exact history. | Respect transaction limits. Device sources must reject length changes when L30 connects them. |
| L11.3 | Pending | Add block import and export. | Block file I/O needs guarded publication and source-alias checks. | L11.2, L04 | Check source aliases, partial reads, staged output, existing destinations, cancellation, imported bytes, and undo. | Keep device commit integration in L30. Preserve genuine I/O errors. |

### L12: 64-bit crypt

All L12 children use `W:src/crypt.rs:13`, `W:src/crypt.rs:79`, `W:src/crypt.rs:141`, `W:src/crypt.rs:181`, `W:src/crypt.rs:285`, `W:src/crypt.rs:385`, `W:src/crypt.rs:403`, and `W:src/crypt.rs:663`.
Linux only has repeating XOR.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L12.1 | Pending | Add the 64-bit crypt interpreter. | Repeating XOR cannot execute the current crypt language or its offset-dependent operations. | L03 | Replay reference vectors. Check grammar, wrapping, high offsets, incomplete units, and arithmetic errors. | Preserve the upstream language. Do not add algorithms or syntax. |
| L12.2 | Pending | Connect prepared crypt edits. | Cancellation or an interpreter error must not apply only part of a transformation. | L12.1, L04, L06, L11 | Check setup retention, program load and store, preparation, cancellation, atomic errors, application, undo, redo, and each viewer route. | Keep separate limits: 32 MiB buffered setup, 64 KiB paged setup, and 64 MiB selected regular-file blocks. |

### L13: verified patches and SHA-256

All L13 children use `W:src/patch.rs:16`, `W:src/patch.rs:223`, `W:src/patch.rs:369`, `W:src/patch.rs:505`, `W:src/patch.rs:659`, and `W:src/patch.rs:704`.
Linux lacks verified patches and SHA-256 support for these workflows.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L13.1 | Pending | Add streaming source hashes. | Patch and companion identity checks need SHA-256 over exact source bytes with bounded memory. | L02, L06 | Check known vectors, empty sources, chunk boundaries, current source stamps, cancellation, and large sources. | Use portable Linux support. The legacy checksum is not SHA-256. |
| L13.2 | Pending | Add verified patch parsing and application. | A patch must match source identity and original bytes before changing the editor. | L13.1, L03 | Check grammar, source size and hash, old bytes, ranges, limits, atomic failure, round-trip input, one undo, and one redo. | Version one allows equal-length replacements and one final append. Preserve 4,096 records, 64 MiB payload, and 129 MiB input. |
| L13.3 | Pending | Add guarded patch export and commands. | Users need net-difference export and import through the current workbench controls. | L13.2, L04, L15 | Check baseline differences, output grammar, round-trip, destination refusal, source changes, cancel, and command reachability. | Preserve upstream viewer routes. Do not add paged patch-tool routes. |

### L14: annotations

All L14 children use `W:src/editor.rs:15`, `W:src/editor.rs:282`, `W:src/editor.rs:309`, `W:src/editor.rs:819`, and `W:src/workbench.rs:1351`.
Linux lacks annotation state.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L14.1 | Pending | Add annotation state and edit snapshots. | Byte splices and history must retain the annotations attached to current ranges. | L03, L13.1 | Check 256 records, nonempty half-open ranges, 1,024-byte UTF-8 text, controls, relocation, snapshots, undo, redo, and cancellation. | Store exact annotation state in existing transactions. Session encoding belongs to L25. |
| L14.2 | Pending | Add annotation controls and source guards. | Users need checked annotation changes and navigation without losing source-bound state. | L14.1, L15 | Check create, read, update, delete, jumps, byte-edit guards, source mismatch, file switching, Save As, and resize. | Permit navigation during byte edits. Preserve upstream change restrictions and buffered viewer routes. |

### L15: terminal appearance and controls

All L15 children use `W:src/console.rs:32`, `W:src/console.rs:318`, `W:src/console.rs:697`, `W:src/console.rs:812`, `W:src/console.rs:1902`, `W:src/main.rs:1723`, and `W:src/main.rs:7778`.
Linux already has terminal input and frame output.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L15.1 | Pending | Add the current palette and frame layout. | Existing terminal output does not match the current Windows visual structure closely enough. | L01.2 | Compare semantic colors, fixed headers and footers, mode rows, standard sizes, small sizes, and clipping against source-defined layouts. | Reuse Linux frame output. Permit terminal theme and font differences. |
| L15.2 | Pending | Add current dialog behavior. | Prompts and browsers must remain readable and stable when terminal dimensions change. | L15.1 | Check dialog frames, selection, scrolling, resize, dismissal, errors, cursor visibility, and terminal restoration. | Reuse established modal functions. Do not add a second UI system. |
| L15.3 | Pending | Align current controls and help. | Linux key encodings must keep Windows actions reachable without breaking Enter behavior. | L15.2 | Check Enter mode cycle, Code follow, F4 choices, Hex F2, Code End, modifier alternatives, prompts, and documented key reachability. | Preserve the Ctrl+M and Enter overlap. Enhanced keyboard protocols remain optional. |

### L16: Unicode Text

All L16 children use `W:src/console.rs:352`, `W:src/console.rs:384`, `W:src/console.rs:452`, `W:src/text_index.rs:19`, `W:src/text_index.rs:586`, `W:src/text_index.rs:979`, `W:src/editor.rs:1066`, and `W:src/editor.rs:1129`.
Linux has CP437 display and refuses Text editing.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L16.1 | Pending | Add the four Text codecs and input. | Byte-only Text behavior cannot display or accept the current Unicode encodings. | L05, L15 | Check CP437, UTF-8, UTF-16LE, UTF-16BE, BOM behavior, invalid units, input conversion, and encoding boundaries. | Preserve exact bytes and the existing path policy. Reuse the upstream Unicode crates. |
| L16.2 | Pending | Add grapheme layout and movement. | Byte-based cursor steps can split a character or produce incorrect screen positions. | L16.1 | Check combining characters, wide characters, tabs, delimiters, wrapping, horizontal movement, row limits, and carried graphemes. | Preserve 64 KiB rows and 4 KiB carry. Do not claim terminal font equivalence. |
| L16.3 | Pending | Add Text edit transactions. | Encoded edits must update byte spans, indexes, cursor positions, and history together. | L16.2, L03, L04 | Check insertion, replacement, deletion, encoding boundaries, undo, redo, cancel, save, and files above memory limits. | Use shared transactions and suffix invalidation. Preserve current upstream edit routes. |

### L17: byte, encoded, and instruction search

All L17 children use `W:src/instruction_search.rs:15`, `W:src/instruction_search.rs:44`, `W:src/instruction_search.rs:200`, `W:src/operations.rs:22`, `W:src/operations.rs:95`, and `W:src/operations.rs:424`.
Linux currently has basic byte search.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L17.1 | Pending | Extend byte and encoded search. | Current search cannot handle all codecs and large logical sources consistently. | L02, L06, L16 | Check masked bytes, text encoding, overlap, both directions, repeat, EOF, current spans, and read-window crossings. | Preserve bounded reads and the current search grammar. |
| L17.2 | Pending | Add instruction-pattern search. | Decoded instruction clauses need architecture-aware matching beyond byte patterns. | L17.1, L07 | Check reference patterns, every supported architecture, clause matching, alignment, invalid decoding, and current edits. | Preserve 1,023 ASCII bytes and 16 clauses. Do not add general semantic analysis. |
| L17.3 | Pending | Add search continuation pages. | Large result sets need bounded navigation without losing repeat state or source validity. | L17.2 | Check page boundaries, forward and backward continuation, independent state, source changes, cancellation, jumps, and no partial publication. | Keep current result and scan bounds. Do not materialize the complete result set. |

### L18: inspection tools

All L18 children use `W:src/inspect.rs:19`, `W:src/inspect.rs:52`, `W:src/inspect.rs:95`, `W:src/inspect.rs:240`, `W:src/inspect.rs:364`, `W:src/inspect.rs:500`, `W:src/inspect.rs:538`, and `W:src/inspect.rs:596`.
Linux has ASCII Strings, entropy, and integer tools.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L18.1 | Pending | Extend Strings, lazy full text, continuation pages, and entropy. | Current tools need Unicode recognition, bounded page navigation, and cancellation during longer scans. | L06, L16 | Check byte offsets, invalid text, minimum lengths, truncated rows, lazy full text, and continuation pages. Check entropy boundaries, result limits, cancellation, and source changes. | Keep these tools buffered-only where upstream does. Do not add paged viewer routes. |
| L18.2 | Pending | Extend typed value inspection. | Current integer-only tools lack floating-point and GUID or UUID representations. | L07, L15 | Check widths, byte order, signed values, exact NaN bits, GUIDs, UUIDs, truncation, and boundary reads. | Preserve source bytes and upstream interpretation rules. |
| L18.3 | Pending | Add structure templates and browsing. | Dependent lengths and pointers need bounded validation before structure fields become jump targets. | L06, L08, L09, L16, L18.2 | Check field bounds, dependent lengths, pointers, malformed structures, browser limits, jumps, and cancellation. | Reuse checked format domains. Keep upstream buffered-only routes. |

### L19: aligned comparison

All L19 children use `W:src/operations.rs:485`, `W:src/operations.rs:491`, `W:src/operations.rs:592`, `W:src/operations.rs:654`, `W:src/workbench.rs:735`, and `W:src/workbench.rs:848`.
Linux only compares equal offsets.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L19.1 | Pending | Add stable aligned comparison spans. | Insertions and deletions require independent source positions instead of equal-offset pairing. | L02, L06 | Check equal runs, changes, insertions, deletions, repeated anchors, unresolved spans, peer identity changes, and cancellation. | Preserve bounded source access and upstream comparison limits. Keep buffered-only viewer integration where upstream does. |
| L19.2 | Pending | Add comparison pages and patch export. | Users need to navigate aligned differences and export only representable patch changes. | L19.1, L04, L13, L15 | Check pages, both-source jumps, source changes, unresolved spans, canceled work, valid export, and unsupported export refusal. | Keep patch version-one restrictions. Do not fabricate alignment or patch records. |

### L20: 64-bit calculator

All L20 children use `W:src/calculator.rs:8`, `W:src/calculator.rs:23`, `W:src/calculator.rs:90`, `W:src/calculator.rs:314`, `W:src/calculator.rs:424`, and `W:src/main.rs:5264`.
Linux lacks the calculator.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L20.1 | Pending | Add the 64-bit calculator evaluator. | Offset calculations need the reference grammar and wrapping arithmetic behavior. | L01.2 | Replay all 111 vectors. Check precedence, shifts, wrapping, division, invalid tails, and 68-byte input. | Preserve the exact language. Do not add evaluation features. |
| L20.2 | Pending | Add calculator controls and retained results. | Users need base conversion and reusable results while staying at the current viewer position. | L20.1, L02, L07, L15 | Check overlays, bases, retained results, address insertion, 64 history entries, cancel, and resize. | Keep calculator history separate from navigation and edit history. |

### L21: Code and Hex references

All L21 children use `W:src/decoder.rs:412`, `W:src/workbench.rs:104`, `W:src/format.rs:2534`, and `W:src/format.rs:2908`.
Existing branch follow is a different operation.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L21.1 | Pending | Add Code and Hex reference matching. | Reference search needs local address domains and width rules beyond direct branch following. | L07, L08, L09, L17 | Replay raw, PE, NE, ELF, LE, and LX cases. Check widths, local domains, invalid targets, and architecture-specific decoding. | Preserve source-defined reference types. Do not infer arbitrary pointer types. |
| L21.2 | Pending | Add reference controls and independent state. | Reference stepping must not overwrite ordinary search or branch-return positions. | L21.1, L15 | Check controls, repeat, continuation pages, jumps, cancellation, source changes, and separate state. | Reuse bounded search and browser contracts. Do not add global cross-file analysis. |

### L22: Names and companions

All L22 children use `W:src/names.rs:41`, `W:src/names.rs:147`, `W:src/names.rs:182`, `W:src/names.rs:214`, `W:src/names_store.rs:28`, `W:src/names_store.rs:146`, and `W:src/names_store.rs:209`.
Linux lacks Names and companions.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L22.1 | Pending | Add Names domains and imports. | Imported labels need checked offsets and source-specific address conversion. | L08, L09 | Check grammar, CP437 input, address domains, shifts, duplicates, invalid ranges, 256 entries, and 1,024-byte text. | Preserve current import formats. Do not add symbol analysis excluded from format scope. |
| L22.2 | Pending | Add Names manager controls. | Users need filtering, navigation, and deletion of imported labels. | L22.1, L15 | Check selection, filters, jumps, deletion, limits, cancel, and resize. | Keep Names separate from annotations while reusing existing browser controls. |
| L22.3 | Pending | Add source-bound Names companions. | A Names file must not silently apply to a changed or substituted source. | L22.2, L04, L13.1 | Check identity, companion read and write errors, source changes, Save As, guarded publication, and mismatch handling. | Preserve current source-binding and destination rules. Session encoding belongs to L25. |

### L23: configuration and CLI compatibility

All L23 children use `W:src/config.rs:74`, `W:src/config.rs:137`, `W:src/config.rs:287`, `W:src/config.rs:313`, `W:src/config.rs:676`, and `W:src/config.rs:714`.
Keep Linux discovery at `L:src/config.rs:215`.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L23.1 | Pending | Extend current configuration parsing. | New architecture, display, Text, and legacy OEM settings need validation without changing Linux discovery. | L01.2, L07, L15, L16 | Define supported OEM code pages and configuration spelling. Check keys, duplicates, invalid values, 256 KiB inputs, atomic failure, headers, and precedence. | Preserve Linux sibling, XDG, explicit, and portable discovery. Keep compatibility identifiers unchanged. |
| L23.2 | Pending | Extend CLI and legacy compatibility. | Startup paths and offsets must retain option boundaries while exposing current settings. | L23.1 | Check quoting, offsets, high values, boundaries, legacy forms, Unicode, non-UTF-8 native paths, escaped display, and exact errors. | Preserve `PathBuf` and `OsString` identity. Never derive a path from display text or select a substitute path. |

### L24: file picker, traversal, and history

All L24 children use `W:src/files.rs:12`, `W:src/files.rs:31`, `W:src/files.rs:375`, `W:src/files.rs:444`, `W:src/main.rs:1804`, and `W:src/main.rs:1893`.
Linux has a picker but lacks current traversal bounds.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L24.1 | Pending | Extend picker controls and bounded traversal. | Recursive selection must match current controls without unbounded directory or result growth. | L04, L15, L23 | Check native pathname bytes, escaped display, sort, hidden files, masks, links, cycles, errors, recovery folders, and traversal limits. | Keep operational paths separate from display text. Do not follow a substitute target. |
| L24.2 | Pending | Add visit history and file marks. | Users need retained picker positions and selected files across file changes. | L24.1 | Check 256 visits, native path identity, marks, reopen behavior, stale paths, selection, and recovery folders. | Keep persistent session encoding in L25. Preserve source-defined history limits. |

### L25: legacy and modern sessions

All L25 children use `W:src/config.rs:816`, `W:src/config.rs:937`, `W:src/config.rs:1132`, `W:src/config.rs:1288`, `W:src/session.rs:19`, `W:src/session.rs:55`, `W:src/session.rs:199`, and `W:src/session.rs:337`.
Linux currently has legacy SAV and the Real16 extension.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L25.1 | Pending | Extend legacy SAV records. | Legacy persistence needs explicit OEM conversion beside annotation, visit-history, and Real16 data. | L07, L13, L14, L16, L22, L24.2 | Check visit history, annotations, source guards, corrupt suffixes, unknown payloads, Real16 coexistence, and representation limits. Check that Names use companions and modern sessions. Check ASCII paths without selection. Check strict selected OEM conversion, exact round trips, and missing or invalid selections. | Preserve 24-file SAV limits, fixed identifiers, and fewer-than-260-byte path limits. Do not expand the format or overwrite unknown data. |
| L25.2 | Pending | Add modern session versions 1 through 6. | Current UTF-8 sessions need larger file sets and must reject unrepresentable native paths before publication. | L25.1, L24 | Check all six versions, version-six output, 256 files, 16 MiB input, identities, UTF-8 representation, bounds, and malformed data. | Do not add a new session encoding or expand old binary formats. |
| L25.3 | Pending | Connect session lifecycle and guarded writes. | File switching, Save As, and restart must restore the same accepted editor state. | L25.2, L04 | Check native paths, Save, Save As, active and inactive files, annotations, Names, visits, modes, Real16, paged limits, and restart. Check source mismatches, write errors, retained editor state, and existing session bytes. | Report persistence failure separately. Do not block native file work, claim persistence success, or convert a path lossily. Do not claim unsupported paged tool persistence. |

### L26: macro banks and recording

All L26 children use `W:src/macros.rs:12`, `W:src/macros.rs:21`, `W:src/macros.rs:68`, `W:src/macros.rs:109`, `W:src/macros.rs:208`, and `W:src/console.rs:1509`.
Linux only has partial startup playback.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L26.1 | Pending | Add macro slots and bank data. | Startup playback alone cannot retain ten recorded macros or exact Unicode events. | L15, L16 | Check ten slots, 1,024 events per slot, modifiers, Unicode events, overflow, malformed banks, and 256 KiB input. | Preserve event semantics. Do not store Windows console records. |
| L26.2 | Pending | Add recording and cancellable playback. | Playback delays and prompts must not lose user input or overwrite retained slots. | L26.1, L04, L06 | Check recording, prompts, stop-on-notice, repeat, retention, guarded bank writes, queued keys, abort, and delay cancellation. | Use Linux controls and existing input polling. Preserve upstream recording restrictions. |

### L27: multi-file replacement and recovery

All L27 children use `W:src/save.rs:475`, `W:src/save.rs:512`, `W:src/save.rs:576`, `W:src/save.rs:743`, `W:src/save.rs:992`, `W:src/save.rs:1136`, and `W:src/save.rs:1393`.
Linux lacks batch journals and startup rollback.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L27.1 | Pending | Prepare selected multi-file replacements. | Users need bounded replacements across explicitly selected files before publication starts. | L04, L06, L17, L24 | Check selected targets, file and result limits, aliases, source changes, cancellation, and prepared replacement bytes. | Change no destination during preparation. Preserve exact source and selection identity. |
| L27.2 | Pending | Add journaled publication and rollback. | A failed batch must identify published files and retain enough data for recovery. | L27.1 | Check journal bounds, locks, publication order, interrupted commits, rollback, write failures, and retained recovery artifacts. | Reuse Linux save rules. Report partial outcomes accurately when rollback fails. |
| L27.3 | Pending | Add startup recovery. | Interrupted batches need validated recovery before users resume normal work. | L27.2 | Check valid and corrupt journals, stale locks, target substitution, incomplete rollback, recovery prompts, and retained files. | Use disposable files and injected interruptions. Do not silently discard unresolved recovery data. |

### L28: YARA-X signatures

All L28 children use `W:src/signatures.rs:22`, `W:src/signatures.rs:47`, `W:src/signatures.rs:457`, and `W:src/workbench.rs:371`.
Linux needs its own child-process adapter.
Preserve the 64 MiB buffered-input limit and the 4 MiB top-level rule limit.
Preserve the 4 MiB combined stdout and stderr limit and the 10,000-row limit.
Preserve the 60-second deadline and the 512 MiB aggregate memory limit.
Canonicalize the top-level rule and use its directory for relative includes.
Keep included files as engine inputs without snapshots or an aggregate 4 MiB include limit.
The deadline covers snapshot creation, execution, and parsing.

Use `HVIEW_YARAX` authoritatively. Otherwise, search a sibling `yr` and then nonempty `PATH` entries.
Use a complete executable path, argument vectors, concurrent bounded pipe draining, and complete validated results.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L28.1 | Pending | Add bounded Linux scanner execution. | Current YARA-X behavior needs enforceable aggregate memory and descendant containment. | L01.2, L04, L06 | Select the mechanism and host prerequisites. Check pre-execution containment, aggregate memory, retained pipes, cleanup cases, limits, paths, diagnostics, and cancellation. | Return a capability error if controls are unavailable. Do not use a shell, weaker limits, Windows APIs, or unsupported containment claims. |
| L28.2 | Pending | Add signature workflow controls. | Signature results must describe the current unsaved bytes and remain valid for navigation. | L28.1, L15 | Check rules, temporary input, unsaved bytes, result bounds, source changes, diagnostics, jumps, cancellation, and cleanup. | Preserve current buffered-only routes. Do not add remote scanning or a new scanner engine. |

### L29: reports and PE checksum

All L29 children use `W:src/workbench.rs:2136`, `W:src/workbench.rs:2264`, and `W:src/main.rs:2226`.
Linux lacks current location export and PE checksum actions.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L29.1 | Pending | Add location reports and debugger text. | Users need current address-domain reports that external tools can read. | L04, L06, L08, L09, L15 | Check raw and format addresses, report bounds, debugger text, current edits, destination refusal, and cancellation. | Export text only. Do not launch debugging tools. |
| L29.2 | Pending | Add confirmed PE checksum adjustment. | Edited PE data needs the reference checksum correction as an undoable edit. | L03, L08, L15 | Replay checksum vectors. Check malformed PE data, preview, no-op, cancel, application, undo, and redo. | Change bytes only after confirmation. Use the existing save path for disk publication. |

### L30: raw-device access and commits

All L30 children use `W:src/device.rs:97`, `W:src/device.rs:215`, `W:src/device.rs:317`, `W:src/device.rs:361`, `W:src/device.rs:422`, `W:src/paged.rs:191`, `W:src/paged.rs:1248`, `W:src/paged.rs:1291`, and `W:src/paged.rs:1354`.
Linux has no device adapter.
The user accepted raw-device editing and the override.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L30.1 | Pending | Add read-only block-device access. | Raw drives, partitions, and logical volumes need device identity and actual size instead of regular-file assumptions. | L01.2, L02, L24 | Check whole devices, partitions, logical volumes, identity, length, bounded reads, permissions, and device selection. | Open read-only by default. Test disposable virtual devices only. |
| L30.2 | Pending | Add writable mode and the user override. | Mounted, in-use, or nonexclusive state must not become an unconditional product-level write prohibition. | L30.1, L03, L11 | Check explicit writable mode, state detection, override selection, fixed-length edits, bounds, and rejection of unsupported length changes. | Preserve permission controls and operating-system errors. Do not unmount devices or change privileges automatically. |
| L30.3 | Pending | Add confirmed device commits and verification. | Device writes can partially succeed and need exact commit ranges, verification, and recovery information. | L30.2, L04 | At commit, check device and range identification and one damage warning. Check neighboring bytes, 64 KiB envelopes, flushes, read-back, refresh, recovery export, failures, and partial-write reporting. | Warn about filesystem damage, partial writes, and limited recovery once per commit. Use disposable virtual devices only. |

### L31: retained HEM functions

All L31 children use `W:src/hem.rs:87`, `W:native/hem_host.c:1186`, `W:native/hem_host.c:1376`, `W:docs/hem-protocol.md:25`, `W:docs/hem-protocol.md:132`, `W:docs/hem-protocol.md:187`, and `W:docs/hem-protocol.md:198`.
They also use `W:docs/hem-collection.md:3`, `W:docs/hem-collection.md:38`, `W:docs/hem-collection.md:46`, `W:docs/hem-collection.md:54`, `W:docs/hem-collection.md:68`, and `W:docs/hem-collection.md:82`.
The collection has 29 unique modules across 34 paths.
Windows binary hosting is reference evidence, not the retained function contract.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L31.1 | Pending | Inventory retained and excluded HEM functions. | The accepted exclusion applies to Windows-specific modules, not every function once exposed through HEM. | L01.1 | List each module and function, input and output behavior, required tables, limits, retained status, and each exclusion reason. | Planning only. Do not require Wine or a Windows DLL host because the collection uses DLL packaging. |
| L31.2 | Pending | Assign retained functions to bounded implementation goals. | The inventory must become named Linux workflows before implementation can be estimated or accepted. | L31.1 | Map each retained function to an existing module and child goal. Add L31.4 onward only for uncovered named workflows. Check dependency cycles and required acceptance evidence. | Planning only. Do not add a speculative plugin framework or one undefined implementation batch. Any new implementation goal requires L01.2. |
| L31.3 | Pending | Verify retained HEM coverage. | Every retained function needs Linux evidence after its assigned implementation goal passes. | L31.2 and every retained-function implementation goal recorded there | Check each retained workflow, input and output limits, companion behavior, errors, and source agreement. Record every excluded Windows-specific module and reason. | Do not require a Windows binary host for excluded modules. Do not complete coverage while an inventory entry lacks evidence. |

### L32: dependencies, CI, and packaging

All L32 children use `L:lib/native-dependencies.json:4`, `L:scripts/package.py:39`, and `L:.github/workflows/ci.yml:10`.
Keep the current native-loading and package baseline.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L32.1 | Pending | Update dependency provenance and notices. | Architecture support and Unicode imports can change package prerequisites and notice obligations. | L01.2 | Check locked versions, native source commits, hashes, transformations, architecture features, GNU prerequisites, and license files. | Do not assign the old C license to Rust source. Do not upgrade native engines for this task. |
| L32.2 | Pending | Extend Linux CI and package probes. | Current probes need to exercise the added guest architectures and dependencies. | L32.1, L07, L16 | Check ABI features, native self-test, missing libraries, independent execution, locked dependencies, and failure messages. | Keep Text and Hex usable without native engines. Do not search the current directory for libraries. |
| L32.3 | Pending | Verify the complete isolated package. | Early package checks cannot establish the final feature set outside the build tree. | L32.2, L02-L31 | Check final manifest, hashes, notices, ELF dependencies, glibc floor, clean extraction, isolation, and packaged feature probes. | Record exact artifact identity and environment. Historical package results do not satisfy this item. |

### L33: final acceptance

All L33 children use PLAN.md requirements, the current tracker crosswalks, UPSTREAM_REVIEW.md evidence, and historical VERIFICATION.md records.
The current full Rust suite has an environment-limited ACL failure.

| ID | Status | Deliverable | Why and context | Dependencies | Acceptance | Boundary |
|---|---|---|---|---|---|---|
| L33.1 | Pending | Run complete Rust and platform acceptance. | Feature checks need a current combined result, including the unresolved ACL environment requirement. | L02-L31, L32.2 | Pass formatting, full tests, strict Clippy, release build, native checks, and relevant Linux save and device checks. Run the unchanged ACL fixture where UID 1 is mapped. | Sol runs checks. Record failures accurately. Use disposable device tests only. |
| L33.2 | Pending | Run complete terminal and package acceptance. | Unit tests alone cannot establish key reachability, terminal restoration, or independent package behavior. | L33.1, L32.3 | Pass current PTY suites, standard and small terminal cases, restoration, Unicode, architecture controls, and packaged probes. | Record the tested terminal and package identity. Reuse valid current evidence when no new reason requires another run. |
| L33.3 | Pending | Complete parity records and Astra acceptance. | The project needs one current requirement matrix with explicit Linux differences and unresolved limits. | L33.2 | Update final records and all crosswalks. Obtain Astra xhigh acceptance for requirements, evidence, exclusions, and documented Linux differences. | Complete only after every required goal and check passes. Record exact next actions for remaining work. |

## Current documentation refinement

| Date | Change | Result | Next action |
|---|---|---|---|
| 2026-09-10 | Complete L01.2 authorization records. | The records authorize L02.1 only. Documentation checks and Astra xhigh review passed. | Plan L02.1 with Astra xhigh. Assign its bounded implementation to Sol xhigh under the recorded authorization. |
| 2026-09-10 | Publish L01.1 implementation contracts. | Commit `1a3877a459aa7bea0f4e6f9d3249b1adb4554fdc` reached `HView-Linux` `rust-rewrite`. Remote verification matched. | Execute L01.2. |
| 2026-09-10 | Complete L01.1 implementation contracts. | Documentation checks and Astra xhigh review passed. Application files remain unchanged. | Execute the user-authorized L01.2 planning item. |
| 2026-09-10 | Update the current model assignment. | Astra xhigh performs all planning and review. Sol xhigh performs all other work and runs all checks. Historical model evidence remains unchanged. | Start the first user-authorized tracker item. |
| 2026-09-10 | Split L01 through L33 into 85 small logical child goals. | The tracker records purpose, source context, dependencies, acceptance, boundaries, and independent Pending status. No application source or check result changed. | Obtain independent Astra review. Then present the detailed plan for user review before application implementation. |

### L01.1 documentation evidence

| Command | Result |
|---|---|
| `git diff -- AGENTS.md PLAN.md TRACKER.md UPSTREAM_REVIEW.md` | Inspected the complete documentation diff. |
| `git diff --check` | Passed. |
| `rg -n "L01\\.1\|L01\\.2\|PathBuf\|OsString\|GetOEMCP\|HVIEW_YARAX\|RLIMIT_AS\|educational block comments\|Astra xhigh\|Astra High" AGENTS.md PLAN.md TRACKER.md UPSTREAM_REVIEW.md` | Verified contracts, child statuses, current model settings, and unchanged historical model evidence. |
| `git diff --name-only -- src tests scripts Cargo.toml Cargo.lock .github` | Produced no output. Application files remain unchanged. |

No application suite ran because L01.1 changes documentation only.

Astra xhigh accepted L01.1 on September 10, 2026.
The review confirmed native pathname handling, strict OEM conversion, scanner limits, accepted platform policies, and educational source comments.
Documentation checks passed. Application files remain unchanged.

### L01.2 documentation evidence

| Command | Result |
|---|---|
| `git diff -- PLAN.md TRACKER.md UPSTREAM_REVIEW.md` | Inspected the complete L01.2 documentation diff. |
| `git diff --check` | Passed. |
| `rg -n "Current authorization:\|L01\\.2\|L02\\.1\|L02\\.2\|approval gate\|application authorization covers" PLAN.md TRACKER.md UPSTREAM_REVIEW.md` | Verified the authorization boundary, selected item, dependencies, and current status. |
| `git diff --name-only -- src tests scripts Cargo.toml Cargo.lock .github AGENTS.md` | Produced no output. Application files and AGENTS.md remain unchanged. |

No application suite ran because L01.2 changes documentation only.

Astra xhigh accepted L01.2 on September 10, 2026.
The user instruction ‘k, do the next thing’ authorizes the next selected item.
Current application authorization covers L02.1 only.
Documentation checks passed. Application files remain unchanged.

## Current stage sequence

| Stage | Tasks | Exit condition |
|---|---|---|
| Authorization records | L01 | Accepted platform contracts and scoped application authorization are recorded. |
| Shared foundation | L02-L06, L15 | Bounded storage, transactions, saves, Text indexing, cancellation, and terminal contracts pass. |
| Addresses and edit dependencies | L07-L10, L13, L14 | Architectures, mappings, navigation, previews, hashing, and annotation state pass. |
| Product workflows | L11, L12, L16-L24 | Editing, analysis, Unicode, controls, Names, configuration, and file workflows pass. |
| Persistent and external workflows | L25-L29 | Sessions, macros, batch recovery, signatures, and exports pass. |
| Platform completion | L30-L32 | Device, HEM, and independent package acceptance pass. |
| Final acceptance | L33 | Every requirement and Linux difference has current evidence and Astra acceptance. |

Tasks in one stage can have different dependencies.
Storage acceptance precedes dependent integration.
The historical D08-first order does not control this plan.
L32 can start early, but final package acceptance follows all included features.

## Requirement crosswalk

| Requirement | Current tasks |
|---|---|
| REQ01: bounded Text, Hex, and Code viewing and editing | L02-L05, L10, L16, L33 |
| REQ02: x86, x64, and AVX assembly and decoding | L07, L10, L32, L33 |
| REQ03: physical and logical drives | L01-L04, L11, L24, L30, L33 |
| REQ04: required executable formats | L07-L10, L33 |
| REQ05: NLM, LAN, and DSK | L09, L10, L33 |
| REQ06: direct branch follow and return | L07-L10, L15, L33 |
| REQ07: instruction-pattern search | L06, L07, L17, L33 |
| REQ08: 64-bit crypt | L03, L11, L12, L33 |
| REQ09: 64-bit calculator | L20, L33 |
| REQ10: selected-block operations | L03, L04, L11, L12, L14, L30, L33 |
| REQ11: multi-file replacement | L04, L06, L17, L24, L27, L33 |
| REQ12: keyboard macros | L15, L16, L26, L33 |
| REQ13: Unicode paths, Text, input, display, editing, search, and sessions | L03-L05, L15-L18, L23-L26, L33 |
| REQ14: retained HEM functions | L01, L03, L04, L08, L09, L11, L15, L22, L31-L33 |
| REQ15: ARMv6 and Thumb | L07-L10, L17, L25, L32, L33 |
| UX01: palette, function keys, Enter cycle, and branch markers | L10, L15, L16, L23, L24, L33 |

## Current upstream crosswalk

| Current Windows work | Current tasks |
|---|---|
| D01, D05, D10, D11 | L07 |
| D02, D03 | L08 |
| D04, D06 | L10 |
| D07, D08, D09 | L03, L13, L14 |
| D12-D15 | L17, L12, L20, L11 |
| S01-S04 | L02, L03-L06, L18 |
| S05, S07-S09 | L16-L19, L25 |
| S10-S14 | L28, L18, L16, L27, L26 |
| P01-P07 | L01, L15, L16, L23-L25, L27, L30, L32 |
| B01-B03, B05-B07 | L07-L09 |
| X01, X03 | L29, L31 |
| R01-R05 | L04, L23-L26 |
| R06-R13 | L32, L33 |
| DatRef, Refer, offset display, and reference stepping | L21, L23 |
| Names manager, imports, and companions | L22, L25 |
| Picker controls, masks, visits, and marks | L24, L25 |
| Text keys, Hex F2, and Code End controls | L10, L15, L16 |
| Legacy SAV and modern configuration | L23, L25 |
| PE checksum and location reports | L29 |

Only S06, B04, and X02 remain outside the current Windows scope.
They cover headless JSON analysis, Capstone 6, and general plugins or debugging tools.

## Historical accepted implementation record through D07

This table records the original D03 scope.
The table records the current status of each task.
Imported code requires Linux checks and Astra review before completion.
Use the Evidence column for implementation locations, checks, and review results.

| ID | Phase | Task | Status | Evidence |
|---|---|---|---|---|
| P1-01 | Foundation | Import Windows Rust modules, assets, and retained fixtures with source provenance | Complete | Imported from `97a308c4fadffa434e96cf4cab33591a26413f4e`; Astra accepted commit `77d4236` |
| P1-02 | Foundation | Add Linux terminal input, frame output, resizing, and state restoration | Complete | PTY passed restoration, idle resize, small help, prompts, key input, CP437, and safe rendering; Astra accepted |
| P1-03 | Foundation | Add native library loading, version checks, and missing-library behavior | Complete | Self-test and isolated package probe passed; native static review and Astra Phase 1 review passed |
| P1-04 | Foundation | Connect Text and Hex display, navigation, wrapping, tabs, and CP437 rendering | Complete | PTY passed Text and Hex without native libraries; Astra accepted |
| P1-05 | Foundation | Connect 16/32/64-bit Code display, movement, decoder reuse, and NOP/INT3 packing | Complete | Native Code checks passed; the focused packing test covers both bytes, settings, and the 15-byte limit; Astra accepted |
| P1-06 | Foundation | Connect help and prompts; check empty files, EOF, small terminals, and error exits | Complete | Empty-file, invalid-option, small-terminal, and saved-state checks passed; Astra accepted |
| P2-01 | File workflow | Add Linux arguments, absolute paths, option boundaries, and startup offset selection | Complete | GNU and legacy options; help without a TTY; strict UTF-8 argument error; Astra accepted `cd476bd` |
| P2-02 | File workflow | Add file picker, multiple files, next/previous selection, masks, and safe recursion | Complete | Picker, view restoration, recursion, Unicode paths, and symlink-cycle checks passed; Astra accepted |
| P2-03 | Configuration | Port configuration parsing and discovery; preserve implemented legacy settings | Complete | Native LF/UTF-8 header; sibling, XDG, portable, and explicit precedence checks passed; Astra accepted |
| P2-04 | Configuration | Replace Windows text detection; verify unsupported-text errors and Hex/Code fallback | Complete | BOM, zero-heavy, UTF-16, and inactive Hex/Code checks passed; Astra accepted |
| P2-05 | Sessions | Port save/restore, active file, view settings, capacity checks, and Linux path handling | Complete | Absolute identity, backslash, restart, 1..24 capacity, view, mode, offset, and path-limit checks passed; Astra accepted |
| P2-06 | Sessions | Preserve compressed imports, checksums, and unknown payloads; reject empty or invalid sessions | Complete | Legacy compressed fixtures, checksum failures, zero counts, truncation, and unknown payload retention passed; Astra accepted |
| P3-01 | Editing | Connect nibble edits, EOF extension, current-byte undo, and edit cancellation | Complete | `tests/reliability_probe.py` checks exact file bytes for all four workflows; Astra accepted |
| P3-02 | Editing | Port Intel assembly, address-aware encoding, and buffer extension | Complete | PTY checks Intel assembly, AT&T display with Intel seed, and EOF extension; Astra accepted |
| P3-03 | Recovery | Add replacement saves, content/identity checks, original backups, and failure recovery | Complete | Astra accepted the backend and the integrated reliability workflow |
| P3-04 | Recovery | Add Save As with atomic destination refusal and correct file/session updates | Complete | Target switch, restart, cancellation, refusal, and recovery checks passed; Astra accepted |
| P3-05 | Recovery | Verify metadata policy, links, permissions, flushes, save failures, and concurrent-change limits | Complete | Nine backend tests and external-change PTY passed; Astra accepted |
| P4-01 | Analysis | Connect exact and masked search with forward/backward repeat | Complete | Exact, masked, next, and previous search workflows passed; Astra accepted `3dbc021` |
| P4-02 | Analysis | Connect strings, entropy, comparison, and integer inspection | Complete | Checked string, entropy, comparison, and integer results passed; Astra accepted |
| P4-03 | Analysis | Connect repeating XOR and fill with checked edit ranges | Complete | Exact saved bytes and rejected out-of-range changes passed; Astra accepted |
| P4-04 | Analysis | Connect result browsers, selection jumps, cancellation, and result limits | Complete | Browser movement, selected offsets, and cancellation passed; Astra accepted |
| P4-05 | PE tools | Connect sections, directories, imports, exports, and overlay browsing | Complete | Generated PE32 and PE32+ structure fixtures passed; Astra accepted |
| P4-06 | PE tools | Connect checked offset/RVA/VA conversion; preserve separate legacy address behavior | Complete | PE32 and PE32+ file, RVA, and VA conversions passed; Astra accepted |
| P4-07 | Analysis | Verify all tools against unsaved buffers, malformed inputs, and range boundaries | Complete | Unsaved-buffer, invalid-pattern, cancellation, and boundary workflows passed; Astra accepted |
| P5-01 | Macros | Port macro events, startup playback, repeats, modifiers, and stop-on-notice behavior | Complete | `tests/macro_probe.py` passed both signatures, repeats, modifiers, notices, and Ctrl-key handling; Astra accepted `5febcd4` |
| P5-02 | Macros | Verify long-delay cancellation and preservation of queued input | Complete | The macro probe passed maximum-delay cancellation and preserved queued prompt input; Astra accepted |
| P5-03 | Linux behavior | Add reachable key alternatives and Linux shortcuts without prompt/edit conflicts | Complete | The macro probe passed Ctrl+S, Ctrl+Q, M, Enter, O, H/J/K/L, prompt, and edit conflicts; Astra accepted |
| P5-04 | Syntax | Add Intel/AT&T configuration; verify Intel defaults, explicit AT&T, and invalid-setting errors | Complete | `DisassemblySyntax` tests pass; assembly input and prompt seeds remain Intel; Astra accepted |
| P5-05 | Linux behavior | Retain verified real-mode decoding and optional invalid-byte display | Complete | The 228-row oracle replay and focused checks passed Real16, VMWRITE forms, targets, strict errors, and fallback; Astra accepted |
| P5-06 | Linux behavior | Permit raw ELF Code viewing without claiming ELF structure or address support | Complete | Linux behavior probe passed raw ELF Code decoding; PE-only address operations still reject ELF; Astra accepted |
| P6-01 | Release | Add Linux packaging, native provenance, hashes, notices, and native self-test | Complete | Final package passed native hashes, ELF checks, isolation, missing-library checks, and the native self-test; Astra accepted |
| P6-02 | Release | Add Linux CI, user documentation, and installation instructions | Complete | Release documentation and CI exist at `bc918c9`; Astra accepted the local checks and configuration |
| P6-03 | Verification | Pass formatting, Rust tests, strict Clippy, and a fresh release build | Complete | Format passed; 65 tests passed; strict Clippy passed; release build passed; Astra accepted |
| P6-04 | Verification | Pass terminal, recovery, session, macro, and native-library integration checks | Complete | All six application probes passed against the final packaged executable; Astra accepted |
| P6-05 | Verification | Verify package isolation, missing libraries, and decoder preparation measurements | Complete | Package isolation passed; final raw median/p95 was 24180/26064 ns; PE was 29850/31273 ns; Astra accepted |
| P6-06 | Final review | Have Astra check every function-matrix row and all documented Linux differences | Complete | Astra passed the 31-row matrix, Linux differences, final package, and branch evidence at `5febcd4` |

## Historical accepted D04 through D07 extension

The user approved this extension after the Windows update review.
Keep the accepted D03 evidence as the original baseline.
Use Sol xhigh for implementation and Astra High for each acceptance review.
Finish each stage before dependent source changes.

| ID | Task | Status | Evidence |
|---|---|---|---|
| D04 | Direct branch navigation, checked targets, return history, and F5 history correction | Complete | Astra accepted `1793755`; unit and PTY checks pass group targets, mappings, machines, syntax, Real16, histories, and F5 clearing |
| D05 | Transient raw runtime base, x86 width, integer byte order, and checked growth | Complete | Astra accepted `04e5610`; raw/AUTO, mapping, widths, byte order, growth, transient state, sessions, and Real16 separation pass |
| D06 | Nonmutating assembly preview with exact-byte confirmation | Complete | Astra accepted `d447c4d`; exact bytes, strict decoding, Real16, raw bounds, wrapping, resize gates, cancellation, and Apply passed |
| D07 | Grouped operation undo/redo with record and byte limits | Complete | Astra accepted `5e4ef68`; grouping, all record types, both limits, atomic refusal, raw redo, shortcuts, save resets, and failures pass |
| EXT-VERIFY | Final regression suite, isolated package, documentation, and Astra acceptance | Complete | Astra accepted source `5e4ef68`, records `56484b0`, all matrix rows, Linux differences, and the isolated package |

### Extension publication

The push published `72c68bf5d8c2bdf9d21aca449390a1a71ae0ad08` to `origin/rust-rewrite`.
The remote hash matched after publication. The application source remains the accepted `5e4ef68` source.
The Windows reference remains clean at `a3b7240`. The Linux default branch remains `main`.
Hosted CI passed for [72c68bf](https://github.com/lukecloud-cyber/HView-Linux/actions/runs/33989620026).
The hosted run passed formatting, 83 Rust tests, strict Clippy, release/native checks, ten application probes, and the isolated package.
The final publication record changes documentation only. The accepted application source and checked package remain unchanged.

## Historical D08 and D09 proposal

This proposal used Windows source `624e3cc924da5c1d3a74a06eca82771079cb80bc`.
Exactly two application commits follow the accepted `a3b7240` D07 source.
D08 is `c8d195a`, and D09 is `624e3cc`.
The proposal did not include later implemented Windows work.
The L01 through L33 plan supersedes its task order and exclusions.

| ID | Historical task | Historical status | Current mapping |
|---|---|---|---|
| D08 | Verified patch import and export | Pending | L13 and L19 |
| D09 | Bounded annotations and session persistence | Pending | L14 and L25 |
| CURRENT-VERIFY | Complete regression suite and isolated package | Pending | L32 and L33 |

Do not use the historical D08-first sequence for current work.

## Historical completed planning and setup

| Date | Work | Evidence |
|---|---|---|
| 2026-09-05 | Analyzed the Windows implementation | Source baseline `97a308c4fadffa434e96cf4cab33591a26413f4e`; full function matrix in PLAN.md |
| 2026-09-05 | Reviewed the previous Linux implementation | Source baseline `35dbd0bbdfba08c1d3062bbeb65d5c6abcd29771`; tests and diagnostic findings below |
| 2026-09-05 | Renamed the local folder and GitHub repository | HView-Linux; existing public visibility and default branch preserved |
| 2026-09-05 | Created and pushed the empty orphan branch | `rust-rewrite`, root commit `4ded82f485022075d061588a090cb8ddbfa03406`; remote hash verified |
| 2026-09-05 | Reviewed the implementation plan | Astra High; six implementation phases with acceptance checks |
| 2026-09-05 | Set the syntax requirement | User selected Intel default and optional AT&T configuration |
| 2026-09-05 | Added persistent project records | PLAN.md, TRACKER.md, and AGENTS.md |
| 2026-09-05 | Reviewed persistent project records | Astra High found no material gaps in task coverage, decisions, evidence, or resume instructions |

## Historical baseline checks and known findings

The following results describe the source projects before the Linux Rust rewrite.
These results do not establish Linux feature parity.

| Check | Result | Limit |
|---|---|---|
| Portable Windows Rust modules | 23 tests passed using direct `rustc --edition=2024 --test` builds | CLI 2, checksum 1, format 10, inspection 4, operations 4, macros 2 |
| Previous Linux standalone tests | 41 tests passed with GCC C17, strict warnings, ASan, and UBSan | Six programs; complete CMake suite and real Zydis integration not run |
| Windows tracker evidence | Records 40 passing Rust tests and additional Windows checks | Windows-only checks were not rerun on this Linux computer |
| Previous Linux complete build | Not run | CMake unavailable; Zydis submodule uninitialized during review |
| New Linux Rust build | Release build passed; native self-test passed | Linux x86-64 host only |

## Historical implementation checks through September 5

The table records results from September 5, 2026.
The table does not describe the September 10, 2026, source review.

| Check | Result |
|---|---|
| `cargo test -- --test-threads=1` | 54 passed; one manual benchmark ignored |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed for the Phase 2 candidate |
| `cargo fmt --all -- --check` | Passed for the Phase 2 candidate |
| `cargo clean && cargo build --locked --release` | Passed for the Phase 2 candidate |
| `target/release/hview-linux --self-test` | Passed 16-bit, 32-bit, and 64-bit native checks |
| `python3 tests/terminal_probe.py target/release/hview-linux` | Passed all Phase 1 PTY checks |
| `python3 scripts/package.py /tmp/hview-linux-phase1-package-1788619612135433605` | Package and isolated native checks passed |
| `cargo test --locked -- --test-threads=1` | 60 passed; one manual benchmark ignored for the Phase 2 candidate |
| `python3 tests/file_workflow_probe.py target/release/hview-linux` | Passed native options, configuration, files, macros, and session workflows |
| `python3 tests/reliability_probe.py target/release/hview-linux` | Passed editing, assembly, Save As, recovery, and external-change workflows |
| `python3 -m py_compile tests/analysis_probe.py` | Passed for the Phase 4 candidate |
| `python3 tests/analysis_probe.py target/release/hview-linux` | Passed all Phase 4 analysis workflows in 13.4 seconds |
| `cargo test --locked --release d01_redraw_preparation_benchmark -- --ignored --nocapture --test-threads=1` | Passed; raw median 23833 ns and PE median 29062 ns |
| Temporary pinned Zydis C17 oracle | Built commit `1ba75ae` with Zycore `1401fb8`; the finite Real16 corpus passed |
| Generated Zydis protected-mode extraction | Returned the exact required set of 41 mnemonics |
| Tracked Zydis oracle replay | Built the tracked C harness; emitted 228 rows; exact 41-name extraction passed |
| `cargo test --locked --all-targets -- --test-threads=1` | 65 passed; one manual benchmark ignored for the corrected Phase 5 candidate |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed for the Phase 5 candidate |
| `cargo build --locked --release` | Passed for the Phase 5 candidate |
| `python3 tests/macro_probe.py target/release/hview-linux` | Passed macro, delay, modifier, notice, alias, prompt, and edit workflows |
| `python3 tests/linux_behavior_probe.py target/release/hview-linux` | Passed Code cycling, Real16, fallback, sessions, syntax, and raw ELF workflows |
| `python3 tests/navigation_probe.py target/release/hview-linux` | Passed direct branch, return, refusal, mapping, syntax, Real16, mode, and edited-byte workflows in 18.2 seconds |
| `python3 tests/raw_model_probe.py target/release/hview-linux` | Passed raw grammar, bounds, mapping, widths, byte order, history, transient state, AUTO, session, syntax, assembly, and growth workflows in 19.0 seconds |
| D06 strict local checks | Format, strict Clippy, release build, 79 tests, and nine application probes passed; one manual benchmark remained ignored |
| `python3 tests/patch_probe.py target/release/hview-linux` | Passed six exact-byte preview sessions with cancellation, Apply, resize, syntax, Real16, fallback, raw bounds, overlap, and EOF growth |
| D07 strict local checks | Format, strict Clippy, release build, native self-test, 83 tests, and ten application probes passed; one manual benchmark remained ignored |
| `python3 tests/edit_history_probe.py target/release/hview-linux` | Passed grouped nibbles, assembly growth, Fill, XOR, limits, resize, shortcuts, failure retention, save resets, and cancellation |
| Fresh D07 baseline checks at `f9c5299` | Format, strict Clippy, release build, native check, 83 tests, and all ten direct application probes passed; one benchmark stayed ignored |
| Fresh manual benchmark at `f9c5299` | Passed separately; raw median/p95 15889/16432 ns and PE median/p95 19698/21096 ns |
| Fresh package review at `f9c5299` | All ten packaged probes, manifest, hashes, ELF tags, isolation, native checks, and both missing-library checks passed |
| Six application probes against one release build | Terminal, file, reliability, analysis, macro, and Linux behavior probes passed |
| Final isolated package | `/home/sweet_cicero/Projects/HView-Linux/target/packages/hview-linux-x86_64-5febcd4`; executable SHA-256 `e0ebf155b1392a955aa1b2d941120889ef4e2511ebf6824a65e116ea696e12c7` |
| Final release benchmark | Raw median/p95 24180/26064 ns; PE median/p95 29850/31273 ns |

These checks ran on Linux x86-64 with Rust 1.98.0.
The fresh D08 and D09 analysis baseline used `/tmp/hview-linux-review-f9c5299-20260905`.
Its executable SHA-256 is `2943b0c5152f918e24d4d5ed7c39999113d435103136bfad6088342f1c77b506`.
The exact fresh check summary is `/tmp/hview-linux-review-f9c5299-20260905-checks.txt`.
The fresh save unit tests used `/tmp` on tmpfs.
Earlier accepted Btrfs save evidence remains separate.
The local CI-equivalent checks passed.
Hosted CI passed for [a2e6ddd](https://github.com/lukecloud-cyber/HView-Linux/actions/runs/33984434765).
Hosted CI also passed for [aa5bd96](https://github.com/lukecloud-cyber/HView-Linux/actions/runs/33984463090).
The Astra Phase 1 review passed at commit `77d4236bc355cdca517c094a45d3a12c766eaef1`.
The Astra Phase 2 review passed at commit `cd476bd2354dd30a545197b6d1ba2b674ff975e6`.
The Astra Phase 3 review passed at commit `1764904fde9a4d0fc8567f7b240c0087511972e2`.
The Astra Phase 4 review passed at commit `3dbc02179d96a782f7061aef07d7c5522189c135`.
The Astra Phase 5 review passed at commit `5febcd48d5d71642fd4d6eca7bd67ff273e149a4`.
The Astra Phase 6 and original D03 parity review passed at the same accepted source commit.
The D04 unit candidate has 70 passing tests and one ignored manual benchmark.
The D04 navigation probe passes supported and unsupported PE machines, checked mappings, direct targets, and return history.
The D05 candidate has 76 passing tests and one ignored manual benchmark.
The affected navigation, analysis, reliability, and Linux behavior probes pass with the D05 release build.
The D04 through D06 documentation passed Astra review at commit `ff71600`.
The D07 implementation candidate is `5e4ef682cda663f5f64c0700c6268c16d3850447`.
The candidate passes 83 Rust tests and all ten application probes.
Astra accepted D07 at this candidate after independent source, history, limit, raw redo, and terminal checks.
The fresh extension package passed all ten application probes with its packaged executable.
Native hashes, ELF tags, isolated loading, and missing-library checks also passed.
The package is `/home/sweet_cicero/Projects/HView-Linux/target/packages/hview-linux-x86_64-5e4ef68`.
The executable SHA-256 is `b55b91b7d3f0735a0980bf57909b83ddef41bf5388041d4e51f5700c39d8c964`.
The command was `python3 scripts/package.py target/packages/hview-linux-x86_64-5e4ef68`.
Astra accepted the complete extension after reviewing the final records at `56484b04fe4553a813f4e6c5ab54174e5e440b57`.
Astra independently reran the package probe and verified the executable hash and packaged README.
All function-matrix rows and Linux differences have implementation and passing check references.
Real editor operations verify 256-record eviction, combined 64-MiB byte eviction, and oversized-edit rejection without state changes.
The final manual benchmark passed with 28 rows, five warmups, ten batches, and five preparations per batch.
Raw median/p95 was 53361/90678 ns. PE median/p95 was 100642/102425 ns.
These measurements do not establish a controlled comparison with the original D03 timing results.

Astra found that a resize with Enter could apply a patch after the preview became too small.
Commit `d447c4d` checks terminal dimensions again after input. Escape retains priority during a simultaneous resize.
The patch probe and Astra's independent immediate-resize check passed after the correction.
The advisory-lock, final-rename race, and power-loss limits remain explicit in `src/save.rs`.
The Phase 4 probe SHA-256 was `bbd48e8a94d359c47618a8f053fbed91870f4bef4381593a856c9379841de90c`.
The redraw benchmark used 28 rows, five warmups, ten batches, and five preparations per batch.
The raw p95 was 27626 ns, and the PE p95 was 30486 ns.

The temporary oracle used the official Zydis source at the pinned commit.
The oracle compared Real16 and LONG_COMPAT_16 with Intel and AT&T syntax.
Relative fixtures used addresses zero, `0xFFFF`, and `0x10000`.
Capstone matched ordinary lengths, registers, operand widths, address widths, and validity.
Real16 now filters the complete protected-mode set and vector encodings.
Real16 preserves LES, LDS, BOUND, POP, MOV control-register instructions, and far pointers.
The session keeps the legacy 16-bit width and stores a versioned 24-file Real16 bitmap.
The session refuses Real16 persistence when unknown data occupies the extension area.
The Real16 policy preserves register VMWRITE and rejects memory VMWRITE.
The tracked harness records formatter targets and numeric target differences.

Astra found that Ctrl-modified macro letters could insert printable text.
The input adapter now gives Ctrl-modified macro letters control characters and keeps their action codes.
Focused edit and prompt workflows pass with the corrected input adapter.
The macro probe labels now match the imported Shift and Alt modifier bits.

The Phase 2 candidate adds GNU options and keeps explicit legacy forms.
The native configuration format uses `[HView-Linux 1]`, UTF-8, and LF line endings.
Configuration lookup uses an explicit path, an executable sibling, and then XDG configuration.
Portable mode stops lookup after the executable sibling.
The candidate keeps legacy CRLF parsing and legacy numeric behavior.
The saved format still permits 1 to 24 ASCII paths with fewer than 260 bytes.
Windows saved paths now fail with a Linux path error.

Astra found six Phase 2 defects in the first candidate.
New sessions now store absolute paths before SAV validation.
Linux absolute paths can contain literal backslashes.
Relative and empty XDG paths now fall back to HOME.
File switching now reads the current session view record.
Explicit startup modes and offsets now initialize inactive session records.
Inactive Hex and Code records now keep their startup cursor visible.
The `--` boundary now disables every legacy option check.

Astra found incomplete CP437 output and idle resize handling.
The candidate now preserves all CP437 cells and redraws after idle resize.
Astra found that control keys could insert hexadecimal digits and prompt text.
The candidate now keeps control characters separate from their action codes.
Astra found three save-backend access and substitution risks.
The save backend now uses descriptor metadata changes and rejects read-only or privileged targets.
Astra accepted the corrected save backend after nine strict Btrfs tests.
Astra found that resize events could dismiss a modal or the analysis menu.
The modal and analysis menu now redraw until the user supplies an input key.
Astra found that a zero-filled binary matched the UTF-16 lane heuristic.
The heuristic now requires text bytes in the lane opposite the zero-byte lane.

The C probes confirmed a missing-file crash, failed empty-file mapping, and continued execution after `fstat` failure.
The rendering probe displayed bytes beyond the final row.
A decoder stub caused an EOF loop timeout.
The decoder stub did not test the real Zydis engine.
Do not port these defects.

Temporary diagnostic artifacts were saved under `/tmp/hview-baseline.vMUmt1`.
That directory can disappear after cleanup or restart.
The findings and limits above remain the persistent evidence summary.

## Resume procedure

1. Open `/home/sweet_cicero/Projects/HView-Linux`.
2. Read AGENTS.md, this tracker, and PLAN.md.
3. Check Git status and the current branch before changing files.
4. Compare current files and commits with the recorded task status.
5. Resolve any difference before selecting the next task.
6. Use Astra xhigh for all planning and review.
7. Use Sol xhigh for all execution, code generation, and check runs.
8. Check recorded authorization before application implementation.
9. Assign an authorized dependency-ready item to Sol xhigh.
10. Record results and the next action in this tracker.

Current resume action: Plan L02.1 with Astra xhigh.
Assign its bounded implementation to Sol xhigh under the recorded authorization.

## Historical D04 through D07 Windows review

The requested Windows pull completed on September 5, 2026.
The clean Windows branch advanced from `97a308c` to `a3b7240` through seven commits.
Astra confirmed four missing Linux feature groups: branch navigation, raw dump addresses, assembly preview, and operation undo/redo.
The portable Windows format module passed all 13 tests on this Linux host.
UPSTREAM_REVIEW.md records source references, dependencies, Linux integration requirements, and proposed acceptance checks.
The update review changed no Linux application code at review time.
The approved D04 through D07 extension now implements the selected update groups.

## Current excluded work

Only S06, B04, and X02 remain outside the current Windows scope.
See PLAN.md for their exact boundaries.
