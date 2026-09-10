# Windows update reviews

## Current September 10 source review

Review date: September 10, 2026.
Windows source: clean local `master` at `469f13d0959d5bed7fbf068a7c4a5858be16d0a8`.
Linux branch: local and remote `rust-rewrite` at `1a3877a459aa7bea0f4e6f9d3249b1adb4554fdc`.
The Linux application source remains the accepted D07 source.

`W:` identifies `/home/sweet_cicero/Projects/HView-windows`.
`L:` identifies `/home/sweet_cicero/Projects/HView-Linux`.
The references below identify current source files and starting lines.

The current Windows tracker marks REQ01 through REQ15 and UX01 complete at `W:REQUIREMENTS.md:12`.
The Windows claims retain explicit limits and require separate Linux acceptance.
The current Linux plan must include D08-D15, S01-S05, S07-S14, P01-P07, B01-B03, B05-B07, X01, and X03.
The plan must also include current legacy UI functions.
Only S06, B04, and X02 remain deferred at `W:TRACKER.md:191`, `:210`, and `:215`.

HView-Linux is a powerful local hacker toolkit.
The product must not block supported, valid, local operations only because they are risky.
Invalid requests, unsupported requests, permission errors, and operating-system or I/O failures still return accurate errors.

### Current source evidence

| Tracker area | Windows source evidence | Current Linux coverage |
|---|---|---|
| L02 bounded files | `W:src/main.rs:8445`; `W:src/paged.rs:20`, `:213` | Missing. `L:src/main.rs:810` reads the complete file. |
| L03 logical spans | `W:src/paged.rs:74`, `:473`, `:578`; `W:src/editor.rs:13` | Partial. `L:src/editor.rs:81` stores one `Vec<u8>`. |
| L04 guarded saves | `W:src/save.rs:383`, `:402`, `:455`; `W:src/paged.rs:1424`, `:1465` | The Linux baseline exists at `L:src/save.rs:707`, `:736`. Scale support is missing. |
| L05 Text indexes | `W:src/text_index.rs:138`, `:183` | Missing. Linux scans buffered rows at `L:src/editor.rs:596`, `:722`. |
| L06 cancellation | `W:src/analysis.rs:12`, `:84`; `W:src/workbench.rs:192` | Missing. Linux tools run synchronously at `L:src/workbench.rs:356`. |
| L07 architectures | `W:src/format.rs:16`, `:2762`; `W:src/decoder.rs:192`, `:286`, `:390`; `W:src/assembler.rs:55`, `:68` | Partial x86 baseline. Linux loader remains at `L:src/native.rs:23`. |
| L08 PE, ELF, Mach-O | `W:src/format.rs:3255`, `:3698`, `:4128`, `:6152`, `:6362` | Partial PE. Linux raw ELF has no structures at `L:src/format.rs:75`. |
| L09 NE, LE, LX, TE, TE64, NetWare | `W:src/format.rs:221`, `:523`, `:1564`, `:1673`, `:1744`, `:1900`, `:2000`, `:2136` | Missing. Linux explicitly rejects NE, LE, LX, and NetWare at `L:src/format.rs:1233`. TE and TE64 detection are absent. |
| L10 branches and preview | `W:src/decoder.rs:538`; `W:src/format.rs:2876`; `W:src/main.rs:6230`, `:7753` | Partial. Linux branch and preview paths start at `L:src/main.rs:221`, `:541`. |
| L11 block operations | `W:src/block.rs:28`, `:126`; `W:src/main.rs:3354`, `:3677` | Partial Fill and XOR only. |
| L12 crypt | `W:src/crypt.rs:13`, `:79`, `:141`, `:181`, `:285`, `:385`, `:403`, `:663` | Missing. Linux only has repeating XOR at `L:src/operations.rs:99`. |
| L13 patches | `W:src/patch.rs:16`, `:223`, `:369`, `:505`, `:659`, `:704` | Missing. Linux has no patch module or patch commands. |
| L14 annotations | `W:src/editor.rs:15`, `:282`, `:309`, `:819`; `W:src/workbench.rs:1351` | Missing. Linux has no annotation model. |
| L15 terminal and controls | `W:src/console.rs:32`, `:318`, `:697`, `:812`, `:1902`; `W:src/main.rs:1723`, `:7778` | Partial terminal foundation at `L:src/console.rs:274`, `:318`, `:611`. |
| L16 Unicode Text | `W:src/console.rs:352`, `:384`, `:452`; `W:src/text_index.rs:19`, `:586`, `:979`; `W:src/editor.rs:1066`, `:1129` | Partial paths and CP437 view. Linux refuses Text editing at `L:src/editor.rs:413`. |
| L17 search | `W:src/instruction_search.rs:15`, `:44`, `:200`; `W:src/operations.rs:22`, `:95`, `:424` | Partial byte search at `L:src/operations.rs:1`, `:30`. Instruction search is missing. |
| L18 inspection tools | `W:src/inspect.rs:19`, `:52`, `:95`, `:240`, `:364`, `:500`, `:538`, `:596` | Partial ASCII tools at `L:src/inspect.rs:1`, `:8`, `:72`, `:107`. |
| L19 comparison | `W:src/operations.rs:485`, `:491`, `:592`, `:654`; `W:src/workbench.rs:735`, `:848` | Partial equal-offset comparison at `L:src/operations.rs:56`. |
| L20 calculator | `W:src/calculator.rs:8`, `:23`, `:90`, `:314`, `:424`; `W:src/main.rs:5264` | Missing. |
| L21 DatRef and Refer | `W:src/decoder.rs:412`; `W:src/workbench.rs:104`; `W:src/format.rs:2534`, `:2908` | Missing. Existing branch following is a different function. |
| L22 Names | `W:src/names.rs:41`, `:147`, `:182`, `:214`; `W:src/names_store.rs:28`, `:146`, `:209` | Missing. Linux has no Names modules or companion lifecycle. |
| L23 configuration | `W:src/config.rs:74`, `:137`, `:287`, `:313`, `:676`, `:714` | Partial. Linux discovery starts at `L:src/config.rs:215`. |
| L24 picker and history | `W:src/files.rs:12`, `:31`, `:375`, `:444`; `W:src/main.rs:1804`, `:1893` | Partial picker. Linux traversal at `L:src/files.rs:34` lacks current bounds. |
| L25 sessions | `W:src/config.rs:816`, `:937`, `:1132`, `:1288`; `W:src/session.rs:19`, `:55`, `:199`, `:337` | Partial legacy SAV only. Linux state starts at `L:src/config.rs:550`. |
| L26 macros | `W:src/macros.rs:12`, `:21`, `:68`, `:109`, `:208`; `W:src/console.rs:1509` | Partial startup playback at `L:src/macros.rs:66`. |
| L27 batch replacement | `W:src/save.rs:475`, `:512`, `:576`, `:743`, `:992`, `:1136`, `:1393` | Missing. Linux has no batch journal or startup rollback. |
| L28 signatures | `W:src/signatures.rs:22`, `:47`, `:457`; `W:src/workbench.rs:371` | Missing. Linux needs a child-process control adapter. |
| L29 reports and checksum | `W:src/workbench.rs:2136`, `:2264`; `W:src/main.rs:2226` | Missing current actions. |
| L30 devices | `W:src/device.rs:97`, `:215`, `:317`, `:361`, `:422`; `W:src/paged.rs:191`, `:1248`, `:1291`, `:1354` | Missing. Linux has no block-device adapter. |
| L31 retained HEM functions | `W:src/hem.rs:87`; `W:native/hem_host.c:1186`, `:1376`; `W:docs/hem-protocol.md:25`, `:132`, `:187`, `:198` | Missing. Exclude Windows-specific modules. Inventory the remaining HEM functions and their Linux requirements. |
| L32 package | `L:lib/native-dependencies.json:4`; `L:scripts/package.py:39`; `L:.github/workflows/ci.yml:10` | Present baseline. New dependencies, probes, and notices remain pending. |

### Current limits to preserve

- Paged files use 64 KiB read windows and `u64` offsets.
- Regular block operations use a 64 MiB limit.
- Changed paged memory uses 65 MiB and 4,096 ranges.
- Undo uses 256 records and 130 MiB in current Windows.
- Text rows use 64 KiB. Grapheme carry uses 4 KiB.
- Patches use 4,096 records, 64 MiB payload, and 129 MiB input.
- Patch version one permits equal-length replacements and one final append.
- Annotations use 256 records and 1,024 UTF-8 bytes per text field.
- Modern sessions use version six, 256 files, and 16 MiB.
- Legacy SAV uses 24 files and retains representation limits.
- Names use 256 entries and 1,024 UTF-8 bytes per text field.
- Macro banks use ten slots, 1,024 events per slot, and 256 KiB input.
- Traversal uses limits for depth, directories, entries, results, paths, and reports.
- Device edit envelopes use 64 KiB and preserve source length.
- Buffered crypt setup uses 32 MiB at `W:src/main.rs:7403`.
- Paged crypt setup uses the 64 KiB `paged::MAX_READ_BYTES` limit at `W:src/main.rs:5730`.
- Selected regular-file block crypt uses a separate 64 MiB limit.
- Instruction patterns use 1,023 ASCII bytes and 16 clauses.
- Calculator input uses 68 ASCII bytes and retains 64 history entries.
- Signature execution uses bounded input, rules, output, rows, time, and child memory.

Paged metadata supports checked navigation.
Several structure and analysis browsers remain buffered-only.
Paged Strings, entropy, comparison, signatures, templates, annotations, and patch tools have no current viewer routes.
Do not claim wider paged support than the Windows source provides.

ELF support remains little-endian.
ELF excludes ET_CORE, runtime rebasing, big-endian data, symbols, and general relocation analysis.
B07 adds ARM machine 40 support and supersedes the earlier B02 exclusion.
Mach-O support remains thin and little-endian.
ARM64 assembly remains unsupported at `W:src/assembler.rs:68`.

### HEM and platform boundaries

The user excluded Windows-specific HEM modules from the Linux scope.
Keep the remaining HEM functions in scope.
Inventory each retained function and its requirements before implementation.
Do not require Wine or a Windows binary host only for excluded modules.
Do not remove the complete HEM requirement.
Do not add a speculative plugin framework.

The full Windows implementation remains reference evidence for excluded modules.
The Windows parent starts `HViewHemHost.exe` through bounded binary IPC at `W:src/hem.rs:87`.
The helper loads 32-bit Windows DLLs and finds `Hem_Load` exports at `W:native/hem_host.c:1186`.
The supplied collection contains 29 unique modules across 34 paths at `W:docs/hem-collection.md:3`.
Companion and output limits appear at `W:docs/hem-collection.md:38`, `:46`, `:54`, `:68`, and `:82`.

Record each excluded Windows-specific module and its reason.
Check every retained HEM function through its Linux interface.

The user accepted close Windows terminal appearance with reachable keys.
Linux theme and font differences remain permitted.

The user approved raw-device editing as a product capability.
Treat raw drives as whole block devices.
Treat partitions and logical volumes as logical devices.
Open devices read-only by default.
Require explicit writable mode.
Permit a user-controlled override for mounted or in-use devices.
Also permit the override when exclusive access is unavailable.
At the write commit, identify the device and byte range.
Give one warning about filesystem damage, partial writes, and limited recovery.
Do not repeat the warning for each edited byte.
Preserve fixed length, bounds, validation, permissions, neighboring bytes, flushes, read-back checks, and accurate failure handling.
Do not unmount devices or bypass privilege controls automatically.
Test only with disposable virtual devices.

Native Linux file operations must preserve valid pathname bytes through `PathBuf` and `OsString`.
The native CLI and picker must accept non-UTF-8 pathnames.
Keep operational paths separate from escaped display text.
Never convert display text back into an operational path.

Preserve exact absolute and relative meanings, literal backslashes, option boundaries, and XDG discovery.
Return actual pathname errors.
Do not guess a Windows drive mapping or select a different file.

Existing modern configuration and session formats use UTF-8 paths.
Reject unrepresentable paths before modern publication.
A representation limit must not block opening, viewing, or editing a valid native path.
The limit must not block Save or Save As for a valid native path.

Report persistence failure separately.
Retain editor state and existing session bytes after persistence failure.
Do not report successful persistence or convert the path lossily.
L02.2, L23.2, L24.1, L24.2, L25.2, and L25.3 own native path integration and persistence independence.

Windows legacy imports use `GetOEMCP` at `W:src/config.rs:676` and `W:src/config.rs:714`.
CP437 Text display does not identify the source pathname code page.
ASCII pathname bytes need no code-page selection.
For non-ASCII input, require an explicitly selected, supported source OEM code page.
Decode strictly and require an exact byte round trip.

Fail for missing, unsupported, ambiguous, or unrepresentable selections.
Use the selected encoding for legacy export with an exact byte round trip.
Preserve the legacy layout and the fewer-than-260-byte pathname limit.
L23.1 defines the supported code pages and configuration spelling.
L25.1 owns strict legacy OEM persistence.

Linux YARA-X execution must preserve the Windows scanner limits.
The limits are 64 MiB input, 4 MiB top-level rules, 4 MiB combined stdout and stderr, 10,000 rows, and 60 seconds.
The aggregate child-job memory limit is 512 MiB.
The deadline covers snapshot creation, execution, and parsing.

Canonicalize the selected top-level rule path.
Use its directory for relative includes.
Keep included files as engine inputs without snapshotting them.
Do not apply the 4 MiB top-level limit as an aggregate include limit.

Resolve `HVIEW_YARAX` authoritatively.
Otherwise, search an executable sibling named `yr` and then each nonempty `PATH` entry.
Resolve a complete executable path and use an argument vector without a shell.
Drain both output pipes concurrently with bounded storage.
Publish only complete, validated results.
Preserve actual launch errors and diagnostics.

Apply child containment before engine code executes.
Stop descendants during cancellation, timeout, resource failure, normal cleanup, and retained-pipe cleanup.
A process-group signal does not cover descendants that leave the group.
A per-process `RLIMIT_AS` does not enforce aggregate child-job memory.

L28.1 must select an enforceable Linux mechanism and record its host prerequisites.
Return an accurate capability error when the host cannot enforce aggregate memory and descendant cleanup.
Do not run with weaker limits.

For each changed source file, add educational block comments to every logical section.
Explain the purpose, inputs, data flow, state changes, key decisions, control flow, and connection to the next section.
Write readable STE for readers who do not know the source.
Keep the comments accurate when the related code changes.
Do not retrofit untouched source files during L01.1.

Linux must keep its terminal, path, save, identity, and device adapters.
Do not copy Windows console records, file APIs, device APIs, or `windows-sys` into the Linux implementation.
Reuse current Unicode segmentation and width behavior through the upstream crates.
Record their locked versions and notices if Linux imports them.

Neither project declares a Rust source license at `W:README.md:481` and `L:README.md:319`.
Do not apply the previous C license to imported Rust source.
Retain native source commits, hashes, transformations, license files, and package checks.

### Current Linux baseline checks

These checks ran on September 10, 2026, against the current Linux application source.

| Command | Result | Limit |
|---|---|---|
| `cargo fmt --all -- --check` | Passed | Current local source. |
| `cargo test --locked --offline -- --test-threads=1` | Failed: 82 passed, one failed, one ignored | The ACL fixture failed before save logic. |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Passed | Current local source. |
| `cargo build --locked --offline --release` | Passed | The build was incremental. |
| `target/release/hview-linux --self-test` | Passed | Current Linux native engines. |
| Focused ACL test with a workspace `TMPDIR` | Failed at the same assertion | The tmpfs and Btrfs filesystems rejected the named UID. |

The failing test is `save::tests::acl_and_metadata_policy_are_explicit`.
`L:src/save.rs:1128` calls `setfacl -m u:1:r--`.
`L:src/save.rs:1133` checks the command result.
`setfacl` returned `Invalid argument` before the save operation.
The sandbox maps only UID and GID 1000.
The evidence supports an environment cause but does not establish a full-suite pass.

The exact focused command used a disposable directory below `L:target`:

```sh
TMPDIR="$task_tmp" cargo test --locked --offline save::tests::acl_and_metadata_policy_are_explicit -- --exact --test-threads=1
```

Run the unchanged fixture where UID 1 is mapped and named-user ACLs work.
Do not record a current full-suite pass before that check succeeds.

This review inspected local source only.
The review did not run the Windows application, HEM modules, an external signature scanner, or real devices.
The review did not run a current full PTY or isolated-package suite.
September 5 package and regression results remain historical evidence.

The user authorized L01.2 and scoped application work on L02.1.
Current application authorization covers L02.1 only.
L02.1 adds owned bounded regular-file reads with 64 KiB windows and `u64` offsets.
The item preserves bounded allocation, short reads, EOF behavior, and actual I/O errors.
Acceptance includes files above 64 MiB and 4 GiB.
File-lifecycle integration remains in L02.2.

The exact next action is: Plan L02.1 with Astra xhigh.
Assign its bounded implementation to Sol xhigh under the recorded authorization.

## Historical update reviews

The remaining sections preserve accepted review evidence from September 5, 2026.
The current review above supersedes their scope, exclusions, and implementation order.

Review date: September 5, 2026.
Planner and checker: Astra High.
The user approved implementation of D04 through D07 after this review.
The original D03 implementation remains the accepted starting point.

## Source state

The requested `git pull --ff-only` completed in `/home/sweet_cicero/Projects/HView-windows`.
The clean `master` branch advanced from `97a308c4fadffa434e96cf4cab33591a26413f4e` to `a3b7240ae0288be383f16135fe6a2f31427fc95c`.
The update contains seven commits, including four feature commits.
The Linux comparison baseline is `aa5bd966af8c91c3e5795c57119a9a4419708639` on `rust-rewrite`.

## Linux gaps at the comparison baseline

The table records gaps at Linux commit `aa5bd96`. Use TRACKER.md for implementation and acceptance status after this review.

| Order | Windows feature and commit | User behavior | Linux gap |
|---|---|---|---|
| 1 | D04: direct code navigation, `7f237fb` | Enter follows direct relative branches and calls. Backspace restores a return position. The history holds 256 positions. | Linux has instruction stepping but no branch following or separate return history. |
| 2 | D05: raw dump address model, `50d5617` | `Ctrl+T R` selects `AUTO` or `X86 16\|32\|64 LE\|BE HEXBASE`. Raw mappings supply checked runtime addresses. | Linux displays raw offsets and supports checked PE conversion, but has no explicit raw runtime base. |
| 3 | D06: assembly preview, `0332735` | A preview shows original bytes, proposed bytes, affected instructions, retained tails, overlap, and EOF growth before application. | Linux writes assembled bytes directly into the edit buffer. |
| 4 | D07: operation undo and redo, `a3b7240` | F3 undoes an edit operation. Shift+F3 redoes an operation. History holds 256 records within 64 MiB. | Linux F3 restores only the current original byte. Linux has no operation redo. |

Implement these candidates in the listed order.
D05 extends D04 address handling.
D06 uses those addresses during assembly preview.
D07 records confirmed assembly patches and all other edit operations.

At this review date, Windows D10 remained pending.
Linux already provides strict decoding and optional one-byte fallback through `InvalidCode=Error|Byte`.
Do not add a second implementation of that feature.
At this review date, D08, D09, and the remaining Windows backlog were unimplemented upstream.

## Source reuse and acceptance checks

Windows source paths below are relative to `/home/sweet_cicero/Projects/HView-windows`.
Linux source paths use the corresponding `src` modules in this repository.

| Candidate | Source to inspect and reuse | Required checks |
|---|---|---|
| D04 | `src/decoder.rs`: `direct_target`; `src/format.rs`: checked navigation mappings; `src/main.rs`: follow and return history | Direct CALL, JMP, conditions, and LOOP; backward and self-targets; return position and top restoration; 256-position bound; invalid sources and targets |
| D05 | `src/editor.rs`: `RawModel`; `src/format.rs`: raw metadata; `src/workbench.rs`: raw-model grammar; `src/inspect.rs`: selected integer byte order | Strict grammar; base and width overflow; PE override; file/VA conversion; RVA refusal; empty buffers; growth bounds; AUTO restoration; transient state |
| D06 | `src/main.rs`: assembly preview construction, instruction rows, and confirmation | Exact proposed bytes; cancellation without mutation; shorter tails; overlapping instructions; EOF growth; decode errors; current-buffer mapping; terminal resize |
| D07 | `src/editor.rs`: edit records, grouped nibble edits, undo, redo, and history limits; edit callers in `src/main.rs` and `src/workbench.rs` | Hex grouping; assembly, fill, and XOR records; redo invalidation; no-op and failed operations; length and cursor restoration; save/cancel resets; history limits |

D04 also fixes stale instruction-step history after a successful F5 Code jump.
At the comparison baseline, the Linux F5 handler left that history intact.
Include this related correction with the navigation port.

The raw model overrides PE headers and affects rendering, decoding, assembly, navigation, and address conversion.
The selected byte order affects integer inspection. X86 decoding and assembly remain little-endian.
Raw settings survive mode changes, Save As, and edit cancellation.
File switches and restarts clear raw settings. The legacy SAV format does not store them.
Base or width changes clear branch-return history. Byte-order-only changes preserve that history.

The preview changes no buffer bytes before Enter confirms the patch.
Escape cancels the preview. F9 remains a separate disk-save operation.
Check assembler and decoder length disagreements without changing the proposed patch bytes.

A completed hexadecimal byte, confirmed assembly patch, fill range, or XOR range forms one undo record.
Successful saves establish a new baseline. Save and edit cancellation clear undo and redo histories.
A changed edit after undo clears redo. Failed, canceled, and no-op edits preserve redo.
An oversized edit must fail before changing the buffer.

## Linux integration requirements

- Define Code-mode Enter as Follow while keeping F4 and M available for mode selection.
- Document the shared Ctrl+M and Enter terminal byte.
- Preserve Intel defaults and explicit AT&T display during target extraction and navigation.
- Keep branch targets consistent with Real16 displayed targets.
- Keep the raw X86 16 linear address model distinct from Real16.
- Verify Shift+F3 through Linux terminal input and provide an accessible alternative if necessary.
- Ignore synthetic resize events before closing grouped hexadecimal edits.
- Use current terminal dimensions and checked indexing in assembly previews.
- Preserve Intel assembly input and prompt seeds under both disassembly syntax settings.
- Preserve the Linux save backend, metadata policy, native loading, Real16 session extension, and raw ELF behavior.

Windows uses Intel operand text to extract direct targets.
Linux must adapt this code for both syntax settings and the existing Real16 policy.
Do not replace Linux modules with complete Windows files.

## Review evidence

The review compared the seven new commits, feature source, README, tracker, and reliability probe changes.
Astra confirmed that D04 through D07 were missing from the Linux comparison baseline.
The portable Windows format module passed all 13 tests on this Linux host.
Those tests cover raw mappings, checked navigation, address bounds, PE conversion, and malformed inputs.

```sh
CARGO_MANIFEST_DIR=/home/sweet_cicero/Projects/HView-windows rustc --edition=2024 --test src/format.rs -o /tmp/hview-windows-a3b7240-format-test
/tmp/hview-windows-a3b7240-format-test --test-threads=1
```

Run these commands from the Windows source directory.
The review did not execute the Windows application or its Windows console probes.
The review changed no Linux application code.
Use Sol xhigh for port implementation and Astra High for acceptance checks.

## Historical D08 and D09 comparison

This comparison used Windows source `624e3cc924da5c1d3a74a06eca82771079cb80bc`.
The clean `master` branch contains exactly two application commits after `a3b7240`.
D08 is `c8d195a`, and D09 is `624e3cc`.
The current Linux commit is `f9c5299f2f21d3531b8295d2d358dcc566cfcb24` on `rust-rewrite`.
Its application source remains the accepted `5e4ef68` D07 source.

The Linux source lacks `src/patch.rs`.
The Linux workbench lacks the D08 `W` and `L` commands and the D09 `N` command.
The Linux `SavedFile` lacks annotations.

### D08 verified patch records

Windows `src/patch.rs:165` exports net differences from the edit-session baseline.
Windows `src/patch.rs:275` parses patch syntax, limits, and ranges.
Windows `src/patch.rs:421` checks source SHA-256, source size, and original bytes.
The same apply path records one patch as one undoable edit.

Require equal lengths for replacements.
Permit an append only at the final file offset.
Do not permit deletion records.
Limit input to 129 MiB and 4096 records.
Limit decoded old-plus-new bytes to 64 MiB.
Keep the existing contiguous 64 MiB history envelope.

Replace Windows BCrypt SHA-256 at `src/patch.rs:13` with a portable Linux implementation.
The current legacy checksum is not SHA-256.
Reuse Linux destination refusal at `src/save.rs:736` for safe patch export.

Check an export and import round-trip.
Check source hash, source size, original bytes, ranges, malformed input, and all limits.
Check atomic destination refusal and safe export.
Check one undo and redo after patch application.

### D09 annotations

Windows `src/editor.rs:53` defines annotation bounds.
Allow at most 256 annotations per file.
Require 1 through 1024 UTF-8 bytes of text.
Reject control characters and empty ranges.
Use half-open annotation ranges.

Windows `src/workbench.rs:115` supplies the annotation browser.
Allow annotation navigation during a byte edit.
Refuse annotation changes during a byte edit.
Adapt the browser to Linux resizing and safe rendering.

Windows `src/config.rs:476` adds a source-bound annotation suffix.
Bind the suffix to the source size and SHA-256.
Append the annotation suffix after the legacy payload.
Preserve the Real16 extension offset at 67544.
Preserve all unknown payload bytes.

Windows `src/main.rs:1160` rejects malformed restored annotations before session overwrite.
Preserve annotations through file switches, mode changes, save, Save As, and cancellation.
Preserve annotations in memory when session persistence is off.

Check create, read, update, delete, bounds, and the byte-edit guard.
Check file switching, save, Save As, restart, and cancellation.
Check an explicit discard after a source mismatch.
Check corrupt suffix refusal.
Check Real16 and legacy coexistence.
Check terminal resizing in the annotation browser.

### Historical implementation order

The earlier proposal put D08 before D09.
The current L01 through L33 plan supersedes that order.
Do not start either task before user approval and its current dependencies.

Preserve Linux absolute paths, session paths, terminal behavior, native loading, and save policy.
Preserve the current Real16 extension and raw model behavior.
Record each intentional Linux deviation.

Fresh format, strict Clippy, release build, native checks, and 83 unit tests passed at `f9c5299`.
One manual benchmark remained ignored during the unit run.
The separate manual benchmark passed.
Raw median and p95 were 15889 ns and 16432 ns.
PE median and p95 were 19698 ns and 21096 ns.
All ten direct application probes passed.
All ten packaged application probes passed.
The package passed manifest, hash, ELF, isolation, native, and both missing-library checks.
The package is `/tmp/hview-linux-review-f9c5299-20260905`.
Its executable SHA-256 is `2943b0c5152f918e24d4d5ed7c39999113d435103136bfad6088342f1c77b506`.
The exact command summary is `/tmp/hview-linux-review-f9c5299-20260905-checks.txt`.
Fresh save unit tests used `/tmp` on tmpfs.
Earlier accepted Btrfs save evidence remains separate.
The analysis found no additional defect or dependency blocker.
