# HView-Linux: Project analysis and implementation plan

Read [TRACKER.md](TRACKER.md) for current progress, verification results, and the next action.
Update the tracker after each implementation change or verification result.

## Target and approved direction

Build HView-Linux in Rust from the current HView-Windows application.
Include all implemented Windows functions through D07.
The user approved the D04 through D07 extension after the original D03 release.
Use UPSTREAM_REVIEW.md for the extension requirements and integration checks.
Use the previous Linux application as a behavior reference.
Keep the previous Linux code in Git history.
Start the Rust application on a new orphan branch named `rust-rewrite`.
Do not copy the previous C application into the new branch.

Rename the local folder, application, and GitHub repository to `HView-Linux`.
Use `/home/sweet_cicero/Projects/HView-Linux` as the project folder.
Use `HView-Linux` for the product name.
Use `hview-linux` for the executable and Cargo package name.
Keep the existing GitHub repository visibility and history.
Do not change the default branch until the Rust application passes the release checks.

Use Astra High (`gpt-6-astra`, effort `high`) for planning, feature checks, and final review.
Use Sol xhigh (`gpt-5.6-sol`, effort `xhigh`) for all application code, test code, and build scripts.

## Analysis baseline

| Project | Baseline | State |
|---|---|---|
| HView-Windows | `97a308c4fadffa434e96cf4cab33591a26413f4e` | Clean Rust source; 15 application modules |
| Previous HView | `35dbd0bbdfba08c1d3062bbeb65d5c6abcd29771` | Clean C source; read-only terminal viewer |

The Windows review covered every application module, embedded test, console probe, package script, source asset reference, and active document.
The review also covered native dependency metadata and the Windows CI workflow.
Historical reconstruction archives are outside the current functionality baseline.

The Windows tracker records R01 through R13 and D01 through D03 as complete.
The tracker records 40 passing Rust tests and two ignored tests.
The tracker also records passing console probes, formatting, Clippy, and isolated package checks.
These results are recorded Windows evidence.
This Linux review did not execute the Windows application or Windows-only tests.

The previous Linux application uses C17, CMake 3.20, termios, mmap, and a Zydis Git submodule.
The current checkout lacks CMake and the initialized Zydis submodule.
The initial review therefore could not build the complete previous Linux application.
Rust 1.98.0 is available on this computer.

The rename and branch setup are complete.
The repository is now `https://github.com/lukecloud-cyber/HView-Linux`.
The repository remains public.
The default branch remains `main` at the previous Linux baseline.
The local and remote `rust-rewrite` branches contain the empty root commit `4ded82f485022075d061588a090cb8ddbfa03406`.
The branch started without tracked files.
The branch now contains the plan, tracker, and project instructions.
Application implementation had not started when this plan was approved.
Use the tracker for current branch and implementation status.

### Checks executed on this Linux computer

The review executed 23 Windows portable-module tests directly with `rustc --edition=2024 --test`.
All 23 tests passed.
The format-module invocation supplied `CARGO_MANIFEST_DIR` for the tracked PE fixtures.
The complete Windows suite remains unexecuted on this computer.

| Portable module | Passed tests |
|---|---:|
| CLI | 2 |
| Checksum | 1 |
| PE format | 10 |
| Inspection | 4 |
| Operations | 4 |
| Macros | 2 |

Six standalone C test programs passed all 41 checks.
The checks used GCC C17 with strict warnings, AddressSanitizer, and UndefinedBehaviorSanitizer.
These checks did not run the complete CMake suite or the real Zydis decoder.
Diagnostic evidence is in `/tmp/hview-baseline.vMUmt1`.

## Function matrix

All Windows paths below are relative to `/home/sweet_cicero/Projects/HView-windows`.
Previous Linux paths refer to commit `35dbd0bbdfba08c1d3062bbeb65d5c6abcd29771`.

| Function | Current Windows implementation | Previous Linux state | Rust work |
|---|---|---|---|
| Text display | CP437 bytes, line-feed detection, tabs, wrapping, and horizontal movement; `src/editor.rs:290`, `src/config.rs:129` | Fixed-width byte display | Reuse Windows display behavior |
| Hex display and movement | Sixteen-byte rows, grouped bytes, CP437 column, byte and nibble movement; `src/editor.rs:152` | Basic hex display and movement | Reuse Windows behavior; retain Linux movement keys |
| Code display | Capstone x86 16/32/64, PE addresses, strict invalid-instruction errors; `src/decoder.rs:75` | Zydis AT&T display, four mode labels, invalid-byte fallback | Default to Intel syntax; provide an AT&T configuration option |
| Decoder reuse | One active decoder; PE metadata parsed once per editor iteration; `src/main.rs:153` | Decoder initialized for each block | Retain Windows reuse |
| Code movement | Next instruction and reverse movement through visited instructions; `src/main.rs:323` | Byte and displayed-instruction movement | Retain Windows movement and verify Linux aliases |
| NOP and INT3 packing | Packs identical one-byte instructions into groups of at most 15 bytes; `src/main.rs:166` | Absent | Reuse |
| Hex editing | Nibble replacement and extension at EOF; `src/editor.rs:127` | Absent | Reuse |
| Edit cancellation | Restores the complete pre-edit buffer; `src/editor.rs:110` | Absent | Reuse |
| Current-byte undo | F3 restores the selected original byte and advances; `src/editor.rs:98` | Absent | Reuse; do not describe this as general undo |
| Assembly | One Intel-syntax instruction, 16/32/64 bits, address-aware encoding; `src/assembler.rs:21` | Absent | Port Keystone loading and retain instruction checks |
| Replacement save | Original backup, staged replacement, content and identity checks; `src/save.rs:176` | Absent | Implement Linux save semantics with equivalent recovery behavior |
| Save As | Refuses existing destinations; opens the new file after success; `src/save.rs:194`, `src/main.rs:323` | Absent | Implement publication without destination replacement |
| Search | Exact text or masked hex; wildcard nibbles; forward and backward repeat; `src/operations.rs:5` | Absent | Reuse |
| Strings | Printable ASCII and ASCII encoded as UTF-16LE/BE; `src/inspect.rs:8` | Absent | Reuse |
| Entropy | Shannon entropy by block; `src/inspect.rs:72` | Absent | Reuse |
| Comparison | Contiguous differences at equal offsets, including unequal tails; `src/operations.rs:56` | Absent | Reuse |
| XOR and fill | Repeating byte masks, checked ranges, edit mode required; `src/operations.rs:99` | Absent | Reuse |
| Integer inspection | Signed and unsigned 8/16/32/64-bit values; both byte orders where applicable; `src/inspect.rs:107` | Absent | Reuse |
| Analysis browser | Selection, paging, horizontal scrolling, checked jumps, and cancellation; `src/workbench.rs:4` | Absent | Reuse with Linux input |
| PE structure browser | Sections, directories, imports, exports, and overlay; `src/format.rs:960` | Absent | Reuse |
| PE address conversion | Explicit file offset, RVA, and preferred ImageBase VA; `src/format.rs:1053` | Absent | Reuse |
| Legacy address behavior | PE mapping, DOS entry point, raw offsets, OEP, and END; `src/format.rs:1123`, `src/cli.rs:62` | Raw file offsets | Reuse separately from checked PE conversion |
| File selection | Interactive folder browser, multiple input files, next and previous file; `src/main.rs:224` | One command-line file | Reuse with Linux paths |
| Wildcards and recursion | Windows file masks and recursive selection; `src/files.rs:182` | Absent | Implement Linux traversal and argument handling |
| Configuration | Thirteen implemented settings, current and legacy headers; `src/config.rs:185` | Absent | Reuse parser compatibility and adapt discovery |
| Saved sessions | Up to 24 files, active file, positions, modes, and display settings; `src/config.rs:469` | Absent | Reuse with Linux path handling |
| Legacy session import | BLZ compressed input, checksums, and unknown payload preservation; `src/config.rs:373` | Absent | Reuse fixtures and parser |
| Macro playback | Startup macro, delays, repetition, modifiers, cancellation, and stop-on-notice; `src/macros.rs:66` | Absent | Reuse parser; translate events into Linux input actions |
| Help and prompts | Editor help, analysis menu, search, goto, assembly, and file prompts; `src/workbench.rs:50` | Short status message | Reuse and update product text |
| Native self-test | Headless engine checks in all three widths; `src/main.rs:712` | Absent | Port and include in package checks |
| Packaging and CI | Pinned native files, hashes, notices, isolated launch, and missing-library checks | CMake targets and seven test programs | Add Linux equivalents |

## Important behavior limits

Strings use a minimum length of four characters in the interface.
Each displayed string has at most 120 characters before its truncation marker.
Strings are not general Unicode decoding.
Strings and comparison show at most 10,000 results.
The PE browser also shows at most 10,000 rows.
The PE parser separately limits entry scans and names.

Entropy uses blocks of at least 4,096 bytes.
The block size increases to keep the map near 4,096 rows.
Comparison uses equal file offsets.
Comparison does not align inserted or deleted regions.
All analysis tools use the current buffer, including unsaved edits.

The Windows application loads complete files into memory.
Edit cancellation requires another complete buffer.
The port must retain this known limit until separate large-file work starts.

Assembly accepts one ASCII instruction with at most 350 characters.
The adapter rejects multiline instructions, semicolon-separated instructions, and invalid output sizes.
Assembly can extend the buffer.
Assembly does not preview neighboring instruction changes.

The current configuration parser deliberately preserves CRLF parsing and legacy numeric rules.
The current saved format permits fewer than 260 ASCII bytes in each path.
The current saved format supports at most 24 files and a 16 MiB decoded payload.
The port must document these limits without silently changing the binary format.

The checked PE tools distinguish file gaps, overlay bytes, and virtual-only bytes.
The checked PE tools reject ambiguous mappings and arithmetic overflow.
VA conversion uses the preferred ImageBase from the current buffer.
Runtime base selection is outside current Windows parity.

## Linux adaptations

### Terminal and input

Keep the application behavior separate from the operating-system input adapter.
Reuse the existing editor actions, prompts, menus, and browser behavior.
Support the actions assigned to Windows function keys and modifier combinations.
Provide a reachable terminal key alternative when terminals cannot distinguish Ctrl+Shift+S from Ctrl+S.
Preserve `m`, Ctrl+M, `o`, Ctrl+Q, and vim movement where these keys do not conflict with prompts or editing.
In prompts and edit mode, interpret typed characters before normal-mode aliases.

Verify the Ctrl+M and Enter overlap explicitly.
Do not require enhanced keyboard protocols for access to an editor action.
If Ctrl+S becomes a save key, disable terminal flow control while the application runs.
Select the terminal adapter after a small key, resize, and restoration check.
Verify upstream documentation before selecting any new dependency or version.

Handle terminal resizing and small dimensions without indexing outside the frame.
Restore raw mode, cursor state, and alternate-screen state after normal exit and errors.
Preserve queued input during macro delays.
Verify Escape cancellation during the maximum supported delay.
Do not transfer Windows scan codes directly into Linux terminal input.

### Paths, configuration, and sessions

Accept Linux absolute paths, relative paths, spaces, Unicode paths, and filenames that begin with a hyphen.
Use `--` to end option parsing.
Keep legacy option forms only where the parser can distinguish those options from Linux paths.
Define native command-line equivalents for offsets, configuration, sessions, macros, and recursion.
Do not use Windows ANSI conversion or Windows separator rules.
Prevent recursive traversal through symlink cycles.

Use Linux product names for default configuration and session filenames.
Preserve `HViewIni`, `HViewSav`, `HViewMacro`, and legacy import signatures as compatibility identifiers.
Do not rename fixed-width binary signatures to the longer product name.
Define configuration lookup precedence and test each supported location.
Keep session path validation before Save As publication.

Report Windows session paths that cannot resolve on Linux.
Do not silently open another file as a path substitute.

Replace the Windows `IsTextUnicode` call in `src/config.rs:129` with tested Linux detection behavior.
Cover byte-order marks, binary input, text detection, and the Hex/Code fallback for unsupported text encodings.
Preserve the current explicit error for unsupported text display.
General Unicode text rendering remains outside the parity scope.

### Native engines and previous Linux behavior

Use the Windows engine versions as the initial behavior baseline: Capstone 5.0.9 and Keystone 0.9.2.
Build or obtain verified Linux shared libraries for the selected target architecture.
Verify native API versions, file provenance, hashes, and package notices.
Load libraries from explicit supported locations.
Do not search the current working directory for native libraries.
Keep Text and Hex usable when decoding or assembly libraries are absent.

The previous Linux application displays AT&T syntax and offers a separate real-mode selection.
Make disassembly syntax a configuration option with Intel and AT&T choices.
Use Intel syntax when the configuration does not specify a syntax.
Use AT&T syntax only when the user selects AT&T in the configuration.
Reject unsupported syntax values with a clear configuration error.

Keep assembly input and assembly prompt text in Intel syntax, regardless of the disassembly setting.
Retain equivalent observable real-mode decoding.
Verify real-mode decoding with representative instruction fixtures before claiming equivalent mode support.
If Capstone differs, implement the required mode behavior or use a verified native decoder for that mode.
Record any unresolved difference as incomplete work.

The previous Linux decoder continues after invalid bytes with a byte directive.
Retain this Linux behavior as an explicit option while preserving Windows strict decoding.
The previous Linux application can inspect ELF bytes as raw x86 data.
Permit raw Code mode for ELF files.
Do not confuse raw ELF viewing with ELF headers, symbols, or address mapping.
Full ELF navigation remains outside Windows parity.

### Recoverable saves

Reuse the save contract, but replace Windows file operations with Linux operations.
Stage replacement bytes beside the destination.
Flush prepared data before publication.
Keep the original backup and target-path record.
Reject detected content changes and file-identity changes.
Ensure Save As cannot replace a destination created during staging.

Retain useful recovery files if publication fails.
Flush affected directories where the selected Linux save procedure requires this operation.

Define and test regular-file, symlink, hard-link, permission, ownership, ACL, and extended-attribute behavior.
Refuse a save when required metadata preservation fails.
Do not present advisory locking as protection against every external writer.
Record the remaining concurrent-writer and rename limits.
Use a local filesystem for initial validation.

## Previous Linux review

The previous C program provides useful interaction references.
The previous C program does not provide an editing or analysis foundation comparable to the Windows Rust application.
Its README still identifies the product as LHiew.
Its build target remains `lhiew`.

The review confirmed several file-open and boundary failures.
A missing-file probe produced a segmentation fault because `src/file_buffer.c` calls `ferror` before its NULL check.
An empty-file probe failed because the module attempts a zero-length mapping.
The same module continues after `fstat` failure.
A ten-byte rendering probe displayed `IJXY` where only `IJ` remained in the file.
The renderer uses the cursor row length for other displayed rows.

A decoder stub returned `NO_MORE_DATA` and caused a loop timeout after two seconds.
The decoder stub verifies loop behavior, not real Zydis decoding.
Source inspection also found uninitialized disassembly rows and a possible row index outside the allocated array.
These findings support Rust reuse.
Do not copy these implementation patterns into the Rust application.

The previous Linux repository includes an MIT notice for its existing source.
The Windows repository does not declare a source license.
Keep origin and license information accurate during the rewrite.
Do not apply the previous C license automatically to imported Windows Rust source.
Preserve required notices for any retained source or native dependency.

## Implementation phases and acceptance checks

| Phase | Sol xhigh implementation | Astra High acceptance check |
|---|---|---|
| 1. Rust application foundation | Import Windows modules and tests; add Linux terminal, input, file, and native-library adapters | Build from a clean checkout; launch empty and nonempty files; verify Text, Hex, Code, and terminal restoration |
| 2. File workflow and configuration | Add Linux arguments, file picker, masks, multiple files, configuration, and sessions | Verify absolute paths, option boundaries, file switching, legacy fixtures, session capacity, and unknown payload preservation |
| 3. Editing and recovery | Connect hex editing, assembly, cancellation, current-byte undo, replacement save, and Save As | Verify exact bytes, EOF extension, rollback, detected-change refusal, atomic Save As refusal, metadata policy, and recovery files |
| 4. Analysis parity | Connect search, strings, entropy, comparison, integers, XOR, fill, PE browser, and address conversion | Run fixture checks; verify unsaved buffers, selection jumps, canceled prompts, invalid inputs, and result limits |
| 5. Macros and Linux continuity | Complete macros, key alternatives, configurable disassembly syntax with an Intel default, and raw ELF behavior | Verify macros, Intel defaults, AT&T selection, invalid syntax settings, real-mode decoding, invalid-byte fallback, and Linux shortcuts |
| 6. Release verification | Add Linux packaging, CI, provenance records, user documentation, and install instructions | Verify clean build, formatting, Clippy, unit tests, terminal probes, package isolation, hashes, and missing-library behavior |

Phase 0 is complete as an environment setup action.
The setup preserved the old history and default branch.
The initial setup verified the remote branch hash, public visibility, zero tracked files, and clean working tree.
Phases 1 through 6 remain application implementation work for Sol xhigh.

Finish each phase before starting dependent work.
Keep the source module boundaries unless a Linux requirement needs a change.
Do not introduce a plugin framework, general backend interface, or shared cross-repository package.
Do not maintain a second application implementation in C.

## Required verification

Run `cargo fmt --check`.
Run `cargo test --locked`.
Run `cargo clippy --locked --all-targets -- -D warnings`.
Run a fresh release build.

Run Linux terminal probes through a pseudoterminal.
Run the packaged native self-test outside the source directory.
Run the package check with each native library absent.

Retain the Windows pure-logic fixtures and their expected results.
Replace Windows console probes with Linux terminal probes that verify the same user outcomes.
Cover empty files, one-byte files, short final rows, incomplete instructions, and files with malformed PE headers.
Cover read-only targets, changed targets, failed staging, failed publication, existing Save As destinations, and canceled Save As prompts.
Cover current-buffer PE changes and checked file-offset, RVA, and VA conversion.
Cover legacy compressed session input, checksum failures, invalid counts, and truncated records.

Reject empty restored sessions before indexing the active file list.

For D01, measure decoder preparation separately from terminal output.
Do not require the Windows timing values on Linux.
Verify decoder reuse and record Linux timing evidence.

## Excluded Windows backlog

The original parity release ended at D03.
The approved extension includes branch following, raw runtime bases, assembly preview, and operation undo/redo through D07.
Exclude verified patch records and annotations.
Exclude paged file access, changed-range storage, background analysis workers, headless JSON analysis, and expanded Unicode sessions.
Exclude signatures, ARM64, full ELF navigation, Mach-O, plugins, a decompiler, and a debugger.
The Linux adaptations above remain required for the application to work correctly on Linux.

## Completion condition

Every function-matrix row must have an implementation location and passing evidence.
Every operating-system difference must have documented behavior and a corresponding check.
Astra High must review the final branch after Sol xhigh completes the required checks.
Feature parity is complete only when the Linux package works independently of both source checkouts.
