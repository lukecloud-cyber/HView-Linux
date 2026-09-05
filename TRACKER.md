# HView-Linux implementation tracker

Last update: September 5, 2026.
Read this file first when a session resumes.
Read [PLAN.md](PLAN.md) for the complete requirements and source references.
Read [VERIFICATION.md](VERIFICATION.md) for the final function and Linux-difference matrix.

## Current state

- Completed: project analysis, repository rename, branch creation, plan, and tracker.
- Application implementation: Phases 1 through 4 passed Astra review.
- Active work: the Phase 5 VMWRITE correction and final Astra review.
- Core owner: `sol_linux_baseline` owns source adapters, fixtures, core tests, and terminal checks.
- Native owner: `native_package` owns `lib`, package scripts, native probes, and native metadata.
- Save owner: `save_backend` owns `src/save.rs` and its inline tests.
- Next task: commit the VMWRITE correction and replayable oracle evidence.
- Next acceptance check: have Astra review the corrected Phase 5 commit.
- Application blockers: none confirmed.
- Current branch: `rust-rewrite`.
- Project folder: `/home/sweet_cicero/Projects/HView-Linux`.
- Repository: [HView-Linux](https://github.com/lukecloud-cyber/HView-Linux).

The Phase 1 candidate contains the imported source and the Linux adapters.
The branch started with the empty root commit `4ded82f485022075d061588a090cb8ddbfa03406`.
The initial branch commit was pushed and verified.
Use Git status and history to determine the current documentation commit and remote state.

## Fixed decisions

| Item | Requirement |
|---|---|
| Scope | All implemented Windows functions through D03, plus the Linux adaptations in PLAN.md |
| Implementation | Reuse Windows Rust source; do not retain a C application |
| Product | HView-Linux |
| Package and executable | `hview-linux` |
| Planner and checker | `gpt-6-astra`, reasoning effort `high` |
| Coding model | `gpt-5.6-sol`, reasoning effort `xhigh` |
| Disassembly syntax | Intel by default; AT&T through explicit configuration |
| Assembly syntax | Intel input and prompt text |
| Previous Linux source | Reference only, on `main` |
| Default branch | Keep `main` until the Rust release passes its checks |
| Compatibility | Preserve current and legacy configuration, session, and macro signatures |
| Source license | Preserve accurate provenance; do not assume the C license covers imported Rust source |

## Status rules

Use `Pending`, `Active`, `Implemented`, `Complete`, or `Blocked` for each task.
`Implemented` means the code exists but required checks or review remain.
`Complete` means the code, required checks, and Astra review pass.
`Blocked` requires a specific cause and a next action.
Do not count source baseline tests as Linux implementation checks.

After each change, update the affected task and the current state.
Record the source files, commit when available, check command, result, and review result.
If a check fails, record the failure and the remaining action.
If requirements change, update both this tracker and the plan.
Before stopping, record uncommitted changes and a concrete resume action.

## Implementation tasks

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
| P5-01 | Macros | Port macro events, startup playback, repeats, modifiers, and stop-on-notice behavior | Implemented | `tests/macro_probe.py` passed both signatures, repeats, modifiers, notices, and Ctrl-key handling |
| P5-02 | Macros | Verify long-delay cancellation and preservation of queued input | Implemented | The macro probe passed maximum-delay cancellation and preserved queued prompt input |
| P5-03 | Linux behavior | Add reachable key alternatives and Linux shortcuts without prompt/edit conflicts | Implemented | The macro probe passed Ctrl+S, Ctrl+Q, M, Enter, O, H/J/K/L, prompt, and edit conflicts |
| P5-04 | Syntax | Add Intel/AT&T configuration; verify Intel defaults, explicit AT&T, and invalid-setting errors | Implemented | `DisassemblySyntax` tests pass; assembly input and prompt seeds remain Intel |
| P5-05 | Linux behavior | Retain verified real-mode decoding and optional invalid-byte display | Implemented | Replayable pinned Zydis corpus checks register and memory VMWRITE, targets, strict errors, and `InvalidCode=Byte` |
| P5-06 | Linux behavior | Permit raw ELF Code viewing without claiming ELF structure or address support | Implemented | Linux behavior probe passed raw ELF Code decoding; PE-only address operations still reject ELF |
| P6-01 | Release | Add Linux packaging, native provenance, hashes, notices, and native self-test | Implemented | Isolated package build, file hashes, ELF checks, and missing-library checks passed |
| P6-02 | Release | Add Linux CI, user documentation, and installation instructions | Implemented | Release documentation and CI exist at `bc918c9`; Astra review remains |
| P6-03 | Verification | Pass formatting, Rust tests, strict Clippy, and a fresh release build | Implemented | Format passed; 65 tests passed; strict Clippy passed; release build passed |
| P6-04 | Verification | Pass terminal, recovery, session, macro, and native-library integration checks | Implemented | Six application probes passed together; final package and review checks remain |
| P6-05 | Verification | Verify package isolation, missing libraries, and decoder preparation measurements | Implemented | Package isolation passed; latest raw median/p95 was 24628/26935 ns; PE was 30263/35727 ns |
| P6-06 | Final review | Have Astra check every function-matrix row and all documented Linux differences | Pending | None |

## Completed planning and setup

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

## Baseline checks and known findings

The following results describe the source projects before the Linux Rust rewrite.
These results do not establish Linux feature parity.

| Check | Result | Limit |
|---|---|---|
| Portable Windows Rust modules | 23 tests passed using direct `rustc --edition=2024 --test` builds | CLI 2, checksum 1, format 10, inspection 4, operations 4, macros 2 |
| Previous Linux standalone tests | 41 tests passed with GCC C17, strict warnings, ASan, and UBSan | Six programs; complete CMake suite and real Zydis integration not run |
| Windows tracker evidence | Records 40 passing Rust tests and additional Windows checks | Windows-only checks were not rerun on this Linux computer |
| Previous Linux complete build | Not run | CMake unavailable; Zydis submodule uninitialized during review |
| New Linux Rust build | Release build passed; native self-test passed | Linux x86-64 host only |

## Current implementation checks

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
| Tracked Zydis oracle replay | Built the tracked C harness; emitted 216 rows; exact 41-name extraction passed |
| `cargo test --locked --all-targets -- --test-threads=1` | 65 passed; one manual benchmark ignored for the corrected Phase 5 candidate |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed for the Phase 5 candidate |
| `cargo build --locked --release` | Passed for the Phase 5 candidate |
| `python3 tests/macro_probe.py target/release/hview-linux` | Passed macro, delay, modifier, notice, alias, prompt, and edit workflows |
| `python3 tests/linux_behavior_probe.py target/release/hview-linux` | Passed Code cycling, Real16, fallback, sessions, syntax, and raw ELF workflows |
| Six application probes against one release build | Terminal, file, reliability, analysis, macro, and Linux behavior probes passed |

These checks ran on Linux x86-64 with Rust 1.98.0.
The Astra Phase 1 review passed at commit `77d4236bc355cdca517c094a45d3a12c766eaef1`.
The Astra Phase 2 review passed at commit `cd476bd2354dd30a545197b6d1ba2b674ff975e6`.
The Astra Phase 3 review passed at commit `1764904fde9a4d0fc8567f7b240c0087511972e2`.
The Astra Phase 4 review passed at commit `3dbc02179d96a782f7061aef07d7c5522189c135`.
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
6. Use Astra High for planning and review.
7. Assign the next coding task to Sol xhigh.
8. Run the required checks for that task.
9. Record results and the next action in this tracker.

Current resume action: inspect the latest commit and active next-phase task before a source change.
Repeat the applicable focused checks after each source change.
Keep later tasks Active or Implemented until their required checks and Astra review pass.

## Excluded work

The Windows backlog after D03 remains outside the initial parity target.
See PLAN.md for the excluded features and required Linux adaptations.
Do not add excluded work without a user request.
