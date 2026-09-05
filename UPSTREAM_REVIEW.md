# Windows update review

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

Windows D10 remains pending.
Linux already provides strict decoding and optional one-byte fallback through `InvalidCode=Error|Byte`.
Do not add a second implementation of that feature.
D08, D09, and the remaining Windows backlog are still unimplemented upstream.

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
