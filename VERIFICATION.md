# HView-Linux verification matrix

This matrix maps each function in `PLAN.md` to Linux source and executable evidence.
Use `TRACKER.md` for task status and Astra review results.

Astra accepted all matrix rows and Linux differences at source commit `5febcd48d5d71642fd4d6eca7bd67ff273e149a4`.
The final package is `target/packages/hview-linux-x86_64-5febcd4`.
The packaged executable SHA-256 is `e0ebf155b1392a955aa1b2d941120889ef4e2511ebf6824a65e116ea696e12c7`.
Local CI-equivalent checks passed. The hosted CI workflow has not run.

## Commands

The matrix uses these evidence names.

| Name | Exact command |
|---|---|
| Unit | `cargo test --locked --all-targets -- --test-threads=1` |
| Terminal | `python3 tests/terminal_probe.py target/release/hview-linux` |
| Files | `python3 tests/file_workflow_probe.py target/release/hview-linux` |
| Reliability | `python3 tests/reliability_probe.py target/release/hview-linux` |
| Analysis | `python3 tests/analysis_probe.py target/release/hview-linux` |
| Macro | `python3 tests/macro_probe.py target/release/hview-linux` |
| Linux | `python3 tests/linux_behavior_probe.py target/release/hview-linux` |
| Package | `python3 scripts/package.py /tmp/hview-linux-package` |
| Benchmark | `cargo test --locked --release d01_redraw_preparation_benchmark -- --ignored --nocapture --test-threads=1` |

## Function matrix

| Function | Linux implementation | Passing evidence |
|---|---|---|
| Text display | `src/editor.rs` text rows and CP437; `src/config.rs` text options; `src/main.rs` frame | Unit `recovered_editor_contract` and `ini_and_text_detection`; Terminal |
| Hex display and movement | `src/editor.rs` Hex rows, navigation, and nibble selection; `src/main.rs` frame | Unit `recovered_editor_contract`; Terminal; Reliability |
| Code display | `src/decoder.rs` Capstone decoder; `src/main.rs` Code rows and addresses | Unit `code_mode_boundaries`; Terminal; Linux |
| Decoder reuse | `src/main.rs` `decoder_for` and `code_rows` | Unit `decoder_for_reuses_and_replaces_decoder`; Benchmark |
| Code movement | `src/editor.rs` navigation; `src/main.rs` instruction history | Terminal; Linux |
| NOP and INT3 packing | `src/main.rs` `decode_at` and `code_rows` | Unit `code_packing_respects_limits_and_settings` |
| Hex editing | `src/editor.rs` `hex_digit`; `src/main.rs` edit input | Unit `recovered_editor_contract`; Reliability |
| Edit cancellation | `src/editor.rs` `cancel_edit` | Unit `recovered_editor_contract`; Reliability; Analysis |
| Current-byte undo | `src/editor.rs` `undo_current_byte` | Unit `recovered_editor_contract`; Reliability |
| Assembly | `src/assembler.rs`; `src/main.rs` `assembly_seed` and edit workflow | Unit `assembler_vectors_and_errors` and `assembly_seed_stays_intel_with_att_display`; Reliability |
| Replacement save | `src/save.rs` `replace` | Nine `src/save.rs` unit checks; Reliability |
| Save As | `src/save.rs` `save_as`; `src/main.rs` target switch | Unit `save_as_uses_atomic_destination_refusal`; Reliability |
| Search | `src/operations.rs` pattern search; `src/main.rs` search workflow | Unit masked and exact search checks; Analysis |
| Strings | `src/inspect.rs` `strings`; `src/workbench.rs` tool workflow | Unit string checks; Analysis |
| Entropy | `src/inspect.rs` `entropy_map`; `src/workbench.rs` tool workflow | Unit `entropy_matches_constant_and_uniform_data`; Analysis |
| Comparison | `src/operations.rs` `differences`; `src/workbench.rs` tool workflow | Unit `comparison_groups_changes_and_length_only_tails`; Analysis |
| XOR and fill | `src/operations.rs` `transform`; `src/workbench.rs` checked ranges | Unit `transforms_repeat_masks_and_reject_invalid_ranges_without_changes`; Analysis |
| Integer inspection | `src/inspect.rs` `integers`; `src/workbench.rs` tool workflow | Unit `integers_handle_endianness_signed_values_and_bounds`; Analysis |
| Analysis browser | `src/workbench.rs` `browse` and `jump` | Analysis paging, scrolling, selection, and cancellation checks |
| PE structure browser | `src/format.rs` `structures`; `src/workbench.rs` PE tool | Unit PE browser checks; Analysis PE32 and PE32+ checks |
| PE address conversion | `src/format.rs` `convert_address`; `src/workbench.rs` address tool | Unit checked-address checks; Analysis PE32 and PE32+ checks |
| Legacy address behavior | `src/format.rs` `entry_point` and `virtual_to_file`; `src/cli.rs` offsets | Unit PE mapping and CLI checks; Files |
| File selection | `src/main.rs` `select_file`, file switching, and current session views | Files picker, next, previous, and restart checks |
| Wildcards and recursion | `src/files.rs` `expand` and `walk`; `src/cli.rs` masks | Unit `native_wildcards_and_recursion`; Files |
| Configuration | `src/config.rs` native and legacy parsing plus discovery | Unit configuration checks; Files; Linux |
| Saved sessions | `src/config.rs` `SavedState`, `parse_saved`, and `encode_saved` | Unit session checks; Files; Reliability; Linux |
| Legacy session import | `src/config.rs` BLZ decode, checksum, and payload retention | Unit `original_save_payloads` and `new_headers_and_legacy_imports`; Files |
| Macro playback | `src/macros.rs` `Playback`; `src/console.rs` event translation | Unit macro checks; Macro |
| Help and prompts | `src/workbench.rs` help, tools, and prompt helpers; `src/console.rs` modal input | Terminal; Analysis; Macro |
| Native self-test | `src/main.rs` `--self-test`; `src/native.rs` explicit library paths | `target/release/hview-linux --self-test`; Package |
| Packaging and CI | `scripts/package.py`, `tests/package_probe.py`, `.github/workflows/ci.yml` | Package hash, isolation, missing-library, and six packaged probe checks |

## Linux differences

| Difference | Behavior | Evidence |
|---|---|---|
| Terminal | Termios raw mode disables flow control and restores terminal state. | Unit terminal layout checks; Terminal |
| Input | Linux sequences map to application keys and preserve prompt characters. | Unit input checks; Terminal; Macro |
| Display safety | Console output escapes terminal controls and accounts for visible cell width. | Unit safe-text checks; Terminal |
| Paths | The CLI accepts Linux paths, Unicode, literal backslashes, and the `--` boundary. | Unit CLI and session checks; Files |
| Configuration lookup | Lookup uses explicit, sibling, XDG, HOME, and portable rules. | Unit configuration-path check; Files |
| Text detection | Linux code detects byte text and refuses UTF-16 Text display. | Unit text-detection checks; Files |
| Native engines | The executable loads verified sibling libraries without current-directory search. | Unit missing-library check; Package |
| Disassembly syntax | Intel is the default. The configuration can select AT&T display. | Unit syntax checks; Linux |
| Real16 | The O key selects Real16 after 64-bit mode. Sessions preserve the selection. | Unit Real16 checks; Linux; tracked Zydis oracle |
| Invalid bytes | `InvalidCode=Error` is strict. `InvalidCode=Byte` emits one-byte rows. | Unit fallback check; Linux |
| Raw ELF | Code mode decodes raw ELF bytes without ELF structure support. | Unit raw-format checks; Linux |
| Save operations | Linux staging preserves supported metadata and uses atomic publication operations. | Nine save unit checks; Reliability |

## Documented limits

| Area | Limit |
|---|---|
| Host | The verified release target is Linux x86-64. |
| Source license | The Rust source has no declared license. Native components keep separate notices. |
| Memory | Each open file uses a complete memory buffer. Edit cancellation keeps a second buffer. |
| Text | Text view is byte-oriented. General Unicode text rendering is outside scope. |
| Sessions | Sessions store 1 through 24 ASCII paths. Each path uses fewer than 260 bytes. |
| Real16 | The application matches display behavior. Execution and segmentation semantics are outside scope. |
| ELF | ELF Code view is raw. ELF structures, symbols, and address mapping are outside scope. |
| Save concurrency | Advisory locks do not stop uncooperative writers. A final pathname race remains possible. |
| Save durability | A final sync failure can leave visible new bytes and retained recovery files. |
| Analysis | Result and parser limits remain the values in `README.md` and `PLAN.md`. |
| Backlog | The excluded Windows backlog in `PLAN.md` remains outside parity scope. |
