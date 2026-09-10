# HView-Linux verification matrix

This matrix maps each function in `PLAN.md` to Linux source and executable evidence.
Use `TRACKER.md` for task status and Astra review results.

This matrix and its documented limits preserve the accepted D03 through D07 baseline.
They do not describe current work after D07.
See the L02.2 evidence in `TRACKER.md` for current bounded file-lifecycle results.

Astra accepted the original D03 matrix and Linux differences at source commit `5febcd48d5d71642fd4d6eca7bd67ff273e149a4`.
The original D03 package is `target/packages/hview-linux-x86_64-5febcd4`.
The packaged executable SHA-256 is `e0ebf155b1392a955aa1b2d941120889ef4e2511ebf6824a65e116ea696e12c7`.
Local CI-equivalent checks passed.
Hosted CI passed after publication of `a2e6ddd` and `aa5bd96`.
See `TRACKER.md` for both hosted run links.

The approved extension adds D04 through D07 from Windows commit `a3b7240ae0288be383f16135fe6a2f31427fc95c`.
Astra accepted D04 at `1793755`, D05 at `04e5610`, and D06 at `d447c4d`.
Astra accepted D07 at `5e4ef682cda663f5f64c0700c6268c16d3850447`.
The extension package passed every application probe, native hash check, isolation check, and missing-library check.
The extension package is `target/packages/hview-linux-x86_64-5e4ef68`.
The extension executable SHA-256 is `b55b91b7d3f0735a0980bf57909b83ddef41bf5388041d4e51f5700c39d8c964`.
The extension passes formatting, 83 Rust tests, strict Clippy, a fresh release build, and the native self-test.
The manual decoder preparation benchmark also passed.
Astra accepted the final package, complete matrix, and Linux differences after reviewing records at `56484b0`.
Astra independently reran the package probe and verified the executable hash and packaged README.
Hosted CI passed the complete extension checks for [72c68bf](https://github.com/lukecloud-cyber/HView-Linux/actions/runs/33989620026).

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
| Navigation | `python3 tests/navigation_probe.py target/release/hview-linux` |
| Raw | `python3 tests/raw_model_probe.py target/release/hview-linux` |
| Patch | `python3 tests/patch_probe.py target/release/hview-linux` |
| History | `python3 tests/edit_history_probe.py target/release/hview-linux` |
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
| Operation undo and redo | `src/editor.rs` edit records; `src/main.rs` edit input; `src/workbench.rs` transforms | Unit grouping, limits, raw redo, dirty state, and atomic refusal; History; Reliability |
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
| Packaging and CI | `scripts/package.py`, `tests/package_probe.py`, `.github/workflows/ci.yml` | Package hash, isolation, missing-library, and every packaged application probe |
| Direct branch navigation | `src/decoder.rs` direct targets; `src/format.rs` checked mappings; `src/main.rs` follow/return | Navigation; Unit direct targets, mappings, bounds, and histories |
| Raw address model | `src/editor.rs` raw state; `src/format.rs` mappings; `src/workbench.rs` grammar; `src/inspect.rs` byte order | Raw; Unit grammar, address limits, mapping, growth, and AUTO state |
| Assembly preview | `src/main.rs` preview construction, instruction rows, and confirmation | Patch; Unit strict replacement decoding, exact bytes, and preview boundaries |

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
| Code Enter | Enter and Ctrl+M share a terminal byte. Both follow branches outside editing. F4 and M select modes. | Navigation; Macro |
| Raw and Real16 | Explicit raw width overrides AUTO. Raw 16-bit mode uses linear addresses and does not use Real16. | Raw; Navigation; Linux |
| Preview dimensions | The complete summary must fit before Apply. Resize and input checks use current terminal dimensions. | Patch, including immediate resize with Enter |
| Edit history keys | F3/Ctrl+Z undo during editing. Shift+F3/Ctrl+Y redo. Resize preserves hexadecimal grouping. | Unit input checks; History; Macro |
| Save operations | Linux staging preserves supported metadata and uses atomic publication operations. | Nine save unit checks; Reliability |

## Documented limits

| Area | Limit |
|---|---|
| Host | The verified release target is Linux x86-64. |
| Source license | The Rust source has no declared license. Native components keep separate notices. |
| Memory | Each open file uses a complete memory buffer. Edit cancellation keeps a second buffer. |
| Edit history | History permits 256 records and 64 MiB of stored before/after bytes. Older records can expire. |
| Raw model | Settings are transient. Raw models provide linear mappings without ELF structure interpretation. |
| Preview | Apply requires 60 columns and enough rows for the full summary. Instruction rows can show truncation markers. |
| Text | Text view is byte-oriented. General Unicode text rendering is outside scope. |
| Sessions | Sessions store 1 through 24 ASCII paths. Each path uses fewer than 260 bytes. |
| Real16 | The application matches display behavior. Execution and segmentation semantics are outside scope. |
| ELF | ELF Code view is raw. ELF structures, symbols, and address mapping are outside scope. |
| Save concurrency | Advisory locks do not stop uncooperative writers. A final pathname race remains possible. |
| Save durability | A final sync failure can leave visible new bytes and retained recovery files. |
| Analysis | Result and parser limits remain the values in `README.md` and `PLAN.md`. |
| Backlog | The excluded Windows backlog in `PLAN.md` remains outside parity scope. |
