# HView-Linux

HView-Linux is a terminal hex editor and binary analysis tool for Linux x86-64.

The application provides Text, Hex, and x86 Code views. It also provides safe editing, sessions, macros, and PE analysis tools.

## Requirements

Use a Linux x86-64 system with a UTF-8 terminal.

Install Rust 1.98.0 and Cargo to build the application. Install Python 3, `binutils`, and `acl` to run all checks.

The repository contains the required Capstone and Keystone shared libraries. The build does not require a system installation of these libraries.

The current checked package references GLIBC_2.34 as its highest glibc symbol version. Later builds can change this measured floor.

The package needs compatible system `libc`, dynamic loader, `libgcc_s`, `libm`, and `libstdc++` libraries. This GNU package does not support musl-only systems.

## Build and run

Build the release executable from the locked dependencies:

```sh
cargo build --locked --release
```

Run the executable with one or more files or file masks:

```sh
target/release/hview-linux sample.bin
target/release/hview-linux --mode code --entry-point sample.exe
target/release/hview-linux --mode hex --offset 20 --recursive '*.bin'
```

Quote a file mask to prevent shell expansion. Use `--` before a file name that starts with a hyphen.

Run the native engine check:

```sh
target/release/hview-linux --self-test
```

## Install a checked package

Build a package in a new directory:

```sh
python3 scripts/package.py
```

The command prints the new package path. You can also give the command a new output directory.

```sh
python3 scripts/package.py /tmp/hview-linux-package
```

Copy the complete package directory to the installation location. Keep both shared libraries beside the executable.

The package contains the executable, shared libraries, native notices, native metadata, this README, and the configuration sample.

The package manifest gives the SHA-256 hash and size of each packaged file.

## Command options

| Option | Action |
| --- | --- |
| `--mode text\|hex\|code` | The option selects the initial view mode. |
| `--offset HEX` | The option selects a hexadecimal file offset. |
| `--virtual HEX` | The option uses retained legacy virtual-address selection. |
| `--entry-point` | The option uses retained legacy entry-point selection. |
| `--end` | The option selects the final byte. |
| `--config PATH` | The option reads the specified configuration file. |
| `--session PATH` | The option reads and writes the specified session file. |
| `--macro PATH` | The option plays the specified startup macro. |
| `--recursive` | The option enables recursion for following file masks. |
| `--help` | The option shows command help without an interactive terminal. |

The application also accepts the verified legacy `/O`, `/SAV`, `/INI`, `/MACRO0`, and `/s` forms.

For PE files, `--virtual` accepts an RVA or preferred ImageBase VA. Directly mapped raw values also follow retained legacy behavior.

For ordinary raw files, `--virtual` uses the value as a file offset. Raw ELF files reject startup virtual-address mapping.

`--entry-point` also supports the retained DOS executable calculation.

## Main keys

| Key | Action |
| --- | --- |
| `F1` | The key shows help. |
| `F2` or `Enter` | The key opens the Intel assembler during Code editing. |
| `F3` | The key starts editing or restores the current edited byte. |
| `F4`, `M`, or `Enter` | The key selects Text, Hex, or Code mode outside editing. |
| `F5` | The key goes to a file offset. |
| `F7` | The key starts an ASCII or masked hexadecimal search. |
| `Shift+F7` | The key finds the next match. |
| `Ctrl+F7` | The key finds the previous match. |
| `F9` | The key saves edits or opens the file browser. |
| `Ctrl+S` | The key saves the buffer to a new file. |
| `Ctrl+T` | The key opens the analysis tools. |
| `Ctrl+F11` | The key opens the previous input file. |
| `Ctrl+F12` | The key opens the next input file. |
| `O` | The key cycles 16-bit, 32-bit, 64-bit, and Real16 Code modes. |
| `H`, `J`, `K`, or `L` | These keys move the cursor outside editing. |
| `Esc` | The key cancels editing or closes the current screen. |
| `F10` or `Ctrl+Q` | The key exits the application. |

Arrow, Home, End, Page Up, and Page Down keys also move the cursor.

Hex search accepts complete byte pairs and wildcard nibbles. For example, enter `48 8B ?? A? ?F`.

## Configuration

The application loads one configuration file. The application uses the first applicable item in this list:

1. The path from `--config`.
2. `hview-linux.ini` beside the executable.
3. `$XDG_CONFIG_HOME/hview-linux/hview-linux.ini` when `XDG_CONFIG_HOME` is absolute.
4. `$HOME/.config/hview-linux/hview-linux.ini` in other cases.

Set `HVIEW_PORTABLE=1` to stop automatic lookup after the file beside the executable. An explicit `--config` path still has precedence.

Start a native configuration file with this exact header:

```ini
[HView-Linux 1]
```

Use UTF-8 and LF line endings. The parser accepts semicolon comments outside quoted values.

Copy `hview-linux.ini.example` to an applicable `hview-linux.ini` path. Change only settings that you need.

| Setting | Accepted values and effect |
| --- | --- |
| `StartMode` | `Text`, `Hex`, or `Code` selects the initial mode. |
| `Wrap` | `Auto`, `On`, or `Off` controls Text wrapping. |
| `Tab` | `Auto`, `On`, or `Off` controls Text tab expansion. |
| `LineFeed` | `Auto`, `CRLF`, `CR`, or `LF` selects Text line separation. |
| `AutoCodeSize` | `On` uses a detected PE 32-bit or 64-bit code size. |
| `DefaultCodeSize` | `16`, `32`, or `64` selects the other default code size. |
| `DisassemblySyntax` | `Intel` or `ATT` selects the Code display syntax. |
| `InvalidCode` | `Error` stops at an invalid instruction. `Byte` shows one `db` byte and continues. |
| `OpcodeShowBytes` | A value from `0` through `15` sets the displayed opcode byte count. |
| `HexDelimiterChar` | A numeric value from `1` through `255` selects the Hex delimiter byte. |
| `ShowOffset` | `Local` selects supported offset display. `Global` is not reconstructed. |
| `PackNops` | `On` or `Off` controls repeated NOP packing. |
| `PackInt3` | `On` or `Off` controls repeated INT3 packing. |
| `SaveFileAtExit` | `On` or `Off` controls automatic session saving. |
| `SaveFile` | A quoted path selects the automatic session file. |

The native default is Intel disassembly syntax. Select `DisassemblySyntax=ATT` only when you need AT&T display syntax.

The default invalid-instruction behavior is `InvalidCode=Error`. Select `InvalidCode=Byte` to continue with a one-byte `db` row.

Assembly input always uses Intel syntax. The assembler prompt also shows Intel syntax when the Code display uses AT&T syntax.

Press `O` to select Real16 after 64-bit Code mode. The Code header shows `Real16` for this mode.

Real16 applies the retained real-mode instruction policy. A native saved session preserves this selection in a versioned Linux extension.

Real16 rejects protected-mode-only instruction forms. Real16 wraps displayed relative branch targets to the 16-bit address range.

The parser reports unknown settings and invalid values. The application can import verified legacy configuration files with the `[HViewIni 5.03]` header.

## Analysis tools

Press `Ctrl+T`, and then select one tool:

| Key | Tool |
| --- | --- |
| `A` | The tool converts a checked PE file offset, RVA, or preferred ImageBase VA. |
| `S` | The tool finds printable ASCII and ASCII encoded as UTF-16LE or UTF-16BE. |
| `P` | The tool browses PE sections, directories, imports, exports, security data, and overlay data. |
| `E` | The tool shows an entropy map in bits per byte. |
| `D` | The tool compares the current buffer with another file at equal offsets. |
| `I` | The tool shows signed and unsigned integers at the cursor. |
| `X` | The tool applies a repeating hexadecimal XOR mask during editing. |
| `F` | The tool fills an edit range with a repeating hexadecimal pattern. |

All analysis tools use the current buffer. Therefore, the tools include unsaved edits.

The address tool is separate from retained command-line address selection. The tool reports checked file, RVA, and VA results without legacy fallbacks.

PE parsing supports checked PE32 and PE32+ file-backed mappings. The PE browser limits output to 10,000 rows.

Code mode can decode raw x86 bytes in non-PE files. Raw ELF files do not receive ELF headers, symbols, or virtual-address mapping.

String results use a four-character minimum and a 120-character display limit. String and comparison browsers limit output to 10,000 rows.

The entropy tool uses blocks of at least 4,096 bytes. The tool increases the block size for large files.

## Editing and saving

Press `F3` to start editing. Hex mode replaces nibbles, and Code mode assembles one Intel instruction.

Press `Esc` to restore the pre-edit buffer. The application keeps a full memory copy for this cancellation operation.

Press `F9` to replace the current file. Press `Ctrl+S` to save the buffer under a new name.

An in-place save checks the original bytes, file identity, metadata, and an advisory file lock before publication.

The replacement keeps the owner, group, permission mode, user xattrs, and POSIX access ACL. The replacement receives a new inode.

The save keeps the original bytes in a private `.HView-save-*` directory beside the target. The backup keeps original access and modification timestamps.

The save rejects symbolic links, multiple hard links, set-user-ID files, set-group-ID files, and unsupported privileged metadata.

Save As atomically refuses an existing destination entry. Successful publication flushes the staged files and their parent directory.

Advisory locks only coordinate with programs that use compatible locks. An uncooperative writer can change the target during the final rename interval.

Do not write the same file concurrently from another program.

A final synchronization failure can leave visible new bytes and recovery files. Read the displayed recovery path before further file changes.

## Sessions and macros

Use `--session PATH` to enable one session file. `SaveFileAtExit=On` enables the configured session file.

A session stores 1 through 24 files. Each stored path must contain fewer than 260 ASCII bytes.

New sessions store absolute Linux paths. A decoded session payload cannot exceed 16 MiB.

A session cannot add Real16 state when unknown data occupies the Linux extension area.

Unicode file paths work without session storage. A session cannot store a Unicode path.

The application imports verified legacy compressed sessions. It preserves verified unknown payload bytes when it updates a session.

Use `--macro PATH` to play one verified legacy `HViewMacro` file at startup. A macro can contain at most 1,024 records.

Macro records can contain delays, repetition, key modifiers, and stop-on-notice behavior. Press `Esc` to cancel active playback.

The macro delay field supports values through 4,294,967,295 milliseconds. Escape cancels a maximum delay promptly.

The application keeps terminal input that arrives during a macro delay. A macro file is an imported binary format; the application has no macro recorder.

## Memory and format limits

The application reads each open file into memory. Editing keeps another complete buffer until you save or cancel the edits.

Comparison also reads the other file into memory. Select file sizes that fit available memory with these copies.

Text mode supports byte-oriented text. Text mode reports UTF-16 text and directs the user to Hex or Code mode.

The structure browser and address conversion support PE files. HView-Linux does not provide ELF structure browsing or ELF address conversion.

## Native components and licenses

Code display uses Capstone 5.0.9. Assembly uses Keystone 0.9.2.

The application first loads `libcapstone.so` and `libkeystone.so` beside the executable. Development builds can use the repository `lib` directory as a fallback.

Set `HVIEW_PORTABLE=1` to disable the development fallback. The release package check uses this setting from an isolated working directory.

`lib/native-dependencies.json` records upstream sources, source revisions, wheel hashes, member hashes, delivered hashes, transformations, and notice hashes.

The delivered Keystone library has no inherited RPATH. The metadata records the verified Patchelf transformation that removed the upstream wheel RPATH.

The package check verifies all recorded native hashes. The check also rejects native RPATH, RUNPATH, AUDIT, and DEPAUDIT tags.

The HView-Linux Rust source currently has no declared license. The native components keep their separate upstream notice files.

Review the source license state and all native notice files before redistribution.

## Verification

Run the local checks:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
target/release/hview-linux --self-test
python3 tests/terminal_probe.py target/release/hview-linux
python3 tests/file_workflow_probe.py target/release/hview-linux
python3 tests/reliability_probe.py target/release/hview-linux
python3 tests/analysis_probe.py target/release/hview-linux
python3 tests/macro_probe.py target/release/hview-linux
python3 tests/linux_behavior_probe.py target/release/hview-linux
python3 scripts/package.py /tmp/hview-linux-package
```

The CI workflow and package command run every application probe. The package command uses the packaged executable with portable native loading.
