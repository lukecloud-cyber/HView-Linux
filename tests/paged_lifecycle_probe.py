#!/usr/bin/env python3
"""Check bounded file lifecycle behavior through a Linux pseudoterminal."""

# These imports provide native byte paths, sparse files, and disposable fixture directories.
# The terminal helper supplies process limits and restoration checks.
import os
from pathlib import Path
import sys
import tempfile

from analysis_probe import pe_fixture, put32
from terminal_probe import run_session


# These terminal sequences cover navigation, editing, history, switching, and blocked edit commands.
# The address-space limit stays below the sparse 4 GiB fixture.
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_T = b"\x14"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
ENTER = b"\r"
ESCAPE = b"\x1b"
ALT_E = b"\x1be"
ALT_G = b"\x1bg"
ALT_N = b"\x1bn"
ALT_O = b"\x1bo"
ALT_P = b"\x1bp"
ALT_S = b"\x1bs"
DOWN = b"\x1b[B"
RIGHT = b"\x1b[C"
ALT_A = b"\x1ba"
ADDRESS_LIMIT = 256 * 1024 * 1024


# This assertion helper requires one byte sequence in captured terminal output.
# A failure includes recent output for diagnosis.
def require(output: bytes, text: bytes, reason: str) -> None:
    """Require one terminal-output value."""
    if text not in output:
        raise AssertionError(f"{reason}: {output[-1000:]!r}")


# This helper selects output after the final display marker.
# Switch and error tests use the result to avoid matching an earlier frame.
def after_last(output: bytes, marker: bytes) -> bytes:
    """Return terminal output after the final required marker."""
    position = output.rfind(marker)
    if position < 0:
        raise AssertionError(f"The terminal output does not contain {marker!r}.")
    return output[position:]


# This assertion helper requires byte sequences in their expected display order.
# Edit checks use the order to distinguish undo, redo, and cancellation frames.
def require_order(output: bytes, *values: bytes) -> None:
    """Require terminal values in order."""
    position = 0
    for value in values:
        position = output.find(value, position)
        if position < 0:
            raise AssertionError(f"The terminal output lacks an ordered value: {value!r}")
        position += len(value)


# This helper creates one sparse file and writes only small marker ranges.
# It flushes marker bytes before the application opens the source.
def sparse_file(path: Path | bytes, length: int, markers: list[tuple[int, bytes]]) -> None:
    """Create one sparse file and write its bounded marker bytes."""
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.ftruncate(descriptor, length)
        for offset, data in markers:
            os.pwrite(descriptor, data, offset)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# This helper reads one bounded marker from a native path and always closes its descriptor.
# Large sparse checks use the helper without loading complete files.
def read_at(path: Path | bytes, length: int, offset: int = 0) -> bytes:
    """Read one bounded marker at an exact file offset."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        return os.pread(descriptor, length, offset)
    finally:
        os.close(descriptor)


# This check opens one source above 4 GiB under a smaller process limit.
# Separate sessions verify low, final, high, and unsupported command behavior.
def check_high_offsets(binary: Path, root: Path) -> tuple[Path, int]:
    """Check first, final, and selected high bytes under a bounded address space."""

    # This sparse source exceeds 4 GiB while all committed data remains small.
    # Each application run has a lower address-space limit than the source length.
    length = (1 << 32) + 0x2000
    high = (1 << 32) + 0x100
    source = root / "above-4g.bin"
    sparse_file(source, length, [(0, b"ABCD"), (high, b"HIGH"), (length - 1, b"Z")])

    # The initial frame must show the first bytes without copying the sparse source.
    first = run_session(
        binary,
        ["--mode=hex", str(source)],
        [CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(first, b"41 42 43 44", "The paged view did not show the first bytes.")

    # Tools remain unavailable until later bounded-view integration.
    # The command must report the limit and then redraw the unchanged source frame.
    unsupported = run_session(
        binary,
        ["--mode=hex", str(source)],
        [CTRL_T, b"\r", CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    notice = b"unavailable for the bounded Hex view"
    require(unsupported, notice, "The paged view did not report the Tools limit.")
    require(
        after_last(unsupported, notice),
        b"41 42 43 44",
        "An unsupported command changed the paged source frame.",
    )

    # The End option first reports the requested Text limitation and then shows the final byte.
    final = run_session(
        binary,
        ["--mode=text", "--end", str(source)],
        [b"\r", CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(final, b"Hex mode only", "The paged view did not report its Hex limitation.")
    require(final, f"{length - 1:08X}".encode(), "The final high address was narrowed.")
    require(final, b"5A", "The paged view did not show the final byte.")

    # Alt+G must parse and display a full u64 file offset and its marker bytes.
    selected = run_session(
        binary,
        ["--mode=hex", str(source)],
        [ALT_G, f"{high:X}".encode(), b"\r", CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(selected, f"{high:08X}".encode(), "Goto narrowed the high file offset.")
    require(selected, b"48 49 47 48", "Goto did not show the high marker bytes.")

    # Unsupported format addresses must report their limit before the Hex view uses offset zero.
    virtual = run_session(
        binary,
        ["--mode=hex", "--virtual", "100", str(source)],
        [b"\r", CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(virtual, b"Virtual and entry-point", "A virtual offset did not report its limit.")
    require(virtual, b"00000000", "A rejected virtual offset did not use file offset zero.")
    return source, high


# This check selects one sparse PE section through bounded entry and virtual metadata reads.
# It also applies the same entry request when an inactive paged session record is created.
def check_paged_pe_startup(binary: Path, root: Path) -> None:
    """Check sparse PE startup, inactive initialization, and format errors."""
    length = (1 << 32) + 0x100
    high = 1 << 32
    source = root / "sparse-pe.bin"
    data, _ = pe_fixture(False)
    fixture = bytearray(data[:0x200])
    section = 0x98 + 0xE0
    put32(fixture, 0x98 + 16, 0x1100)
    put32(fixture, section + 8, 0x200)
    put32(fixture, section + 16, 0x200)
    put32(fixture, section + 20, 0xFFFFFF00)
    sparse_file(source, length, [(0, fixture), (high, b"\xC3PE")])

    # EntryPoint and both compatibility virtual forms must select the same high file byte.
    for option in [["--entry-point"], ["--virtual", "1100"], ["--virtual", "401100"]]:
        output = run_session(
            binary,
            ["--mode=hex", *option, str(source)],
            [CTRL_Q],
            address_limit_bytes=ADDRESS_LIMIT,
        )
        require(output, b"100000000", "Sparse PE startup narrowed the selected offset.")
        require(output, b"C3 50 45", "Sparse PE startup did not show the mapped bytes.")

    # The session constructor keeps its below-4-GiB offset in the unchanged SAV representation.
    inactive = root / "pe-low.bin"
    put32(fixture, 0x98 + 16, 0x1000)
    sparse_file(inactive, length, [(0, fixture), (0xFFFFFF00, b"\xC3PE")])
    small = root / "pe-session-small.bin"
    session = root / "pe-startup.sav"
    small.write_bytes(b"small")
    output = run_session(
        binary,
        ["--mode=hex", "--entry-point", "--session", str(session), str(small), str(inactive)],
        [ALT_N, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    returned = after_last(output, inactive.name.encode())
    require(returned, b"FFFFFF00", "The inactive PE entry offset was not retained.")
    require(returned, b"C3 50 45", "The inactive PE view did not show mapped bytes.")

    # A recognized unsupported signature must show its format error and use the zero fallback.
    rejected = root / "sparse-ne.bin"
    prefix = bytearray(132)
    prefix[:2] = b"MZ"
    put32(prefix, 60, 128)
    prefix[128:130] = b"NE"
    sparse_file(rejected, 64 * 1024 * 1024 + 1, [(0, prefix)])
    output = run_session(
        binary,
        ["--mode=hex", "--entry-point", str(rejected)],
        [ENTER, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"NE, LE, and LX executable formats are unsupported.", "Paged startup lost the format error.")
    require(output, b"00000000", "A rejected paged entry did not use offset zero.")


# This check edits one large source through grouped nibbles and the complete history controls.
# All changes must stay in memory until Escape restores the captured source layout.
def check_paged_edits(binary: Path, source: Path, high: int) -> None:
    """Check paged Hex edits, retained controls, high offsets, and cancellation."""

    # A resize between the two nibbles must keep one history record.
    # Leave commands must preserve the edited bytes, history, cursor, and owned source.
    output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [
            ALT_E,
            b"A",
            (60, 24, b"EDITMODE"),
            b"B",
            CTRL_Z,
            CTRL_Y,
            ALT_G,
            b"0",
            b"\r",
            b"C",
            CTRL_Z,
            CTRL_Y,
            ALT_N,
            b"\r",
            CTRL_Q,
            b"\r",
            ALT_O,
            b"\r",
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            ALT_E,
            CTRL_Z,
            b"\r",
            ESCAPE,
            CTRL_Q,
        ],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"Alt+S to save", "A blocked command did not retain edit mode.")
    require(output, b"Escape in the editor", "A leave command did not explain cancellation.")
    require(output, b"The undo history is empty", "Cancellation did not clear paged history.")
    require_order(
        output,
        b"A1 42 43 44",
        b"AB 42 43 44",
        b"41 42 43 44",
        b"AB 42 43 44",
        b"CB 42 43 44",
        b"AB 42 43 44",
        b"CB 42 43 44",
        b"AB 42 43 44",
        b"CB 42 43 44",
        b"41 42 43 44",
    )

    # Goto after one high nibble must reset the destination to its high nibble.
    # An Alt-modified Hex character must not create an edit record.
    goto_output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [ALT_E, b"A", ALT_G, b"1", b"\r", b"C", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(goto_output, b"A1 C2 43 44", "Goto retained the previous low-nibble state.")
    modified_output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [ALT_E, ALT_A, b"\r", CTRL_Z, b"\r", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(
        modified_output,
        b"The undo history is empty",
        "An Alt-modified Hex key changed paged data.",
    )

    # Normal-mode character aliases must not move the cursor during editing.
    # The next unmodified Hex digit must still change the first high nibble.
    alias_output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [ALT_E, b"lA", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(
        alias_output,
        b"A1 42 43 44",
        "A normal-mode character alias moved the paged edit cursor.",
    )

    # A high Goto keeps the complete u64 cursor through edit, undo, and redo.
    # Escape then restores the original marker and leaves the sparse source unchanged.
    high_output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [
            ALT_G,
            f"{high:X}".encode(),
            b"\r",
            ALT_E,
            b"AB",
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(high_output, f"{high + 1:08X}".encode(), "The edited high cursor was narrowed.")
    require_order(high_output, b"AB 49 47 48", b"48 49 47 48", b"AB 49 47 48", b"48 49 47 48")

    # Nibble navigation can select EOF, but overtype must refuse file growth.
    # Dismissing the error keeps edit mode until Escape performs explicit cancellation.
    eof_output = run_session(
        binary,
        ["--mode=hex", "--end", str(source)],
        [ALT_E, RIGHT, RIGHT, b"F", b"\r", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(eof_output, b"cannot extend the file at EOF", "Paged editing did not refuse EOF growth.")

    # Explicit cancellation never publishes the in-memory bytes to the opened file.
    descriptor = os.open(source, os.O_RDONLY)
    try:
        if os.pread(descriptor, 4, 0) != b"ABCD" or os.pread(descriptor, 4, high) != b"HIGH":
            raise AssertionError("Paged cancellation changed source bytes on disk.")
    finally:
        os.close(descriptor)


# This helper finds the private recovery directory for one native target path.
# The target note stores exact pathname bytes, so the lookup does not use display text.
def recovery_for_target(root: Path, target: Path | bytes) -> Path:
    """Return the single recovery directory for a target."""
    expected = os.fsencode(target) + b"\n"
    matches = [
        folder
        for folder in root.glob(".HView-save-*")
        if (folder / "target.txt").read_bytes() == expected
    ]
    if len(matches) != 1:
        raise AssertionError(f"The target has {len(matches)} recovery directories.")
    return matches[0]


# This check publishes paged replacement and Save As results through their physical shortcuts.
# It verifies fresh baselines, session restart, independent backups, and bounded sparse storage.
def check_paged_saves(binary: Path, root: Path) -> None:
    """Check paged replacement and exclusive Save As publication."""

    # Replacement publishes one changed byte and leaves an independent original backup.
    # A later canceled edit restores the published baseline, and session restart sees that baseline.
    length = 64 * 1024 * 1024 + 1
    source = root / "paged-save.bin"
    session = root / "paged-save.sav"
    sparse_file(source, length, [(0, b"ABCD"), (length - 1, b"Z")])
    output = run_session(
        binary,
        ["--mode=hex", "--session", str(session), str(source)],
        [ALT_E, b"ab", ALT_S, ALT_E, b"c", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require_order(output, b"AB 42 43 44", b"AB C2 43 44", b"AB 42 43 44")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        if os.pread(descriptor, 4, 0) != b"\xabBCD":
            raise AssertionError("Paged replacement did not publish the logical bytes.")
    finally:
        os.close(descriptor)
    replacement = recovery_for_target(root, source)
    backup = replacement / "original.bin"
    descriptor = os.open(backup, os.O_RDONLY)
    try:
        if os.pread(descriptor, 4, 0) != b"ABCD":
            raise AssertionError("Paged replacement did not retain independent original bytes.")
    finally:
        os.close(descriptor)
    restarted = run_session(binary, ["--session", str(session)], [CTRL_Q])
    require(restarted, b"AB 42 43 44", "Session restart did not use the saved paged baseline.")

    # Save As publishes a new path without changing its source.
    # A later canceled edit restores the new destination baseline.
    copy_source = root / "paged-copy-source.bin"
    destination = root / "paged-copy.bin"
    sparse_file(copy_source, length, [(0, b"WXYZ"), (length - 1, b"Q")])
    output = run_session(
        binary,
        ["--mode=hex", str(copy_source)],
        [ALT_E, b"cd", CTRL_S, os.fsencode(destination), b"\r", ALT_E, b"e", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"paged-copy.bin", "Paged Save As did not adopt the destination path.")
    require_order(output, b"CD 58 59 5A", b"CD E8 59 5A", b"CD 58 59 5A")
    if read_at(copy_source, 4) != b"WXYZ":
        raise AssertionError("Paged Save As changed the original source.")
    if read_at(destination, 4) != b"\xcdXYZ":
        raise AssertionError("Paged Save As did not publish the logical bytes.")

    # An existing Save As destination causes a reachable prepublication refusal.
    # Undo, Redo, modal dismissal, and cancellation must retain the active paged edit session.
    refusal_source = root / "paged-refusal-source.bin"
    refusal_destination = root / "paged-refusal-destination.bin"
    sparse_file(refusal_source, length, [(0, b"WXYZ"), (length - 1, b"R")])
    refusal_destination.write_bytes(b"occupied")
    output = run_session(
        binary,
        ["--mode=hex", str(refusal_source)],
        [
            ALT_E,
            b"ab",
            b"cd",
            CTRL_Z,
            CTRL_S,
            os.fsencode(refusal_destination),
            b"\r",
            b"\r",
            CTRL_Y,
            CTRL_Z,
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(
        output,
        b"The Save As destination already exists.",
        "Paged Save As did not report the existing destination.",
    )
    require_order(
        output,
        b"AB CD 59 5A",
        b"AB 58 59 5A",
        b"AB CD 59 5A",
        b"AB 58 59 5A",
        b"57 58 59 5A",
        b"AB 58 59 5A",
        b"57 58 59 5A",
    )
    if refusal_destination.read_bytes() != b"occupied":
        raise AssertionError("Paged Save As changed the existing destination.")
    if read_at(refusal_source, 4) != b"WXYZ":
        raise AssertionError("Paged Save As refusal changed the original source.")

    # One high-offset replacement proves the save remains bounded below the 4 GiB fixture size.
    # Sparse target and backup allocation must remain small after publication.
    high_length = (1 << 32) + 0x2000
    high = (1 << 32) + 0x100
    high_source = root / "paged-high-save.bin"
    sparse_file(
        high_source,
        high_length,
        [(0, b"LOW"), (high, b"HIGH"), (high_length - 1, b"Z")],
    )
    run_session(
        binary,
        ["--mode=hex", str(high_source)],
        [ALT_G, f"{high:X}".encode(), b"\r", ALT_E, b"ab", ALT_S, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    high_backup = recovery_for_target(root, high_source) / "original.bin"
    for path, expected in [(high_source, b"\xabIGH"), (high_backup, b"HIGH")]:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            if os.pread(descriptor, len(expected), high) != expected:
                raise AssertionError(f"The high save bytes are incorrect for {path!r}.")
            if os.fstat(descriptor).st_size != high_length:
                raise AssertionError(f"The high save length is incorrect for {path!r}.")
            if os.fstat(descriptor).st_blocks * 512 >= 16 * 1024 * 1024:
                raise AssertionError(f"The high save became dense for {path!r}.")
        finally:
            os.close(descriptor)


# This check switches between buffered and paged sources before a session restart.
# It verifies the paged offset only in frames after each return.
def check_switch_and_restart(binary: Path, root: Path, large: Path, high: int) -> None:
    """Check mixed storage switches and a paged session restart."""

    # The first switch creates one SAV record for each storage form.
    # Later switches must restore independent buffered and paged positions.
    small = root / "small.bin"
    small.write_bytes(b"small-file")
    session = root / "mixed.sav"
    output = run_session(
        binary,
        ["--mode=hex", "--session", str(session), str(small), str(large)],
        [ALT_N, ALT_G, f"{high:X}".encode(), b"\r", ALT_P, RIGHT, ALT_N, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"small.bin", "The buffered file did not open during mixed switching.")
    require(output, b"above-4g.bin", "The paged file did not open during mixed switching.")
    returned_large = after_last(output, b"above-4g.bin")
    require(
        returned_large,
        f"{high:08X}".encode(),
        "The paged position did not survive switching.",
    )

    # A new process must restore the active paged file and its full u64 position.
    restarted = run_session(
        binary,
        ["--session", str(session)],
        [CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(restarted, b"above-4g.bin", "The session did not restore the paged file.")
    require(restarted, f"{high:08X}".encode(), "The session narrowed the paged position.")


# This check changes active source paths and lengths while descriptors remain open.
# Errors must stop the view before mixed bytes become visible.
def check_source_changes(binary: Path, root: Path) -> None:
    """Check replacement, truncation, and fresh reopen behavior."""

    # Path replacement must stop the active view before replacement bytes become visible.
    length = 64 * 1024 * 1024 + 1
    replaced = root / "replaced.bin"
    old = root / "replaced-old.bin"
    sparse_file(replaced, length, [(0, b"OLD")])

    # This callback replaces the pathname while the application owns the original descriptor.
    # A later input requests another frame and triggers validation.
    def replace_path() -> None:
        """Replace the active pathname with a new sparse file."""
        replaced.rename(old)
        sparse_file(replaced, length, [(0, b"NEW")])

    output = run_session(
        binary,
        ["--mode=hex", str(replaced)],
        [replace_path, RIGHT],
        expected_code=1,
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"different file", "Path replacement did not stop the paged view.")
    if b"4E 45 57" in output:
        raise AssertionError("Replacement bytes became visible before the replacement error.")
    reopened = run_session(
        binary,
        ["--mode=hex", str(replaced)],
        [CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(reopened, b"4E 45 57", "A fresh open did not read the replacement source.")

    # Descriptor validation must report truncation before another frame can publish.
    truncated = root / "truncated.bin"
    sparse_file(truncated, length, [(0, b"KEEP")])
    output = run_session(
        binary,
        ["--mode=hex", str(truncated)],
        [lambda: os.truncate(truncated, 3), RIGHT],
        expected_code=1,
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"shrank outside", "Truncation did not stop the paged view.")

    # An external replacement during edit mode must retain the in-memory owner until Escape.
    # Ctrl+Q cannot discard the edit, and no replacement bytes can enter a validated frame.
    edited = root / "edited-replacement.bin"
    edited_old = root / "edited-replacement-old.bin"
    sparse_file(edited, length, [(0, b"OLD")])

    def replace_edited_path() -> None:
        """Replace the pathname while one paged edit remains active."""
        edited.rename(edited_old)
        sparse_file(edited, length, [(0, b"NEW")])

    output = run_session(
        binary,
        ["--mode=hex", str(edited)],
        [ALT_E, b"A", replace_edited_path, RIGHT, CTRL_Q, ESCAPE],
        expected_code=1,
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"different file", "Edit mode did not report pathname replacement.")
    require(output, b"Edits remain in memory", "A source error did not retain edit ownership.")
    if output.count(b"different file") < 2:
        raise AssertionError("Ctrl+Q discarded the edit session after a source error.")
    if b"4E 45 57" in output:
        raise AssertionError("Replacement bytes became visible during the retained edit session.")

    # A new process uses the normal fresh-open lifecycle and sees the replacement source.
    reopened = run_session(
        binary,
        ["--mode=hex", str(edited)],
        [CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(reopened, b"4E 45 57", "A fresh open did not read the edited replacement source.")


# This check selects and saves an invalid UTF-8 pathname through the native picker.
# Display text uses escapes while native open and replacement preserve exact Path bytes.
def check_native_picker(binary: Path, root: Path) -> None:
    """Check native non-UTF-8 picker input, display, and paged replacement."""

    # The initial ASCII path selects the directory without expanding CLI path support.
    # The picker returns the original invalid pathname bytes for the next native open.
    folder = root / "native-picker"
    folder.mkdir()
    first = folder / "a-first.bin"
    first.write_bytes(b"FIRST")
    native = os.fsencode(folder) + b"/b-native-\xff.bin"
    sparse_file(native, 64 * 1024 * 1024 + 1, [(0, b"NATIVE")])
    output = run_session(
        binary,
        ["--mode=hex", str(first)],
        [ALT_O, DOWN, DOWN, b"\r", ALT_E, b"ab", ALT_S, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"b-native-\\xFF.bin", "The picker did not escape invalid pathname bytes.")
    require(output, b"AB 41 54 49-56 45", "The native paged replacement did not show saved bytes.")
    if read_at(native, 6) != b"\xabATIVE":
        raise AssertionError("Paged replacement changed the native pathname or saved incorrect bytes.")


# This check makes Save As choose a path that the legacy SAV format cannot represent.
# Runtime view state and existing SAV bytes must remain independent from that failure.
def check_session_error_preservation(binary: Path, root: Path) -> None:
    """Check Save As state after legacy path representation fails."""

    # The first run creates stable SAV bytes for two buffered files.
    # The second run changes the native path to a name that legacy SAV cannot represent.
    first = root / "session-first.bin"
    second = root / "session-second.bin"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    session = root / "preserved.sav"
    run_session(
        binary,
        ["--mode=hex", "--session", str(session), str(first), str(second)],
        [CTRL_Q],
    )
    before = session.read_bytes()
    destination = root / "�-copy.bin"
    terminal_destination = os.fsencode(root) + b"/\x82-copy.bin"
    output = run_session(
        binary,
        ["--session", str(session)],
        [
            RIGHT,
            CTRL_S,
            terminal_destination,
            b"\r",
            b"\r",
            ALT_N,
            ALT_P,
            CTRL_Q,
        ],
    )
    require(output, b"Session disabled", "Save As did not report the session path limit.")
    returned_copy = after_last(output, b"\\u{FFFD}-copy.bin")
    require(
        returned_copy,
        b"00000001",
        "The buffered position did not survive later file switches.",
    )
    if not destination.exists():
        names = os.listdir(os.fsencode(root))
        raise AssertionError(f"Save As did not create the expected native path: {names!r}")
    if destination.read_bytes() != first.read_bytes():
        raise AssertionError("Save As did not publish the valid native destination.")
    if session.read_bytes() != before:
        raise AssertionError("A session representation failure changed existing SAV bytes.")

    # A separate paged case publishes one changed sparse source under an unrepresentable session path.
    # File switching must retain the native destination and u64 cursor after session publication stops.
    paged_source = root / "paged-session-source.bin"
    paged_other = root / "paged-session-other.bin"
    paged_session = root / "paged-preserved.sav"
    sparse_file(paged_source, 64 * 1024 * 1024 + 1, [(0x10, b"PAGE")])
    paged_other.write_bytes(b"other")
    run_session(
        binary,
        ["--mode=hex", "--session", str(paged_session), str(paged_source), str(paged_other)],
        [CTRL_Q],
    )
    paged_before = paged_session.read_bytes()
    paged_destination = root / "�-paged-copy.bin"
    terminal_paged_destination = os.fsencode(root) + b"/\x82-paged-copy.bin"
    output = run_session(
        binary,
        ["--session", str(paged_session)],
        [
            ALT_G,
            b"10",
            b"\r",
            ALT_E,
            b"ab",
            CTRL_S,
            terminal_paged_destination,
            b"\r",
            b"\r",
            ALT_N,
            ALT_P,
            CTRL_Q,
        ],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"Session disabled", "Paged Save As did not report the session path limit.")
    returned_paged = after_last(output, b"\\u{FFFD}-paged-copy.bin")
    require(
        returned_paged,
        b"00000011",
        "The paged destination cursor did not survive file switching.",
    )
    if read_at(paged_destination, 4, 0x10) != b"\xabAGE":
        raise AssertionError("Paged Save As did not publish the native destination bytes.")
    if paged_session.read_bytes() != paged_before:
        raise AssertionError("Paged session representation failure changed existing SAV bytes.")


# This entry point creates all lifecycle fixtures in one disposable directory.
# Each check runs the release application through a restored pseudoterminal.
def main() -> None:
    """Run all bounded lifecycle checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: paged_lifecycle_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    # Each disposable directory contains sparse sources, sessions, and replacement files.
    # The terminal helper verifies terminal restoration after every successful or failed process.
    with tempfile.TemporaryDirectory(prefix="hview-paged-lifecycle-") as temporary:
        root = Path(temporary)
        large, high = check_high_offsets(binary, root)
        check_paged_pe_startup(binary, root)
        check_paged_edits(binary, large, high)
        check_switch_and_restart(binary, root, large, high)
        check_paged_saves(binary, root)
        check_source_changes(binary, root)
        check_native_picker(binary, root)
        check_session_error_preservation(binary, root)

    print("Paged lifecycle probe passed.")


if __name__ == "__main__":
    main()
