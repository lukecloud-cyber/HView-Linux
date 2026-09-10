#!/usr/bin/env python3
"""Check bounded file lifecycle behavior through a Linux pseudoterminal."""

# These imports provide native byte paths, sparse files, and disposable fixture directories.
# The terminal helper supplies process limits and restoration checks.
import os
from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


# These terminal sequences cover navigation, editing, history, switching, and blocked edit commands.
# The address-space limit stays below the sparse 4 GiB fixture.
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_T = b"\x14"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
CTRL_F11 = b"\x1b[23;5~"
CTRL_F12 = b"\x1b[24;5~"
ESCAPE = b"\x1b"
F3 = b"\x1b[13~"
F5 = b"\x1b[15~"
F9 = b"\x1b[20~"
F10 = b"\x1b[21~"
DOWN = b"\x1b[B"
RIGHT = b"\x1b[C"
SHIFT_F3 = b"\x1b[13;2~"
ALT_A = b"\x1bA"
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

    # Save As and tools are unavailable until later bounded-view integration.
    # Each command must report the limit and then redraw the unchanged source frame.
    unsupported = run_session(
        binary,
        ["--mode=hex", str(source)],
        [CTRL_S, b"\r", CTRL_T, b"\r", CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    notice = b"unavailable for the bounded Hex view"
    if unsupported.count(notice) < 2:
        raise AssertionError("The paged view did not report both unsupported commands.")
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

    # F5 must parse and display a full u64 file offset and its marker bytes.
    selected = run_session(
        binary,
        ["--mode=hex", str(source)],
        [F5, f"{high:X}".encode(), b"\r", CTRL_Q],
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


# This check edits one large source through grouped nibbles and the complete history controls.
# All changes must stay in memory until Escape restores the captured source layout.
def check_paged_edits(binary: Path, source: Path, high: int) -> None:
    """Check paged Hex edits, retained controls, high offsets, and cancellation."""

    # A resize between the two nibbles must keep one history record.
    # Blocked commands must preserve the edited bytes, history, cursor, and owned source.
    output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [
            F3,
            b"A",
            (60, 24, b"EDITMODE"),
            b"B",
            F3,
            SHIFT_F3,
            F5,
            b"0",
            b"\r",
            b"C",
            CTRL_Z,
            CTRL_Y,
            CTRL_S,
            b"\r",
            F9,
            b"\r",
            CTRL_F12,
            b"\r",
            CTRL_Q,
            b"\r",
            F10,
            b"\r",
            F3,
            SHIFT_F3,
            ESCAPE,
            F3,
            F3,
            b"\r",
            ESCAPE,
            CTRL_Q,
        ],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(output, b"Memory edits remain", "A blocked command did not retain edit mode.")
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
        [F3, b"A", F5, b"1", b"\r", b"C", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(goto_output, b"A1 C2 43 44", "Goto retained the previous low-nibble state.")
    modified_output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [F3, ALT_A, F3, b"\r", ESCAPE, CTRL_Q],
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
        [F3, b"lA", ESCAPE, CTRL_Q],
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
            F5,
            f"{high:X}".encode(),
            b"\r",
            F3,
            b"AB",
            F3,
            SHIFT_F3,
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
        [F3, RIGHT, RIGHT, b"F", b"\r", ESCAPE, CTRL_Q],
        address_limit_bytes=ADDRESS_LIMIT,
    )
    require(eof_output, b"cannot extend the file at EOF", "Paged editing did not refuse EOF growth.")

    # The application never publishes the in-memory bytes to the opened file during L03.3.
    descriptor = os.open(source, os.O_RDONLY)
    try:
        if os.pread(descriptor, 4, 0) != b"ABCD" or os.pread(descriptor, 4, high) != b"HIGH":
            raise AssertionError("Paged cancellation changed source bytes on disk.")
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
        [CTRL_F12, F5, f"{high:X}".encode(), b"\r", CTRL_F11, RIGHT, CTRL_F12, CTRL_Q],
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
        [F3, b"A", replace_edited_path, RIGHT, CTRL_Q, ESCAPE],
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


# This check selects an invalid UTF-8 pathname through the native picker.
# Display text uses escapes while the selected Path bytes remain unchanged.
def check_native_picker(binary: Path, root: Path) -> None:
    """Check native non-UTF-8 picker input and escaped display text."""

    # The initial ASCII path selects the directory without expanding CLI path support.
    # The picker returns the original invalid pathname bytes for the next native open.
    folder = root / "native-picker"
    folder.mkdir()
    first = folder / "a-first.bin"
    first.write_bytes(b"FIRST")
    native = os.fsencode(folder) + b"/b-native-\xff.bin"
    descriptor = os.open(native, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, b"NATIVE")
    finally:
        os.close(descriptor)
    output = run_session(binary, ["--mode=hex", str(first)], [F9, DOWN, DOWN, b"\r", CTRL_Q])
    require(output, b"b-native-\\xFF.bin", "The picker did not escape invalid pathname bytes.")
    require(output, b"4E 41 54 49-56 45", "The picker did not open the native pathname.")


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
            CTRL_F12,
            CTRL_F11,
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
        check_paged_edits(binary, large, high)
        check_switch_and_restart(binary, root, large, high)
        check_source_changes(binary, root)
        check_native_picker(binary, root)
        check_session_error_preservation(binary, root)

    print("Paged lifecycle probe passed.")


if __name__ == "__main__":
    main()
