#!/usr/bin/env python3
"""Check grouped edit undo and redo through a Linux pseudoterminal."""

from pathlib import Path
import sys
import tempfile

from macro_probe import macro_file
from terminal_probe import run_session


CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_T = b"\x14"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
ENTER = b"\r"
ESCAPE = b"\x1b"
F2 = b"\x1b[12~"
F3 = b"\x1b[13~"
F9 = b"\x1b[20~"
RIGHT = b"\x1b[C"
SHIFT_F3_CSI = b"\x1b[13;2~"
SHIFT_F3_SS3 = b"\x1bO1;2R"


def require(output: bytes, *values: bytes) -> None:
    """Require each terminal value."""
    for value in values:
        if value not in output:
            raise AssertionError(f"The terminal output lacks: {value!r}")


def require_order(output: bytes, *values: bytes) -> None:
    """Require terminal values in order."""
    position = 0
    for value in values:
        position = output.find(value, position)
        if position < 0:
            raise AssertionError(f"The terminal output lacks an ordered value: {value!r}")
        position += len(value)


def header(offset: int) -> bytes:
    """Return the selected file offset header."""
    return f"{offset:08X}\N{BOX DRAWINGS LIGHT VERTICAL}HView-Linux".encode()


def hex_row(values: str) -> bytes:
    """Return the first hexadecimal data row."""
    return f"00000000:  {values}".encode()


def range_edit(tool: bytes, span: str, pattern: str) -> list[bytes]:
    """Return actions for one range edit."""
    return [CTRL_T, tool, span.encode(), ENTER, pattern.encode(), ENTER]


def check_hex_groups_and_resize(binary: Path, root: Path) -> None:
    """Check grouped nibbles, cursor state, and resize events."""
    path = root / "groups.bin"
    path.write_bytes(b"\x12")
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [
            F3,
            b"A",
            (60, 24, b"EDITMODE"),
            b"B",
            F3,
            SHIFT_F3_CSI,
            F3,
            b"C",
            CTRL_Z,
            CTRL_Y,
            b"D",
            F3,
            F3,
            (80, 24, b"EDITMODE"),
            ESCAPE,
            CTRL_Q,
        ],
    )
    require_order(
        output,
        hex_row("A2"),
        header(1),
        hex_row("AB"),
        header(0),
        hex_row("12"),
        header(1),
        hex_row("AB"),
        header(0),
        hex_row("12"),
        hex_row("C2"),
        hex_row("12"),
        hex_row("C2"),
        header(1),
        hex_row("CD"),
        header(0),
        hex_row("C2"),
        header(0),
        hex_row("12"),
    )
    if path.read_bytes() != b"\x12":
        raise AssertionError("Edit cancellation did not restore the complete baseline.")


def check_redo_retention_and_change(binary: Path, root: Path) -> None:
    """Check failed, canceled, no-op, and changed operations."""
    path = root / "redo.bin"
    original = b"\x10\x20\x30\x40"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [
            F3,
            b"AA",
            F3,
            *range_edit(b"f", "3 2", "11"),
            ENTER,
            CTRL_T,
            b"f",
            ESCAPE,
            *range_edit(b"f", "0 1", "10"),
            CTRL_Y,
            F3,
            b"BB",
            CTRL_Y,
            ENTER,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"The block extends past the file end.",
        b"The redo history is empty.",
    )
    require_order(output, b"AA 20 30 40", b"10 20 30 40", b"AA 20 30 40", b"BB 20 30 40")
    if path.read_bytes() != original:
        raise AssertionError("The redo retention workflow changed the file.")


def check_range_records_and_cancel(binary: Path, root: Path) -> None:
    """Check Fill, XOR, and complete edit cancellation."""
    path = root / "ranges.bin"
    original = b"\x10\x20\x30\x40"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [
            F3,
            *range_edit(b"f", "0 4", "11"),
            F3,
            SHIFT_F3_SS3,
            *range_edit(b"x", "0 4", "FF"),
            F3,
            CTRL_Y,
            ESCAPE,
            (20, 3, b"\x1b[3;1H"),
            F3,
            F3,
            (80, 24, b"The undo history is empty."),
            ENTER,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require_order(
        output,
        b"11 11 11 11",
        b"10 20 30 40",
        b"11 11 11 11",
        b"EE EE EE EE",
        b"11 11 11 11",
        b"EE EE EE EE",
        b"10 20 30 40",
    )
    require(output, b"The undo history is empty.")
    if path.read_bytes() != original:
        raise AssertionError("Edit cancellation did not restore range edits.")


def check_growth_and_save_resets(binary: Path, root: Path) -> None:
    """Check EOF length restoration and successful save resets."""
    path = root / "growth.bin"
    path.write_bytes(b"\x12")
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [RIGHT, F3, b"AB", CTRL_Z, CTRL_Y, F9, F3, F3, ENTER, ESCAPE, CTRL_Q],
    )
    require_order(output, header(2), header(1), header(2))
    require(output, b"The undo history is empty.")
    if path.read_bytes() != b"\x12\xAB":
        raise AssertionError("EOF redo or replacement save wrote incorrect bytes.")

    source = root / "source.bin"
    copy = root / "copy.bin"
    source.write_bytes(b"\x34")
    output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [
            F3,
            b"CD",
            CTRL_S,
            str(copy).encode(),
            ENTER,
            F3,
            F3,
            ENTER,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(output, b"The undo history is empty.")
    if source.read_bytes() != b"\x34" or copy.read_bytes() != b"\xCD":
        raise AssertionError("Save As reset history or wrote incorrect bytes.")


def check_failed_save(binary: Path, root: Path) -> None:
    """Check that failed replacement and Save As keep history."""
    path = root / "failed.bin"
    path.write_bytes(b"\x56")
    output = run_session(
        binary,
        ["--mode=hex", str(path)],
        [
            F3,
            b"AA",
            lambda: path.write_bytes(b"\xEE"),
            F9,
            ENTER,
            F3,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(output, b"changed outside")
    require_order(output, b"AA", b"changed outside", b"56", b"AA")
    if path.read_bytes() != b"\xEE":
        raise AssertionError("The failed save replaced the external bytes.")

    source = root / "failed-as.bin"
    existing = root / "existing.bin"
    source.write_bytes(b"\x56")
    existing.write_bytes(b"\x77")
    output = run_session(
        binary,
        ["--mode=hex", str(source)],
        [
            F3,
            b"AA",
            CTRL_S,
            str(existing).encode(),
            ENTER,
            ENTER,
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(output, b"The destination already exists.")
    require_order(output, b"AA", b"destination already exists", b"56", b"AA")
    if source.read_bytes() != b"\x56" or existing.read_bytes() != b"\x77":
        raise AssertionError("The failed Save As changed a file.")


def check_assembly_record(binary: Path, root: Path) -> None:
    """Check assembly EOF growth and canceled-preview history."""
    config = root / "code.ini"
    config.write_bytes(b"[HView-Linux 1]\nStartMode=Code\nDefaultCodeSize=32\n")
    path = root / "assembly.bin"
    original = b"\x90"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), str(path)],
        [
            RIGHT,
            F3,
            F2,
            b"ret",
            ENTER,
            ENTER,
            ESCAPE,
            F3,
            F2,
            b"nop",
            ENTER,
            ESCAPE,
            CTRL_Y,
            F9,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Assembly patch preview",
        b"Original bytes (0): <end of file>",
        b"Replacement bytes (1): C3",
        b"Replacement bytes (1): 90",
    )
    require_order(output, header(2), header(1), header(2))
    if path.read_bytes() != b"\x90\xC3":
        raise AssertionError("Assembly redo used canceled preview bytes.")


def check_control_macro(binary: Path, root: Path) -> None:
    """Check that a Ctrl macro character is not a hex digit."""
    path = root / "macro.bin"
    macro = root / "control.mac"
    path.write_bytes(b"\x12")
    macro.write_bytes(
        macro_file(
            [
                (0, 0xFF3D),
                (2, ord("A")),
                (0, ord("B")),
                (0, 0xFF43),
                (2, ord("Q")),
            ]
        )
    )
    run_session(binary, ["--mode=hex", "--macro", str(macro), str(path)], [])
    if path.read_bytes() != b"\xB2":
        raise AssertionError("A Ctrl macro character changed a hexadecimal edit byte.")


def main() -> None:
    """Run the edit history checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: edit_history_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-edit-history-") as temporary:
        root = Path(temporary)
        check_hex_groups_and_resize(binary, root)
        check_redo_retention_and_change(binary, root)
        check_range_records_and_cancel(binary, root)
        check_growth_and_save_resets(binary, root)
        check_failed_save(binary, root)
        check_assembly_record(binary, root)
        check_control_macro(binary, root)
    print("Edit history probe passed.")


if __name__ == "__main__":
    main()
