#!/usr/bin/env python3
"""Check Linux arguments, configuration, files, macros, and sessions."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from terminal_probe import run_session


CTRL_Q = b"\x11"
CTRL_F11 = b"\x1b[23;5~"
CTRL_F12 = b"\x1b[24;5~"
F9 = b"\x1b[20~"
DOWN = b"\x1b[B"


def native_config(mode: str) -> bytes:
    """Make a small native configuration file."""
    return f"[HView-Linux 1]\nStartMode={mode}\n".encode()


def macro_file(key: int, modifiers: int = 0) -> bytes:
    """Make one legacy macro event."""
    data = bytearray(69)
    data[:10] = b"HViewMacro"
    data[14:16] = (0x9006).to_bytes(2, "little")
    data[16:18] = (1).to_bytes(2, "little")
    data.extend(bytes([modifiers]))
    data.extend(key.to_bytes(4, "little"))
    return bytes(data)


def checksum(data: bytes) -> int:
    """Calculate the saved payload checksum."""
    full = len(data) & ~3
    value = 0
    for byte in reversed(data[full:]):
        value = ((value << 9) + byte) & 0xFFFFFFFF
    value = (value * 8) & 0xFFFFFFFF
    for offset in range(0, full, 4):
        rotated = ((value << 1) | (value >> 31)) & 0xFFFFFFFF
        word = int.from_bytes(data[offset : offset + 4], "little")
        value = (value + rotated + word) & 0xFFFFFFFF
    return value


def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


def main() -> None:
    """Run the file workflow checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: file_workflow_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    help_result = subprocess.run(
        [binary, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if help_result.returncode != 0 or b"--session PATH" not in help_result.stdout:
        raise AssertionError("Help did not work without a terminal.")
    invalid = subprocess.run(
        [os.fsencode(binary), b"bad-\xff"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if invalid.returncode == 0 or b"not valid UTF-8" not in invalid.stderr:
        raise AssertionError("A non-UTF-8 argument did not produce a clear error.")

    with tempfile.TemporaryDirectory(prefix="hview-files-") as temporary:
        root = Path(temporary)
        data_file = root / "data.bin"
        data_file.write_bytes(bytes(range(32)))
        output = run_session(
            binary,
            ["--mode", "hex", "--offset", "10", str(data_file)],
            [CTRL_Q],
        )
        require(output, b"00000010", "The native offset did not select byte 0x10.")
        output = run_session(binary, ["--mode=hex", "--end", str(data_file)], [CTRL_Q])
        require(output, b"0000001F", "The end option did not select the final byte.")

        unicode_file = root / "r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}.bin"
        unicode_file.write_bytes(b"Unicode path")
        run_session(binary, [str(unicode_file)], [CTRL_Q])

        hyphen_file = root / "-literal.bin"
        hyphen_file.write_bytes(b"Hyphen path")
        old_directory = Path.cwd()
        try:
            os.chdir(root)
            run_session(binary, ["--", hyphen_file.name], [CTRL_Q])
        finally:
            os.chdir(old_directory)

        copied = root / "bin" / "hview-linux"
        copied.parent.mkdir()
        shutil.copy2(binary, copied)
        xdg = root / "xdg"
        xdg_config = xdg / "hview-linux" / "hview-linux.ini"
        xdg_config.parent.mkdir(parents=True)
        xdg_config.write_bytes(native_config("Hex"))
        environment = os.environ.copy()
        environment.pop("HVIEW_PORTABLE", None)
        environment["XDG_CONFIG_HOME"] = str(xdg)
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"00000000:", "The XDG configuration did not select Hex mode.")

        sibling_config = copied.with_name("hview-linux.ini")
        sibling_config.write_bytes(native_config("Text"))
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"2Unwrap", "The sibling configuration did not have precedence.")

        explicit_config = root / "explicit.ini"
        explicit_config.write_bytes(native_config("Hex"))
        output = run_session(
            copied,
            ["--config", str(explicit_config), str(data_file)],
            [CTRL_Q],
            environment,
        )
        require(output, b"00000000:", "The explicit configuration did not have precedence.")

        sibling_config.unlink()
        environment["HVIEW_PORTABLE"] = "1"
        output = run_session(copied, [str(data_file)], [CTRL_Q], environment)
        require(output, b"2Unwrap", "Portable mode did not skip XDG configuration.")
        environment.pop("HVIEW_PORTABLE")

        invalid_config = root / "invalid.ini"
        invalid_config.write_bytes(
            b"[HView-Linux 1]\nDisassemblySyntax=Unsupported\n"
        )
        output = run_session(
            binary,
            ["--config", str(invalid_config), str(data_file)],
            [],
            expected_code=1,
        )
        require(output, b"Illegal value", "An invalid syntax setting did not fail.")

        macro = root / "quit.mac"
        macro.write_bytes(macro_file(ord("Q"), 2))
        run_session(binary, ["--macro", str(macro), str(data_file)], [])

        recursive = root / "recursive"
        (recursive / "child").mkdir(parents=True)
        (recursive / "a.bin").write_bytes(b"A")
        (recursive / "child" / "b.bin").write_bytes(b"B")
        output = run_session(
            binary,
            ["--recursive", str(recursive / "*.bin")],
            [CTRL_F12, CTRL_Q],
        )
        require(output, b"b.bin", "Recursive file expansion did not include the child file.")

        picker = root / "picker"
        picker.mkdir()
        first = picker / "a-first.bin"
        second = picker / "b-picked.bin"
        first.write_bytes(b"First")
        second.write_bytes(b"Second")
        session = root / "state.sav"
        output = run_session(
            binary,
            ["--session", str(session), str(first)],
            [F9, DOWN, DOWN, b"\r", CTRL_Q],
        )
        require(output, b"b-picked.bin", "The file picker did not open the selected file.")
        if not session.is_file():
            raise AssertionError("The explicit session file was not published.")

        output = run_session(binary, ["--session", str(session)], [CTRL_F11, CTRL_Q])
        require(output, b"a-first.bin", "Previous-file selection did not open the first file.")
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"a-first.bin", "The active file did not survive restart.")

        view_config = root / "view.ini"
        view_config.write_bytes(native_config("Hex"))
        view_session = root / "view.sav"
        run_session(
            binary,
            ["--config", str(view_config), "--session", str(view_session), str(first)],
            [b"\x1b[C", F9, DOWN, DOWN, b"\r", CTRL_F11, CTRL_Q],
        )
        view_payload = view_session.read_bytes()[32:]
        active = int.from_bytes(view_payload[:4], "little")
        final_offset = int.from_bytes(view_payload[384:392], "little")
        if (active, final_offset) != (0, 1):
            raise AssertionError("File switching did not restore the current view offset.")

        saved = bytearray(session.read_bytes())
        if saved[24:28] != b"\0\0\0\0":
            raise AssertionError("The native saved fixture is unexpectedly compressed.")
        payload = saved[32:]
        payload[100000] = 0x53
        saved[32:] = payload
        saved[28:32] = checksum(payload).to_bytes(4, "little")
        session.write_bytes(saved)
        run_session(binary, ["--session", str(session)], [CTRL_Q])
        if session.read_bytes()[32 + 100000] != 0x53:
            raise AssertionError("A session update changed an unknown payload byte.")

        windows_session = Path(__file__).parent / "fixtures" / "offset-10.sav"
        output = run_session(
            binary,
            ["--session", str(windows_session)],
            [],
            expected_code=1,
        )
        require(output, b"Windows syntax", "A Windows session path did not fail clearly.")

        excluded_session = root / "unicode-state.sav"
        output = run_session(
            binary,
            ["--session", str(excluded_session), str(unicode_file)],
            [CTRL_Q],
            expected_code=1,
        )
        require(output, b"260 ASCII bytes", "A Unicode session path did not fail clearly.")
        if excluded_session.exists():
            raise AssertionError("An invalid session was published.")

        backslash_file = root / "name\\part.bin"
        backslash_file.write_bytes(b"Backslash path")
        backslash_session = root / "backslash.sav"
        output = run_session(
            binary,
            ["--session", str(backslash_session), str(backslash_file)],
            [CTRL_Q],
        )
        output = run_session(binary, ["--session", str(backslash_session)], [CTRL_Q])
        require(output, b"name\\part.bin", "A Linux backslash path did not survive restart.")

        first_directory = root / "first-directory"
        second_directory = root / "second-directory"
        first_directory.mkdir()
        second_directory.mkdir()
        (first_directory / "same.bin").write_bytes(b"FIRST DIRECTORY")
        (second_directory / "same.bin").write_bytes(b"SECOND DIRECTORY")
        relative_session = root / "relative.sav"
        old_directory = Path.cwd()
        try:
            os.chdir(first_directory)
            run_session(
                binary,
                ["--session", str(relative_session), "same.bin"],
                [CTRL_Q],
            )
            os.chdir(second_directory)
            output = run_session(binary, ["--session", str(relative_session)], [CTRL_Q])
        finally:
            os.chdir(old_directory)
        require(output, b"FIRST DIRECTORY", "A relative session path opened a different file.")
        if b"SECOND DIRECTORY" in output:
            raise AssertionError("A session used the restart working directory.")

        utf16_file = root / "utf16.bin"
        utf16_file.write_bytes("\N{ZERO WIDTH NO-BREAK SPACE}Text".encode("utf-16-le"))
        utf16_session = root / "utf16.sav"
        output = run_session(
            binary,
            [
                "--mode=hex",
                "--offset=1",
                "--session",
                str(utf16_session),
                str(data_file),
                str(utf16_file),
            ],
            [b"m", b"t\r", CTRL_F12, CTRL_Q],
        )
        if not utf16_session.is_file():
            raise AssertionError("Explicit Hex mode did not initialize the UTF-16 session file.")
        utf16_payload = utf16_session.read_bytes()[32:]
        second_base = 8 + 2814
        active = int.from_bytes(utf16_payload[:4], "little")
        mode = int.from_bytes(utf16_payload[second_base + 2772 : second_base + 2776], "little")
        offset = int.from_bytes(utf16_payload[second_base + 376 : second_base + 384], "little")
        if (active, mode, offset) != (1, 2, 1):
            raise AssertionError("The inactive session record lost its startup mode or offset.")

    print("File workflow probe passed.")


if __name__ == "__main__":
    main()
