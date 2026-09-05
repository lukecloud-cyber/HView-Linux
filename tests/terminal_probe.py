#!/usr/bin/env python3
"""Check HView-Linux through a Linux pseudoterminal."""

import fcntl
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from collections.abc import Callable


def set_size(fd: int, columns: int, rows: int) -> None:
    """Set the pseudoterminal size."""
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def drain(fd: int, output: bytearray, wait: float = 0.08) -> None:
    """Read available terminal output for a bounded time."""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], min(0.02, end - time.monotonic()))
        if not ready:
            continue
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            return


def run_session(
    binary: Path,
    arguments: list[str],
    actions: list[
        bytes
        | tuple[int, int]
        | tuple[int, int, bytes]
        | list[bytes]
        | Callable[[], None]
    ],
    environment: dict[str, str] | None = None,
    expected_code: int = 0,
) -> bytes:
    """Run one terminal session and return its output."""
    master, slave = pty.openpty()
    set_size(slave, 80, 24)
    before = termios.tcgetattr(slave)
    process = subprocess.Popen(
        [str(binary), *arguments],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=environment,
    )
    output = bytearray()
    try:
        drain(master, output, 0.15)
        for action in actions:
            if callable(action):
                action()
            elif isinstance(action, tuple):
                start = len(output)
                set_size(slave, action[0], action[1])
                if len(action) == 3:
                    drain(master, output, 0.25)
                    if action[2] not in output[start:]:
                        raise AssertionError("An idle resize did not redraw the terminal.")
                    continue
            elif isinstance(action, list):
                for fragment in action:
                    os.write(master, fragment)
                    time.sleep(0.005)
            else:
                os.write(master, action)
            drain(master, output)
        end = time.monotonic() + 3
        while process.poll() is None and time.monotonic() < end:
            drain(master, output)
        if process.poll() is None:
            process.kill()
            raise AssertionError(f"The terminal session did not stop: {arguments!r}")
        drain(master, output)
        if process.returncode != expected_code:
            raise AssertionError(
                f"The terminal session returned {process.returncode}: {output[-1000:]!r}"
            )
        after = termios.tcgetattr(slave)
        if after != before:
            raise AssertionError("The application did not restore the terminal settings.")
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
        os.close(slave)


def main() -> None:
    """Run the terminal checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: terminal_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")
    with tempfile.TemporaryDirectory(prefix="hview-terminal-") as temporary:
        root = Path(temporary)
        unsafe_name = "name\x1b[31m中.bin"
        text_file = root / unsafe_name
        text_file.write_bytes(b"Alpha\r\nBeta")
        output = run_session(
            binary,
            [str(text_file)],
            [
                b"prx",
                b"\x1bOP",
                (20, 5, b"\x1b[5;1H"),
                b"z",
                b"\r",
                b"\r",
                (12, 3),
                b"H\r",
                b"\x11",
            ],
        )
        if b"\x1b[31m" in output:
            raise AssertionError("A file name emitted a terminal escape sequence.")
        if "中".encode() in output or b"\\u{4E2D}" not in output:
            raise AssertionError("A wide file name did not use safe escaped rendering.")
        if b"Enter Open" in output:
            raise AssertionError("A lowercase key invoked the file selector.")
        for key in [b"p", b"r", b"x"]:
            run_session(binary, [str(text_file)], [key, b"\x11"])

        edit_file = root / "edit.bin"
        edit_file.write_bytes(b"\x00")
        run_session(
            binary,
            ["/Oh=0", str(edit_file)],
            [
                b"\x1b[13~",
                b"\x1b[3~",
                b"\x01\x03\x06",
                b"a",
                b"\x1b[20~",
                b"\x11",
            ],
        )
        if edit_file.read_bytes() != b"\xa0":
            raise AssertionError("The Delete sequence canceled or changed the hex edit.")

        save_as = root / "copy.bin"
        run_session(
            binary,
            [str(text_file)],
            [b"\x13", b"\x01\x03\x06", str(save_as).encode(), b"\r", b"\x11"],
        )
        if save_as.read_bytes() != text_file.read_bytes():
            raise AssertionError("Ctrl+S did not save the current bytes.")

        search_output = run_session(
            binary,
            ["/Oh=0", str(text_file)],
            [[b"\x1b[", b"18;2", b"~"], b"\x1b", b"\x11"],
        )
        if b"Press F7" not in search_output:
            raise AssertionError("The modified F7 sequence did not reach the search action.")

        code_file = root / "code.bin"
        code_file.write_bytes(b"\x90\xc3")
        code_output = run_session(binary, ["/Oc=0", str(code_file)], [b"\x11"])
        if b"nop" not in code_output:
            raise AssertionError("Code mode did not decode the native fixture.")

        att_file = root / "att.ini"
        att_file.write_bytes(
            b"[HViewIni 5.03]\r\nDisassemblySyntax=ATT\r\nDefaultCodeSize=32\r\n"
        )
        att_code = root / "att.bin"
        att_code.write_bytes(b"\x89\xd8")
        att_output = run_session(
            binary,
            [f"/INI={att_file}", "/Oc=0", str(att_code)],
            [b"\x11"],
        )
        if b"%ebx" not in att_output or b"%eax" not in att_output:
            raise AssertionError("AT&T configuration did not change the Code display.")

        created_file = root / "created.bin"
        run_session(
            binary,
            [str(created_file)],
            [(30, 4, b"\x1b[4;1H"), b"c", b"\x11"],
        )
        if not created_file.is_file():
            raise AssertionError("A resize dismissed the file creation question.")

        tool_output = run_session(
            binary,
            [str(text_file)],
            [b"\x14", (30, 5, b"\x1b[5;1H"), b"i", b"\x1b", b"\x11"],
        )
        if b"Integers at cursor" not in tool_output:
            raise AssertionError("A resize dismissed the analysis menu.")

        empty_file = root / "empty.bin"
        empty_file.touch()
        run_session(binary, [str(empty_file)], [b"\x11"])
        error_output = run_session(binary, ["/?"], [], expected_code=1)
        if b"hview-linux" not in error_output:
            raise AssertionError("The invalid option did not report command usage.")

        portable = root / "portable"
        portable.mkdir()
        portable_binary = portable / "hview-linux"
        shutil.copy2(binary, portable_binary)
        portable_environment = os.environ.copy()
        portable_environment["HVIEW_PORTABLE"] = "1"
        for mode in [[], ["/Oh=0"]]:
            output = run_session(
                portable_binary,
                [*mode, str(text_file)],
                [b"\x11"],
                portable_environment,
            )
            if b"libcapstone" in output or b"libkeystone" in output:
                raise AssertionError("Text or Hex mode tried to load a native engine.")
        missing_output = run_session(
            portable_binary,
            ["/Oc=0", str(code_file)],
            [b"\x11"],
            portable_environment,
        )
        if b"libcapstone" not in missing_output:
            raise AssertionError("Code mode did not report the missing decoder.")
    print("Terminal probe passed.")


if __name__ == "__main__":
    main()
