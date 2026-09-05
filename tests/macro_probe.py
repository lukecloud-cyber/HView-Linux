#!/usr/bin/env python3
"""Check macros and Linux key aliases through a pseudoterminal."""

from pathlib import Path
import sys
import tempfile
import time

from terminal_probe import run_session


CTRL_Q = b"\x11"
ENTER = b"\r"
ESCAPE = b"\x1b"
F3 = b"\x1b[13~"
F9 = b"\x1b[20~"
RIGHT = 0xFF4D
F7 = 0xFF41
ALT_F7 = 0xFF5A
CTRL_F7 = 0xFF64
SHIFT_F7 = 0xFF6E


def macro_file(
    events: list[tuple[int, int]],
    *,
    delay_ms: int = 0,
    repeat: bool = False,
    stop_on_notice: bool = False,
    legacy: bool = False,
) -> bytes:
    """Make one macro fixture."""
    data = bytearray(69)
    data[:10] = b"HiewMacro\0" if legacy else b"HViewMacro"
    data[14:16] = (0x9006).to_bytes(2, "little")
    data[16:18] = len(events).to_bytes(2, "little")
    data[18:22] = delay_ms.to_bytes(4, "little")
    data[22] = int(stop_on_notice) | (int(repeat) << 1)
    for modifiers, key in events:
        data.append(modifiers)
        data.extend(key.to_bytes(4, "little"))
    return bytes(data)


def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


def header(offset: int) -> bytes:
    """Make the selected-offset header text."""
    return f"{offset:08X}\N{BOX DRAWINGS LIGHT VERTICAL}HView-Linux".encode()


def main() -> None:
    """Run the macro and alias checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: macro_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-macro-") as temporary:
        root = Path(temporary)
        data_file = root / "data.bin"
        data_file.write_bytes(bytes(range(64)))

        current = root / "current.mac"
        current.write_bytes(macro_file([(0, RIGHT), (0, RIGHT), (2, ord("Q"))]))
        output = run_session(
            binary,
            ["--mode=hex", "--macro", str(current), str(data_file)],
            [],
        )
        require(
            output,
            header(2),
            "The current macro did not move to byte 2 before Ctrl+Q stopped playback.",
        )

        legacy = root / "legacy.mac"
        legacy.write_bytes(
            macro_file(
                [(0, RIGHT), (0, RIGHT), (0, RIGHT), (2, ord("Q"))],
                legacy=True,
            )
        )
        output = run_session(
            binary,
            ["--mode=hex", f"/MACRO0={legacy}", str(data_file)],
            [],
        )
        require(
            output,
            header(3),
            "The legacy option and signature did not move to byte 3.",
        )

        repeat_file = root / "repeat.mac"
        repeat_file.write_bytes(macro_file([(0, RIGHT)], delay_ms=5, repeat=True))
        repeat_data = root / "repeat.bin"
        repeat_data.write_bytes(bytes(range(8)))
        output = run_session(
            binary,
            ["--mode=hex", "--macro", str(repeat_file), str(repeat_data)],
            [ESCAPE],
        )
        require(
            output,
            header(7),
            "The repeating macro did not reach the final byte before cancellation.",
        )

        modifier_file = root / "modifiers.mac"
        modifier_file.write_bytes(
            macro_file(
                [
                    (2, CTRL_F7),
                    (0, ord("x")),
                    (4, ALT_F7),
                    (0, ord("x")),
                    (1, SHIFT_F7),
                ]
            )
        )
        output = run_session(
            binary,
            ["--macro", str(modifier_file), str(data_file)],
            [ESCAPE, CTRL_Q],
        )
        repeat_notice = b"Press F7 to enter a search pattern first."
        if output.count(repeat_notice) != 2:
            raise AssertionError("The Ctrl and Alt macro modifiers did not run F7 repeat.")
        require(
            output,
            b"ASCII: _",
            "The Shift macro modifier did not run the F7 search prompt.",
        )

        notice_file = root / "notice.mac"
        notice_file.write_bytes(
            macro_file([(0, F7), (0, 0)], repeat=True, stop_on_notice=True)
        )
        output = run_session(
            binary,
            ["--macro", str(notice_file), str(data_file)],
            [b"Z", ENTER, b"x", CTRL_Q],
        )
        if output.count(b"[ Not found ]") != 1:
            raise AssertionError("The stop-on-notice macro did not stop after one notice.")

        delay_file = root / "delay.mac"
        delay_file.write_bytes(macro_file([(0, RIGHT)], delay_ms=0xFFFFFFFF))
        start = time.monotonic()
        output = run_session(
            binary,
            [
                "--mode=text",
                "--offset=FF",
                "--macro",
                str(delay_file),
                str(data_file),
            ],
            [b"mh\r", ESCAPE, CTRL_Q],
        )
        if time.monotonic() - start >= 2:
            raise AssertionError("Escape did not cancel the maximum macro delay promptly.")
        require(output, b"[ Jump out of file ]", "The startup notice did not open.")
        require(
            output,
            b"Mode: T Text, H Hex, C Code",
            "The delay cancellation did not preserve the queued M key.",
        )
        require(
            output,
            b"00000000:",
            "The mode prompt did not use the queued H and Enter keys.",
        )

        # Linux terminals send the same carriage-return byte for Ctrl+M and Enter.
        output = run_session(
            binary,
            ["--mode=text", str(data_file)],
            [ENTER, b"h\r", CTRL_Q],
        )
        require(
            output,
            b"Mode: T Text, H Hex, C Code",
            "Ctrl+M and Enter did not open the mode prompt.",
        )
        require(output, b"00000000:", "The prompt did not interpret H as prompt text.")

        output = run_session(
            binary,
            ["--mode=hex", "--offset=20", str(data_file)],
            [b"h", b"k", b"l", b"j", CTRL_Q],
        )
        position = 0
        for offset in [0x1F, 0x0F, 0x10, 0x20]:
            position = output.find(header(offset), position)
            if position < 0:
                raise AssertionError("The H, K, L, and J aliases did not move in order.")
            position += 1

        code_config = root / "code.ini"
        code_config.write_bytes(b"[HView-Linux 1]\nDefaultCodeSize=16\n")
        code_file = root / "code.bin"
        code_file.write_bytes(b"\x90\xc3")
        output = run_session(
            binary,
            [
                "--config",
                str(code_config),
                "--mode=code",
                str(code_file),
            ],
            [b"o", CTRL_Q],
        )
        require(output, b"a32", "The O alias did not select 32-bit Code mode.")

        edit_file = root / "edit.bin"
        edit_file.write_bytes(b"\0")
        run_session(
            binary,
            ["--mode=hex", str(edit_file)],
            [F3, b"mohjkl", b"a", F9, CTRL_Q],
        )
        if edit_file.read_bytes() != b"\xA0":
            raise AssertionError("Normal-mode aliases changed the hexadecimal edit workflow.")

    print("Macro probe passed.")


if __name__ == "__main__":
    main()
