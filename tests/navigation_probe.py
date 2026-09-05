#!/usr/bin/env python3
"""Check direct Code navigation through a Linux pseudoterminal."""

from pathlib import Path
import sys
import tempfile

from analysis_probe import pe_fixture, put32
from file_workflow_probe import checksum
from terminal_probe import run_session


BACKSPACE = b"\x7f"
CTRL_Q = b"\x11"
DOWN = b"\x1b[B"
ENTER = b"\r"
ESCAPE = b"\x1b"
F3 = b"\x1b[13~"
F4 = b"\x1b[14~"
F5 = b"\x1b[15~"
F9 = b"\x1b[20~"
UP = b"\x1b[A"


def header(offset: int) -> bytes:
    """Return the selected-offset header."""
    return f"{offset:08X}\N{BOX DRAWINGS LIGHT VERTICAL}HView-Linux".encode()


def pe_header(address: int) -> bytes:
    """Return the selected PE address header."""
    return f".{address:08X}-Linux".encode()


def require(output: bytes, *texts: bytes) -> None:
    """Require each output value."""
    for value in texts:
        if value not in output:
            raise AssertionError(f"The terminal output lacks: {value!r}")


def require_order(output: bytes, *texts: bytes) -> None:
    """Require output values in order."""
    position = 0
    for value in texts:
        position = output.find(value, position)
        if position < 0:
            raise AssertionError(f"The terminal output lacks an ordered value: {value!r}")
        position += len(value)


def after_last(output: bytes, text: bytes) -> bytes:
    """Return output after the final value."""
    position = output.rfind(text)
    if position < 0:
        raise AssertionError(f"The terminal output lacks: {text!r}")
    return output[position:]


def check_direct_branches(binary: Path, root: Path) -> None:
    """Check direct branch types and directions."""
    data = bytearray(b"\x90" * 0x80)
    data[0:3] = b"\xE8\x1D\x00"
    data[3:5] = b"\x75\x1B"
    data[5:7] = b"\xE2\x19"
    data[7:9] = b"\xEB\x17"
    data[0x42:0x44] = b"\xEB\xBC"
    path = root / "direct.bin"
    path.write_bytes(data)

    for source, target, mnemonic in [
        (0, 0x20, b"call"),
        (3, 0x20, b"jne"),
        (5, 0x20, b"loop"),
        (7, 0x20, b"jmp"),
        (0x42, 0, b"jmp"),
    ]:
        output = run_session(
            binary,
            ["--mode=code", "--offset", f"{source:X}", str(path)],
            [ENTER, BACKSPACE, CTRL_Q],
        )
        require(output, mnemonic)
        require_order(output, header(source), header(target), header(source))


def patch_saved_view(path: Path, offset: int, top: int) -> None:
    """Set one native saved view and update its checksum."""
    saved = bytearray(path.read_bytes())
    if saved[24:28] != b"\0\0\0\0":
        raise AssertionError("The navigation session is unexpectedly compressed.")
    payload = bytearray(saved[32:])
    base = 8
    payload[base + 352 : base + 360] = top.to_bytes(8, "little")
    payload[base + 376 : base + 384] = offset.to_bytes(8, "little")
    saved[32:] = payload
    saved[28:32] = checksum(payload).to_bytes(4, "little")
    path.write_bytes(saved)


def check_nested_returns(binary: Path, root: Path) -> None:
    """Check nested returns and restored view position."""
    data = bytearray(b"\x90" * 0x80)
    data[0] = 0xC3
    data[0x20:0x23] = b"\xE8\x1D\x00"
    data[0x40:0x43] = b"\xE8\x1D\x00"
    data[0x60] = 0xC3
    source = root / "nested.bin"
    session = root / "nested.sav"
    source.write_bytes(data)
    run_session(
        binary,
        ["--mode=code", "--session", str(session), str(source)],
        [CTRL_Q],
    )
    patch_saved_view(session, 0x20, 0)

    output = run_session(
        binary,
        ["--session", str(session)],
        [ENTER, ENTER, BACKSPACE, BACKSPACE, CTRL_Q],
    )
    require_order(
        output,
        header(0x20),
        header(0x40),
        header(0x60),
        header(0x40),
        header(0x20),
    )
    require(after_last(output, header(0x20)), b" 00000000: C3")


def check_self_and_history_resets(binary: Path, root: Path) -> None:
    """Check no-op targets and history resets."""
    self_path = root / "self.bin"
    data = bytearray(b"\x90" * 0x20)
    data[0:3] = b"\xE8\x0D\x00"
    data[0x10:0x12] = b"\xEB\xFE"
    self_path.write_bytes(data)
    output = run_session(
        binary,
        ["--mode=code", str(self_path)],
        [ENTER, ENTER, BACKSPACE, BACKSPACE, ENTER, CTRL_Q],
    )
    require_order(output, header(0), header(0x10), header(0x10), header(0))
    require(output, b"The branch return history is empty.")

    output = run_session(
        binary,
        ["--mode=code", str(self_path)],
        [ENTER, b"o", BACKSPACE, ENTER, CTRL_Q],
    )
    require(output, b"The branch return history is empty.")

    step_path = root / "step.bin"
    step_path.write_bytes(b"\xC3" * 0x40)
    output = run_session(
        binary,
        ["--mode=code", str(step_path)],
        [DOWN, F5, b"20", ENTER, UP, CTRL_Q],
    )
    if output.count(header(0x20)) < 2 or header(0) in after_last(output, header(0x20)):
        raise AssertionError("A successful F5 jump kept stale instruction-step history.")


def check_modes_and_changed_buffer(binary: Path, root: Path) -> None:
    """Check mode keys, assembly access, and changed bytes."""
    mode_path = root / "modes.bin"
    mode_path.write_bytes(b"\xE8\x05\x00" + b"\x90" * 13)
    output = run_session(
        binary,
        ["--mode=text", str(mode_path)],
        [
            ENTER,
            b"h\r",
            ENTER,
            b"c\r",
            b"m",
            b"h\r",
            b"m",
            b"c\r",
            F4,
            b"h\r",
            F4,
            b"c\r",
            ENTER,
            BACKSPACE,
            F3,
            ENTER,
            ESCAPE,
            ESCAPE,
            CTRL_Q,
        ],
    )
    if output.count(b"Mode: T Text, H Hex, C Code") < 6:
        raise AssertionError("Text, Hex, M, or F4 did not keep mode selection available.")
    require_order(output, header(0), header(8), header(0))
    require(output, b"Assembler")

    changed = root / "changed.bin"
    changed.write_bytes(b"\xEB\x00" + b"\xC3" * 8)
    output = run_session(
        binary,
        ["--mode=hex", "--offset=1", str(changed)],
        [F3, b"02", F9, ENTER, b"c\r", F5, b"0", ENTER, ENTER, BACKSPACE, CTRL_Q],
    )
    require_order(output, header(0), header(4), header(0))
    if not changed.read_bytes().startswith(b"\xEB\x02"):
        raise AssertionError("The changed direct target bytes were not saved.")


def check_raw_refusals(binary: Path, root: Path) -> None:
    """Check invalid, indirect, far, and outside sources."""
    cases = [
        ("ordinary", b"\x90", b"no direct relative branch or call target"),
        ("indirect", b"\xFF\xD0", b"no direct relative branch or call target"),
        ("far", b"\x9A\x08\x00\x00\x00", b"no direct relative branch or call target"),
        ("invalid", b"\x0F", b"Invalid or incomplete x86 instruction"),
        ("outside", b"\xE8\xFF\x7F", b"branch target is outside the current buffer"),
    ]
    for name, data, message in cases:
        path = root / f"{name}.bin"
        path.write_bytes(data)
        output = run_session(
            binary,
            ["--mode=code", str(path)],
            [ENTER, ENTER, CTRL_Q],
        )
        require(output, message, header(0))

    fallback = root / "fallback.ini"
    fallback.write_bytes(b"[HView-Linux 1]\nStartMode=Code\nInvalidCode=Byte\n")
    invalid = root / "fallback.bin"
    invalid.write_bytes(b"\x0F")
    output = run_session(
        binary,
        ["--config", str(fallback), str(invalid)],
        [ENTER, ENTER, CTRL_Q],
    )
    require(output, b"db 0F", b"Invalid or incomplete x86 instruction", header(0))


def branch32(source: int, target: int) -> bytes:
    """Encode one direct near call displacement."""
    displacement = (target - source - 5) & 0xFFFFFFFF
    return b"\xE8" + displacement.to_bytes(4, "little")


def check_pe_navigation(binary: Path, root: Path) -> None:
    """Check mapped PE navigation and mapping refusals."""
    source_data, base = pe_fixture(False)
    mapped = bytearray(source_data)
    mapped[0x210:0x215] = branch32(base + 0x1010, base + 0x1020)
    mapped[0x220] = 0xC3
    mapped_path = root / "pe-mapped.bin"
    mapped_path.write_bytes(mapped)
    output = run_session(
        binary,
        ["--mode=code", "--offset=210", str(mapped_path)],
        [ENTER, BACKSPACE, CTRL_Q],
    )
    require_order(
        output,
        pe_header(base + 0x1010),
        pe_header(base + 0x1020),
        pe_header(base + 0x1010),
    )
    require(output, b".00401010: E80B000000", b".00401020: C3")

    unsupported = bytearray(mapped)
    unsupported[0x84:0x86] = (0x01C4).to_bytes(2, "little")
    unsupported_path = root / "pe-unsupported-machine.bin"
    unsupported_path.write_bytes(unsupported)
    output = run_session(
        binary,
        ["--mode=code", "--offset=210", str(unsupported_path)],
        [ENTER, ENTER, BACKSPACE, ENTER, CTRL_Q],
    )
    require(
        output,
        b"The PE processor is unsupported for code decoding.",
        b"The branch return history is empty.",
    )
    if pe_header(base + 0x1020) in output:
        raise AssertionError("Follow accepted an unsupported PE processor.")

    overlay = bytearray(source_data)
    overlay[0x800:0x802] = b"\xEB\x00"
    overlay_path = root / "pe-overlay.bin"
    overlay_path.write_bytes(overlay)
    output = run_session(
        binary,
        ["--mode=code", "--offset=800", str(overlay_path)],
        [ENTER, ENTER, CTRL_Q],
    )
    require(output, b"branch source has no virtual address", header(0x800))

    section = 0x98 + 0xE0
    gap_source = bytearray(source_data)
    put32(gap_source, section + 8, 0x300)
    put32(gap_source, section + 16, 0x100)
    put32(gap_source, section + 20, 0x300)
    put32(gap_source, 0x98 + 92, 0)
    gap_source[0x250:0x252] = b"\xEB\x00"
    gap_source_path = root / "pe-gap-source.bin"
    gap_source_path.write_bytes(gap_source)
    output = run_session(
        binary,
        ["--mode=code", "--offset=250", str(gap_source_path)],
        [ENTER, ENTER, CTRL_Q],
    )
    require(output, b"branch source has no virtual address", pe_header(base + 0x1050))

    virtual_target = bytearray(source_data)
    put32(virtual_target, section + 8, 0x300)
    put32(virtual_target, section + 16, 0x100)
    put32(virtual_target, 0x98 + 92, 0)
    virtual_target[0x200:0x205] = branch32(base + 0x1000, base + 0x1200)
    virtual_path = root / "pe-virtual-target.bin"
    virtual_path.write_bytes(virtual_target)
    output = run_session(
        binary,
        ["--mode=code", "--offset=200", str(virtual_path)],
        [ENTER, ENTER, CTRL_Q],
    )
    require(output, b"branch target has no file byte", pe_header(base + 0x1000))

    gap_target = bytearray(source_data)
    gap_target[0x200:0x205] = branch32(base + 0x1000, base + 0x800)
    gap_path = root / "pe-gap-target.bin"
    gap_path.write_bytes(gap_target)
    output = run_session(
        binary,
        ["--mode=code", "--offset=200", str(gap_path)],
        [ENTER, ENTER, CTRL_Q],
    )
    require(output, b"outside the PE image", pe_header(base + 0x1000))


def syntax_config(path: Path, syntax: str, bits: int = 16) -> None:
    """Write one native Code configuration."""
    path.write_text(
        f"[HView-Linux 1]\nStartMode=Code\nDefaultCodeSize={bits}\nDisassemblySyntax={syntax}\n"
    )


def check_syntax_and_real16(binary: Path, root: Path) -> None:
    """Check Intel, AT&T, and Real16 targets."""
    call = root / "syntax-call.bin"
    data = bytearray(b"\x90" * 0x20)
    data[0:5] = branch32(0, 0x10)
    call.write_bytes(data)

    boundary = root / "real16-boundary.bin"
    data = bytearray(b"\x90" * 0x10002)
    data[0xFFFE:0x10000] = b"\xEB\x00"
    data[0x10000:0x10002] = b"\xEB\xFE"
    boundary.write_bytes(data)

    for syntax in ("Intel", "ATT"):
        config32 = root / f"{syntax.lower()}-32.ini"
        syntax_config(config32, syntax, 32)
        output = run_session(
            binary,
            ["--config", str(config32), str(call)],
            [ENTER, BACKSPACE, CTRL_Q],
        )
        require(output, b"0x10")
        require_order(output, header(0), header(0x10), header(0))

        config16 = root / f"{syntax.lower()}-16.ini"
        syntax_config(config16, syntax)
        output = run_session(
            binary,
            ["--config", str(config16), "--offset=FFFE", str(boundary)],
            [ENTER, ENTER, BACKSPACE, CTRL_Q],
        )
        require(output, b"0x10000")
        require_order(
            output,
            header(0xFFFE),
            header(0x10000),
            header(0x10000),
            header(0xFFFE),
        )

        for start in (0xFFFE, 0x10000):
            output = run_session(
                binary,
                ["--config", str(config16), f"--offset={start:X}", str(boundary)],
                [b"o", b"o", b"o", ENTER, BACKSPACE, CTRL_Q],
            )
            position = output.find(b"Real16")
            if position < 0:
                raise AssertionError("Code mode did not select Real16.")
            real = output[position:]
            require(real, b"0x0")
            require_order(real, header(start), header(0), header(start))


def main() -> None:
    """Run the direct navigation checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: navigation_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-navigation-") as temporary:
        root = Path(temporary)
        check_direct_branches(binary, root)
        check_nested_returns(binary, root)
        check_self_and_history_resets(binary, root)
        check_modes_and_changed_buffer(binary, root)
        check_raw_refusals(binary, root)
        check_pe_navigation(binary, root)
        check_syntax_and_real16(binary, root)
    print("Navigation probe passed.")


if __name__ == "__main__":
    main()
