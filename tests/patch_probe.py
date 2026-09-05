#!/usr/bin/env python3
"""Check nonmutating assembly patch previews."""

from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


CTRL_Q = b"\x11"
CTRL_T = b"\x14"
ENTER = b"\r"
ESCAPE = b"\x1b"
F2 = b"\x1b[12~"
F3 = b"\x1b[13~"
F9 = b"\x1b[20~"
RIGHT = b"\x1b[C"


def require(output: bytes, *values: bytes) -> None:
    """Require each terminal value."""
    for value in values:
        if value not in output:
            raise AssertionError(f"The terminal output lacks: {value!r}")


def require_bytes(path: Path, expected: bytes, reason: str) -> None:
    """Require exact file bytes."""
    if path.read_bytes() != expected:
        raise AssertionError(reason)


def raw_model(value: str) -> list[bytes]:
    """Return actions that set one raw model."""
    return [CTRL_T, b"r", value.encode(), ENTER]


def check_overlap_and_resize(binary: Path, root: Path, config: Path) -> None:
    """Check longer overlap, cancellation, and live resize."""
    path = root / "overlap.bin"
    original = bytes.fromhex("90 BB 02 00 00 00 C3")
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(path)],
        [
            (60, 24, b"\x1b[24;1H"),
            F3,
            F2,
            b"mov eax,1\r",
            (30, 5),
            ENTER,
            (60, 24, b"Assembly patch preview"),
            ESCAPE,
            F9,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Assembly patch preview",
        b"File offset: 00000000",
        b"Runtime address: 0000000000000000",
        b"Original bytes (5): 90 BB 02 00 00",
        b"Replacement bytes (5): B8 01 00 00 00",
        b"Replacement length delta: +4 bytes",
        b"File growth: +0",
        b"Partial overlap:",
        b"retains 1",
        b"byte(s).",
        b"Resize to at least 60 columns",
        b"Esc Cancel  Resize to apply",
        b"Original affected instructions",
        b"Proposed instructions",
        b"F:1 mov ebx",
        b"F:0 mov eax",
        b"Enter Apply  Esc Cancel",
    )
    require_bytes(path, original, "A canceled longer preview changed the file.")


def check_shorter_apply(binary: Path, root: Path, config: Path) -> None:
    """Check a shorter patch and its retained tail."""
    path = root / "shorter.bin"
    original = bytes.fromhex("B8 44 33 22 11 C3")
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(path)],
        [
            F3,
            F2,
            b"nop\r",
            ENTER,
            lambda: require_bytes(
                path,
                original,
                "An applied preview changed the file before F9.",
            ),
            ESCAPE,
            F9,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Original bytes (5): B8 44 33 22 11",
        b"Replacement bytes (1): 90",
        b"Replacement length delta: -4 bytes",
        b"File growth: +0 bytes",
        b"Shorter replacement:",
        b"retained tail byte(s)",
        b"F:0 nop",
    )
    require_bytes(
        path,
        bytes.fromhex("90 44 33 22 11 C3"),
        "F9 did not save the exact shorter patch and retained tail.",
    )


def check_eof_growth(binary: Path, root: Path, config: Path) -> None:
    """Check an applied patch at the end of the file."""
    path = root / "eof.bin"
    original = b"\x90"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(path)],
        [
            RIGHT,
            F3,
            F2,
            b"ret\r",
            ENTER,
            lambda: require_bytes(
                path,
                original,
                "EOF growth changed the file before F9.",
            ),
            ESCAPE,
            F9,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"File offset: 00000001",
        b"Runtime address: 0000000000000001",
        b"Original bytes (0): <end of file>",
        b"Replacement bytes (1): C3",
        b"Replacement length delta: n/a",
        b"File growth: +1 bytes",
        b"EOF growth: 1 byte(s) will be appended.",
        b"F:1 ret",
    )
    require_bytes(path, b"\x90\xC3", "F9 did not save the EOF growth.")


def check_raw_runtime_address(binary: Path, root: Path) -> None:
    """Check address-aware assembly with a raw runtime base."""
    path = root / "raw.bin"
    original = b"\x90" * 5 + b"\xC3"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 32 LE 10000000"),
            F3,
            F2,
            b"call 10000008\r",
            ESCAPE,
            F9,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Runtime address: 0000000010000000",
        b"Replacement bytes (5): E8 03 00 00 00",
        b"F:0 nop A:10000000",
        b"F:0 call 0x10000008 A:10000000",
    )
    require_bytes(path, original, "A canceled raw-address preview changed the file.")


def check_att_display(binary: Path, root: Path) -> None:
    """Check Intel assembly input with AT&T display rows."""
    config = root / "att.ini"
    config.write_bytes(
        b"[HView-Linux 1]\nDefaultCodeSize=32\nDisassemblySyntax=ATT\n"
    )
    path = root / "att.bin"
    original = bytes.fromhex("89 D8 C3")
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(path)],
        [F3, F2, b"mov eax,1\r", ESCAPE, F9, CTRL_Q],
    )
    require(
        output,
        b"%ebx, %eax",
        b"eax, ebx",
        b"Replacement bytes (5): B8 01 00 00 00",
        b"$1, %eax",
    )
    require_bytes(path, original, "A canceled AT&T preview changed the file.")


def check_real16_and_fallback(binary: Path, root: Path) -> None:
    """Check Real16 preview decoding and strict replacement decoding."""
    config = root / "fallback.ini"
    config.write_bytes(
        b"[HView-Linux 1]\nDefaultCodeSize=16\nInvalidCode=Byte\n"
    )
    real = root / "real16.bin"
    original = bytes.fromhex("B8 34 12 C3")
    real.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(real)],
        [b"o", b"o", b"o", F3, F2, b"mov ax,5678\r", ESCAPE, F9, CTRL_Q],
    )
    require(
        output,
        b"Real16",
        b"Original bytes (3): B8 34 12",
        b"Replacement bytes (3): B8 78 56",
        b"F:0 mov ax, 0x1234",
        b"F:0 mov ax, 0x5678",
    )
    require_bytes(real, original, "A canceled Real16 preview changed the file.")

    invalid = root / "invalid.bin"
    invalid.write_bytes(b"\x0F")
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(invalid)],
        [F3, F2, b"nop\r", ESCAPE, F9, CTRL_Q],
    )
    require(
        output,
        b"Original bytes (1): 0F",
        b"Replacement bytes (1): 90",
        b"F:0 db 0F",
        b"F:0 nop",
    )
    require_bytes(invalid, b"\x0F", "A fallback preview changed the file.")

    protected = root / "protected.bin"
    protected.write_bytes(b"\x90")
    output = run_session(
        binary,
        ["--config", str(config), "--mode=code", str(protected)],
        [
            b"o",
            b"o",
            b"o",
            F3,
            F2,
            b"arpl ax, ax\r",
            ENTER,
            ESCAPE,
            F9,
            CTRL_Q,
        ],
    )
    require(output, b"Cannot verify the replacement instruction")
    if b"Assembly patch preview" in output:
        raise AssertionError("Invalid Real16 replacement bytes reached the preview.")
    require_bytes(
        protected,
        b"\x90",
        "Invalid Real16 replacement bytes changed the file.",
    )


def main() -> None:
    """Run the assembly patch preview checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: patch_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-patch-") as temporary:
        root = Path(temporary)
        config = root / "intel32.ini"
        config.write_bytes(b"[HView-Linux 1]\nDefaultCodeSize=32\n")
        check_overlap_and_resize(binary, root, config)
        check_shorter_apply(binary, root, config)
        check_eof_growth(binary, root, config)
        check_raw_runtime_address(binary, root)
        check_att_display(binary, root)
        check_real16_and_fallback(binary, root)
    print("Assembly patch preview probe passed.")


if __name__ == "__main__":
    main()
