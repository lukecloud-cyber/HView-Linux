#!/usr/bin/env python3
"""Check the transient raw address model through a Linux pseudoterminal."""

from pathlib import Path
import sys
import tempfile

from analysis_probe import pe_fixture
from terminal_probe import run_session


BACKSPACE = b"\x7f"
CTRL_F11 = b"\x1b[23;5~"
CTRL_F12 = b"\x1b[24;5~"
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_T = b"\x14"
ENTER = b"\r"
ESCAPE = b"\x1b"
F2 = b"\x1b[12~"
F3 = b"\x1b[13~"
F5 = b"\x1b[15~"


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


def last_header(output: bytes, name: str) -> bytes:
    """Return the final header for one file."""
    position = output.rfind(name.encode())
    if position < 0:
        raise AssertionError(f"The terminal output lacks the file name: {name}")
    start = output.rfind(b"\x1b[1;1H", 0, position)
    end = output.find(b"\x1b[2;1H", position)
    if start < 0 or end < 0:
        raise AssertionError("The terminal output lacks a complete header.")
    return output[start:end]


def raw_header(address: int) -> bytes:
    """Return one raw Code address header."""
    digits = f"{address:08X}"
    suffix = "-Linux"[max(0, len(digits) - 8) :]
    return f".{digits}{suffix}".encode()


def raw_model(value: str | None) -> list[bytes]:
    """Return actions that open the raw model prompt."""
    actions = [CTRL_T, b"r"]
    if value is None:
        return [*actions, ESCAPE]
    return [*actions, value.encode(), ENTER]


def address(value: str) -> list[bytes]:
    """Return actions that open the address tool."""
    return [CTRL_T, b"a", value.encode(), ENTER]


def dismissing_raw_model(value: str) -> list[bytes]:
    """Return actions that submit and dismiss an invalid raw model."""
    return [*raw_model(value), ENTER]


def check_addresses_and_byte_order(binary: Path, root: Path) -> None:
    """Check raw address conversion and selected integer byte order."""
    path = root / "address.bin"
    path.write_bytes(bytes(range(1, 17)))
    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 32 LE 10000000"),
            F5,
            b"8",
            ENTER,
            *address("F 8"),
            ESCAPE,
            *address("V 10000008"),
            ESCAPE,
            *address("R 8"),
            ENTER,
            CTRL_T,
            b"i",
            ESCAPE,
            *raw_model("X86 32 BE 10000000"),
            CTRL_T,
            b"i",
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"RAW address | current buffer",
        b"File=00000008 RVA=- VA=0000000010000008",
        b"Raw address mode has no RVA.",
        raw_header(0x10000008),
    )
    little = output.find(b"Integers at cursor")
    big = output.rfind(b"Integers at cursor")
    if little < 0 or big <= little:
        raise AssertionError("The integer tool did not open for both byte orders.")
    if b"16-bit LE: unsigned 2569" not in output[little:big]:
        raise AssertionError("The little-endian raw model did not select little-endian integers.")
    if b"16-bit BE:" in output[little:big]:
        raise AssertionError("The little-endian raw model showed big-endian integer rows.")
    if b"16-bit BE: unsigned 2314" not in output[big:]:
        raise AssertionError("The big-endian raw model did not select big-endian integers.")
    if b"16-bit LE:" in output[big:]:
        raise AssertionError("The big-endian raw model showed little-endian integer rows.")


def check_decode_and_assembly(binary: Path, root: Path) -> None:
    """Check raw decoding and Intel assembly addresses."""
    config = root / "att.ini"
    config.write_bytes(b"[HView-Linux 1]\nStartMode=Code\nDisassemblySyntax=ATT\n")
    path = root / "assembly.bin"
    original = b"\x89\xD8" + b"\x90" * 6 + b"\xC3"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--config", str(config), str(path)],
        [
            *raw_model("X86 32 LE 1000"),
            F3,
            F2,
            b"call 1008",
            ENTER,
            ESCAPE,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"%ebx",
        b"%eax",
        b"eax, ebx",
        b".00001000: E803000000",
        raw_header(0x1000),
    )
    if path.read_bytes() != original:
        raise AssertionError("A canceled raw assembly edit changed the file.")


def check_atomic_failures_and_growth(binary: Path, root: Path) -> None:
    """Check strict input, address bounds, and checked buffer growth."""
    path = root / "atomic.bin"
    original = b"\x90\xC3"
    path.write_bytes(original)
    output = run_session(
        binary,
        ["--mode=code", "--offset=1", str(path)],
        [
            *raw_model("X86 32 LE 1000"),
            *dismissing_raw_model("X86 32 LE 1000 junk"),
            *dismissing_raw_model("X86 16 LE FFFFFFFF"),
            *dismissing_raw_model("X86 32 LE 100000000"),
            *dismissing_raw_model("X86 64 LE 10000000000000000"),
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Enter AUTO or X86 16|32|64 LE|BE HEXBASE.",
        b"32-bit linear address range",
        b"64-bit address range",
    )
    header = last_header(output, path.name)
    require(header, b"RAW", b"a32", raw_header(0x1001))
    if path.read_bytes() != original:
        raise AssertionError("A rejected raw model changed the file.")

    empty = root / "empty.bin"
    empty.touch()
    output = run_session(
        binary,
        ["--mode=hex", str(empty)],
        [
            *raw_model("X86 64 BE FFFFFFFFFFFFFFFF"),
            F3,
            b"AA",
            b"B",
            ENTER,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(output, b"RAW", b"64-bit address range", b"AA")
    if empty.read_bytes():
        raise AssertionError("A canceled boundary edit changed the empty file.")


def check_history_and_width_cycle(binary: Path, root: Path) -> None:
    """Check raw history rules and width cycling."""
    path = root / "history.bin"
    data = bytearray(b"\x90" * 16)
    data[0:5] = b"\xE8\x03\x00\x00\x00"
    data[8] = 0xC3
    path.write_bytes(data)
    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 32 LE 1000"),
            ENTER,
            *dismissing_raw_model("X86 32 LE 1000 junk"),
            *raw_model("X86 32 BE 1000"),
            BACKSPACE,
            ENTER,
            *raw_model("X86 64 BE 1000"),
            BACKSPACE,
            ENTER,
            F5,
            b"0",
            ENTER,
            ENTER,
            *raw_model("X86 64 BE 2000"),
            BACKSPACE,
            ENTER,
            CTRL_Q,
        ],
    )
    require_order(
        output,
        raw_header(0x1000),
        raw_header(0x1008),
        raw_header(0x1000),
        raw_header(0x1008),
    )
    require(output, b"call", b"0x1008")
    if output.count(b"The branch return history is empty.") < 2:
        raise AssertionError("A raw base or width change kept branch-return history.")

    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 16 BE 1000"),
            b"o",
            b"o",
            b"o",
            CTRL_T,
            b"i",
            ESCAPE,
            CTRL_Q,
        ],
    )
    require_order(output, b"a16", b"a32", b"a64", b"a16")
    if output.count(raw_header(0x1000)) < 4:
        raise AssertionError("Raw width cycling changed the runtime base.")
    integers = output[output.rfind(b"Integers at cursor") :]
    if b"16-bit BE:" not in integers or b"16-bit LE:" in integers:
        raise AssertionError("Raw width cycling changed the selected byte order.")

    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 64 LE 100000000"),
            ENTER,
            b"o",
            ENTER,
            BACKSPACE,
            ENTER,
            BACKSPACE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"32-bit linear address range",
        raw_header(0x100000000),
        raw_header(0x100000008),
    )
    error = output.find(b"32-bit linear address range")
    if error < 0:
        raise AssertionError("A rejected raw narrowing did not report its address limit.")
    require_order(
        output[error:],
        raw_header(0x100000008),
        raw_header(0x100000000),
        raw_header(0x100000008),
        raw_header(0x100000000),
    )
    if last_header(output, path.name).find(raw_header(0x100000000)) < 0:
        raise AssertionError("A rejected raw width change lost branch-return history.")


def check_transient_lifetime(binary: Path, root: Path) -> None:
    """Check raw state across rebuilds, files, and restarts."""
    source = root / "source.bin"
    copy = root / "copy.bin"
    source.write_bytes(b"\x90\xC3")
    output = run_session(
        binary,
        ["--mode=code", str(source)],
        [
            *raw_model("X86 32 LE 1000"),
            b"m",
            b"h",
            ENTER,
            F3,
            b"FF",
            ESCAPE,
            CTRL_S,
            ESCAPE,
            CTRL_S,
            str(copy).encode(),
            ENTER,
            CTRL_Q,
        ],
    )
    require(last_header(output, copy.name), b"RAW")
    if source.read_bytes() != b"\x90\xC3" or copy.read_bytes() != b"\x90\xC3":
        raise AssertionError("Mode changes, cancellation, or Save As changed the bytes.")

    output = run_session(binary, ["--mode=code", str(copy)], [CTRL_Q])
    if b"RAW" in last_header(output, copy.name):
        raise AssertionError("A raw model survived an application restart.")

    first = root / "first.bin"
    second = root / "second.bin"
    first.write_bytes(b"\x90")
    second.write_bytes(b"\xC3")
    output = run_session(
        binary,
        ["--mode=code", str(first), str(second)],
        [*raw_model("X86 32 LE 1000"), CTRL_F12, CTRL_F11, CTRL_Q],
    )
    if b"RAW" in last_header(output, first.name):
        raise AssertionError("A raw model survived a file switch.")
    require(output, second.name.encode())


def check_auto_pe_and_session(binary: Path, root: Path) -> None:
    """Check AUTO restoration for PE, configuration, and sessions."""
    pe_path = root / "pe.bin"
    pe_data, base = pe_fixture(False)
    pe_path.write_bytes(pe_data)
    output = run_session(
        binary,
        ["--mode=code", str(pe_path)],
        [
            *raw_model("X86 32 LE 50000000"),
            *address("F 0"),
            ESCAPE,
            *raw_model("AUTO"),
            CTRL_Q,
        ],
    )
    require_order(output, raw_header(base), raw_header(0x50000000), raw_header(base))
    require(output, b"File=00000000 RVA=- VA=0000000050000000")
    final = last_header(output, pe_path.name)
    if b"RAW" in final or b"PE" not in final or b"a32" not in final:
        raise AssertionError("AUTO did not restore PE mapping and width.")

    config = root / "width.ini"
    config.write_bytes(b"[HView-Linux 1]\nStartMode=Code\nDefaultCodeSize=64\n")
    raw = root / "raw.bin"
    raw.write_bytes(b"\x90")
    output = run_session(
        binary,
        ["--config", str(config), str(raw)],
        [*raw_model("X86 16 LE 1000"), *raw_model("AUTO"), CTRL_Q],
    )
    final = last_header(output, raw.name)
    if b"RAW" in final or b"a64" not in final:
        raise AssertionError("AUTO did not restore the configured code width.")

    session = root / "real16.sav"
    output = run_session(
        binary,
        ["--session", str(session), "--mode=code", str(raw)],
        [
            b"o",
            b"o",
            b"o",
            *raw_model("X86 32 LE 1000"),
            *raw_model("AUTO"),
            *raw_model("X86 32 LE 1000"),
            CTRL_Q,
        ],
    )
    require_order(
        output,
        b"Real16",
        raw_header(0x1000),
        b"Real16",
        raw_header(0x1000),
    )
    final = last_header(output, raw.name)
    if b"RAW" not in final or b"a32" not in final or b"Real16" in final:
        raise AssertionError("An explicit raw model did not hide Real16.")
    output = run_session(binary, ["--session", str(session)], [CTRL_Q])
    final = last_header(output, raw.name)
    if b"RAW" in final or b"Real16" not in final:
        raise AssertionError("The session stored the transient raw model instead of Real16.")


def main() -> None:
    """Run the raw model checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: raw_model_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-raw-model-") as temporary:
        root = Path(temporary)
        check_addresses_and_byte_order(binary, root)
        check_decode_and_assembly(binary, root)
        check_atomic_failures_and_growth(binary, root)
        check_history_and_width_cycle(binary, root)
        check_transient_lifetime(binary, root)
        check_auto_pe_and_session(binary, root)
    print("Raw model probe passed.")


if __name__ == "__main__":
    main()
