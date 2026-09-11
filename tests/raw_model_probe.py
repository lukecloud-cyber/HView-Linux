#!/usr/bin/env python3
"""Check the transient raw address model through a Linux pseudoterminal."""

# These imports provide PE fixtures, disposable raw files, and terminal sessions.
from pathlib import Path
import sys
import tempfile

from analysis_probe import pe_fixture
from terminal_probe import run_session


# These byte sequences select mapped file, assembler, edit, Goto, and retained tool controls.
BACKSPACE = b"\x7f"
ALT_N = b"\x1bn"
ALT_P = b"\x1bp"
ALT_S = b"\x1bs"
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
CTRL_T = b"\x14"
CTRL_Y = b"\x19"
CTRL_Z = b"\x1a"
ENTER = b"\r"
ESCAPE = b"\x1b"
ALT_A = b"\x1ba"
ALT_E = b"\x1be"
ALT_G = b"\x1bg"


# These assertions require terminal values and their state-transition order.
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


# This selector returns the final complete header for one named source.
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


# This assertion finds one complete header with the requested raw model and runtime address.
def require_raw_header(output: bytes, name: str, model: bytes, address: int) -> None:
    """Require one complete raw Code header."""
    marker = b"\x1b[1;1H"
    position = 0
    while (start := output.find(marker, position)) >= 0:
        end = output.find(b"\x1b[2;1H", start)
        if end < 0:
            break
        header = output[start:end]
        if name.encode() in header and b"RAW" in header and model in header:
            if raw_header(address) in header:
                return
        position = end
    raise AssertionError(f"The terminal output lacks the {model!r} raw header.")


# This formatter builds one raw runtime header at the requested address width.
def raw_header(address: int) -> bytes:
    """Return one raw Code address header."""
    digits = f"{address:08X}"
    suffix = "-Linux"[max(0, len(digits) - 8) :]
    return f".{digits}{suffix}".encode()


# These action builders open raw-model and address prompts with controlled input.
def raw_model(value: str | None) -> list[bytes]:
    """Return actions that open the raw model prompt."""
    actions = [CTRL_T, b"r"]
    if value is None:
        return [*actions, ESCAPE]
    return [*actions, value.encode(), ENTER]


def address(value: str) -> list[bytes]:
    """Return actions that open the address tool."""
    return [CTRL_T, b"a", value.encode(), ENTER]


# This action builder submits one invalid model and dismisses its notice.
def dismissing_raw_model(value: str) -> list[bytes]:
    """Return actions that submit and dismiss an invalid raw model."""
    return [*raw_model(value), ENTER]


# This check maps raw addresses and inspects integers with the selected byte order.
def check_addresses_and_byte_order(binary: Path, root: Path) -> None:
    """Check raw address conversion and selected integer byte order."""
    path = root / "address.bin"
    path.write_bytes(bytes(range(1, 17)))
    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 32 LE 10000000"),
            ALT_G,
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


# This check decodes and assembles through one selected 32-bit raw model.
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
            ALT_E,
            ALT_A,
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
        b"Runtime address: 0000000000001000",
        b"Replacement bytes (5): E8 03 00 00 00",
        raw_header(0x1000),
    )
    if path.read_bytes() != original:
        raise AssertionError("A canceled raw assembly edit changed the file.")


# This check rejects invalid model changes and handles valid high-base file growth atomically.
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
            *dismissing_raw_model("X86 032 LE 1000"),
            *dismissing_raw_model("X86 +32 LE 1000"),
            *dismissing_raw_model("X86 32 LE 1000 junk"),
            *dismissing_raw_model("ARM 32 LE 1000"),
            *dismissing_raw_model("THUMB LE"),
            *dismissing_raw_model("X86 16 LE FFFFFFFF"),
            *dismissing_raw_model("ARM LE FFFFFFFF"),
            *dismissing_raw_model("X86 32 LE 100000000"),
            *dismissing_raw_model("X86 64 LE 10000000000000000"),
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Enter AUTO, X86 16|32|64 LE|BE HEXBASE, or ARM|THUMB|ARM64 LE|BE HEXBASE.",
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
            ALT_E,
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


# This check selects each ARM-family model and follows one ARM branch through current Code controls.
def check_arm_code_and_navigation(binary: Path, root: Path) -> None:
    """Check ARM-family labels, mappings, branches, history, and model selection."""
    path = root / "arm-code.bin"
    data = bytearray(b"\x00" * 20)
    data[0:4] = bytes.fromhex("00 00 00 EA")
    data[8:10] = bytes.fromhex("00 BF")
    data[12:16] = bytes.fromhex("1F 20 03 D5")
    path.write_bytes(data)

    # This session follows and returns from ARM, then changes architecture at the same base.
    # The architecture change clears history while byte-order-only behavior stays in the x86 check.
    output = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("ARM LE 1000"),
            *address("F 0"),
            ESCAPE,
            *address("V 1000"),
            ESCAPE,
            ENTER,
            b"o",
            ENTER,
            BACKSPACE,
            ENTER,
            *raw_model("THUMB LE 1000"),
            BACKSPACE,
            ENTER,
            *raw_model("ARM64 BE 1000"),
            ALT_G,
            b"C",
            ENTER,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"File=00000000 RVA=- VA=0000000000001000",
        b"The branch return history is empty.",
        b"Use Ctrl+T, then R, to select a raw architecture.",
        b"nop",
    )
    require_order(
        output,
        raw_header(0x1000),
        raw_header(0x1008),
        raw_header(0x1000),
        raw_header(0x1008),
    )
    refusal = output.find(b"Use Ctrl+T, then R, to select a raw architecture.")
    if refusal < 0:
        raise AssertionError("The ARM-family O refusal did not appear.")
    require_order(output[refusal:], raw_header(0x1008), raw_header(0x1000))
    require_raw_header(output, path.name, b"ARM", 0x1000)
    require_raw_header(output, path.name, b"THUMB", 0x1008)
    require_raw_header(output, path.name, b"ARM64", 0x100C)


# This check previews ARM and Thumb assembly and keeps one ARM edit transaction in memory.
def check_arm_assembly_transactions(binary: Path, root: Path) -> None:
    """Check ARM-family assembly preview, history, refusal, and cancellation."""
    arm = root / "arm-assembly.bin"
    arm_original = bytes.fromhex("00 00 A0 E1")
    arm.write_bytes(arm_original)

    # This session applies ARM bytes, checks Undo and Redo, and cancels the unsaved transaction.
    output = run_session(
        binary,
        ["--mode=code", str(arm)],
        [
            *raw_model("ARM LE 8000"),
            ALT_E,
            ALT_A,
            b"mov r0, #1",
            ENTER,
            ENTER,
            ESCAPE,
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Assembly patch preview",
        b"Runtime address: 0000000000008000",
        b"Replacement bytes (4): 01 00 A0 E3",
        b"mov          r0, #1",
    )
    applied = output.find(b"Enter Apply  Esc Cancel")
    if applied < 0:
        raise AssertionError("The ARM assembly preview did not offer Apply.")
    require_order(
        output[applied:],
        b"0100A0E3",
        b"0000A0E1",
        b"0100A0E3",
        b"0000A0E1",
    )
    if arm.read_bytes() != arm_original:
        raise AssertionError("ARM Undo, Redo, or cancellation changed the file.")

    # This session previews Thumb bytes and cancels before the editor receives a replacement.
    thumb = root / "thumb-assembly.bin"
    thumb_original = bytes.fromhex("00 BF")
    thumb.write_bytes(thumb_original)
    output = run_session(
        binary,
        ["--mode=code", str(thumb)],
        [
            *raw_model("THUMB LE 9000"),
            ALT_E,
            ALT_A,
            b"movs r0, #1",
            ENTER,
            ESCAPE,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Assembly patch preview",
        b"Runtime address: 0000000000009000",
        b"Replacement bytes (2): 01 20",
    )
    if thumb.read_bytes() != thumb_original:
        raise AssertionError("A canceled Thumb preview changed the file.")

    # This session keeps dirty ARM bytes while ARM64 rejects assembly, then reaches cancellation.
    arm64 = root / "arm64-assembly.bin"
    arm64_original = bytes.fromhex("00 00 A0 E1")
    arm64.write_bytes(arm64_original)
    output = run_session(
        binary,
        ["--mode=code", str(arm64)],
        [
            *raw_model("ARM LE A000"),
            ALT_E,
            ALT_A,
            b"mov r0, #1",
            ENTER,
            ENTER,
            ESCAPE,
            *raw_model("ARM64 LE A000"),
            ALT_A,
            b"nop",
            ENTER,
            ENTER,
            ESCAPE,
            *raw_model("ARM LE A000"),
            CTRL_Z,
            CTRL_Y,
            ESCAPE,
            CTRL_Q,
        ],
    )
    require(
        output,
        b"Replacement bytes (4): 01 00 A0 E3",
        b"ARM64 assembly is unsupported.",
    )
    refusal = output.find(b"ARM64 assembly is unsupported.")
    if refusal < 0:
        raise AssertionError("The ARM64 assembly refusal did not appear.")
    require_order(
        output[refusal:],
        b"0100A0E3",
        b"0000A0E1",
        b"0100A0E3",
        b"0000A0E1",
    )
    if arm64.read_bytes() != arm64_original:
        raise AssertionError("ARM64 refusal or cancellation changed the file.")


# This check clears address history when model width or base changes.
def check_history_and_width_cycle(binary: Path, root: Path) -> None:
    """Check raw history rules and width cycling."""
    # This section creates one relative call and verifies history across accepted and rejected model changes.
    path = root / "history.bin"
    data = bytearray(b"\x90" * 16)
    data[0:5] = b"\xE8\x03\x00\x00\x00"
    data[8] = 0xC3
    path.write_bytes(data)

    # This session keeps one return entry through a canceled and an unchanged model selection.
    retained = run_session(
        binary,
        ["--mode=code", str(path)],
        [
            *raw_model("X86 32 LE 1000"),
            ENTER,
            *raw_model(None),
            BACKSPACE,
            ENTER,
            *raw_model("X86 32 LE 1000"),
            BACKSPACE,
            CTRL_Q,
        ],
    )
    require_order(
        retained,
        raw_header(0x1000),
        raw_header(0x1008),
        raw_header(0x1000),
        raw_header(0x1008),
        raw_header(0x1000),
    )

    # This session checks rejected, byte-order-only, architecture, and base changes.
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
            ALT_G,
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

    # This section cycles the configured width while the runtime base and byte order remain stable.
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

    # This section rejects a narrowing overflow and proves that prior branch-return positions remain available.
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


# This check clears transient raw state across file switches and application restart.
def check_transient_lifetime(binary: Path, root: Path) -> None:
    """Check raw state across rebuilds, files, and restarts."""
    source = root / "source.bin"
    copy = root / "copy.bin"
    source.write_bytes(bytes.fromhex("00 00 A0 E1"))
    output = run_session(
        binary,
        ["--mode=code", str(source)],
        [
            *raw_model("ARM LE 1000"),
            b"m",
            b"h",
            ENTER,
            ALT_E,
            b"FF",
            ESCAPE,
            ALT_G,
            b"0",
            ENTER,
            ALT_E,
            b"01",
            ALT_S,
            b"m",
            b"c",
            ENTER,
            ALT_G,
            b"0",
            ENTER,
            b"m",
            b"h",
            ENTER,
            ALT_E,
            b"02",
            CTRL_S,
            str(copy).encode(),
            ENTER,
            b"m",
            b"c",
            ENTER,
            ALT_G,
            b"0",
            ENTER,
            CTRL_Q,
        ],
    )
    require_order(output, b"0100A0E1", b"0200A0E1")
    require_raw_header(output, source.name, b"ARM", 0x1000)
    require_raw_header(output, copy.name, b"ARM", 0x1000)
    if source.read_bytes() != bytes.fromhex("01 00 A0 E1"):
        raise AssertionError("The ARM replacement Save wrote incorrect bytes.")
    if copy.read_bytes() != bytes.fromhex("02 00 A0 E1"):
        raise AssertionError("The ARM Save As wrote incorrect bytes.")

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
        [*raw_model("THUMB LE 1000"), ALT_N, ALT_P, CTRL_Q],
    )
    if b"RAW" in last_header(output, first.name):
        raise AssertionError("A raw model survived a file switch.")
    require(output, second.name.encode())


# This check restores AUTO PE mapping and preserves supported SAV view fields.
def check_auto_pe_and_session(binary: Path, root: Path) -> None:
    """Check AUTO restoration for PE, configuration, and sessions."""
    # This section overrides a PE model, then restores the mapped PE address and width through AUTO.
    pe_path = root / "pe.bin"
    pe_data, base = pe_fixture(False)
    pe_path.write_bytes(pe_data)
    output = run_session(
        binary,
        ["--mode=code", str(pe_path)],
        [
            *raw_model("ARM LE 50000000"),
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

    # This section restores the configured Code width when AUTO removes an explicit raw model.
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

    # This section keeps Real16 in the SAV record while explicit raw models remain transient.
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


# This entry point runs every raw-model group in one disposable directory.
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
        check_arm_code_and_navigation(binary, root)
        check_arm_assembly_transactions(binary, root)
        check_history_and_width_cycle(binary, root)
        check_transient_lifetime(binary, root)
        check_auto_pe_and_session(binary, root)
    print("Raw model probe passed.")


if __name__ == "__main__":
    main()
