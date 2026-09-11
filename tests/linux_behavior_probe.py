#!/usr/bin/env python3
"""Check Real16, invalid-byte fallback, and explicit raw ELF Code viewing."""

# These imports provide native paths, process arguments, temporary isolation, and the shared PTY driver.
# The probe uses only standard-library data and the established terminal helper.
from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


# These key bytes select analysis tools, confirm prompts, and close the application.
# Each session supplies exact terminal input through the shared PTY driver.
CTRL_Q = b"\x11"
CTRL_T = b"\x14"
ENTER = b"\r"


# This assertion helper checks one required terminal value and reports the feature reason.
# The caller keeps each expected value close to its tested workflow.
def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


# This assertion helper selects output after the last mode label.
# Later checks cannot pass from stale text in an earlier terminal frame.
def after_last(output: bytes, text: bytes) -> bytes:
    """Return output after the final text value."""
    position = output.rfind(text)
    if position < 0:
        raise AssertionError(f"The terminal output lacks: {text!r}")
    return output[position:]


# The entry point validates one release executable and runs all fixtures in one private directory.
# Each retained group checks one visible application behavior through terminal input.
def main() -> None:
    """Run the Linux behavior checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: linux_behavior_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-linux-behavior-") as temporary:
        root = Path(temporary)

        # The mode-cycle group checks the complete automatic x86 width and Real16 order.
        # The final cycle must return to the initial 16-bit Code mode.
        code = root / "code.bin"
        code.write_bytes(b"\x90\xc3")
        output = run_session(
            binary,
            ["--mode=code", str(code)],
            [b"o", b"o", b"o", b"o", CTRL_Q],
        )
        position = 0
        for label in [b"a16", b"a32", b"a64", b"Real16", b"a16"]:
            position = output.find(label, position)
            if position < 0:
                raise AssertionError("The Code mode cycle order is incorrect.")
            position += len(label)

        # The legacy group checks instructions that remain valid under the Real16 policy.
        # Prefix-like bytes must keep their established 16-bit instruction meanings.
        legacy = root / "legacy.bin"
        legacy.write_bytes(bytes.fromhex("C4 00 C5 00 62 00 8F 00"))
        output = run_session(
            binary,
            ["--mode=code", str(legacy)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        real_output = after_last(output, b"Real16")
        for mnemonic in [b"les", b"lds", b"bound", b"pop"]:
            require(
                real_output,
                mnemonic,
                "Real16 rejected a valid legacy prefix lookalike.",
            )

        # The protected-instruction group checks strict rejection after Real16 selection.
        # The selected protected-mode instruction must not enter the visible Code list.
        protected = root / "protected.bin"
        protected.write_bytes(bytes.fromhex("63 C0"))
        output = run_session(
            binary,
            ["--mode=code", str(protected)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        require(
            after_last(output, b"Real16"),
            b"Invalid or incomplete x86 instruction",
            "Strict Real16 accepted a protected-mode instruction.",
        )

        # The fallback group enables InvalidCode=Byte through a native configuration file.
        # The same protected input must become one visible data byte.
        fallback_config = root / "fallback.ini"
        fallback_config.write_bytes(
            b"[HView-Linux 1]\nStartMode=Code\nInvalidCode=Byte\n"
        )
        output = run_session(
            binary,
            ["--config", str(fallback_config), str(protected)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        require(
            after_last(output, b"Real16"),
            b"db 63",
            "The explicit invalid-byte fallback did not show one byte.",
        )

        # The incomplete-input group compares strict decoding with configured byte fallback.
        # Both sessions use the same one-byte truncated x86 instruction.
        incomplete = root / "incomplete.bin"
        incomplete.write_bytes(b"\x0f")
        output = run_session(binary, ["--mode=code", str(incomplete)], [CTRL_Q])
        require(
            output,
            b"Invalid or incomplete x86 instruction",
            "The default decoder did not keep strict invalid-byte handling.",
        )
        output = run_session(
            binary,
            ["--config", str(fallback_config), str(incomplete)],
            [CTRL_Q],
        )
        require(output, b"db 0F", "The fallback did not show an incomplete byte.")

        # The wrapping group selects a branch at the first address above the 16-bit range.
        # Real16 must display the wrapped direct target at address zero.
        relative = root / "relative.bin"
        relative.write_bytes(bytes(0x10000) + b"\xeb\xfe")
        output = run_session(
            binary,
            ["--mode=code", "--offset=10000", str(relative)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        require(
            after_last(output, b"Real16"),
            b"jmp          0x0",
            "Real16 did not wrap the relative target to 16 bits.",
        )

        # The syntax group selects AT&T display before it enters Real16.
        # Register order and names must keep the configured x86 syntax.
        att_config = root / "att.ini"
        att_config.write_bytes(
            b"[HView-Linux 1]\nStartMode=Code\nDisassemblySyntax=ATT\n"
        )
        registers = root / "registers.bin"
        registers.write_bytes(bytes.fromhex("89 D8"))
        output = run_session(
            binary,
            ["--config", str(att_config), str(registers)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        require(
            after_last(output, b"Real16"),
            b"%bx, %ax",
            "Real16 did not preserve the selected AT&T syntax.",
        )

        # The SAV group writes a Real16 session and reopens the saved view.
        # The second process must restore the versioned Real16 state.
        session = root / "real16.sav"
        run_session(
            binary,
            ["--mode=code", "--session", str(session), str(code)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"Real16", "The saved session did not restore Real16.")

        # The malformed ELF source starts in Hex mode before an explicit raw model takes ownership.
        # Code mode then decodes the selected bytes without accepting malformed automatic metadata.
        elf = root / "raw.elf"
        raw = bytearray(0x30)
        raw[:4] = b"\x7fELF"
        raw[0x20:0x22] = b"\x90\xc3"
        elf.write_bytes(raw)
        output = run_session(
            binary,
            ["--mode=hex", "--offset=20", str(elf)],
            [CTRL_T, b"r", b"X86 32 LE 0", ENTER, b"m", b"c", ENTER, CTRL_Q],
        )
        require(output, b"RAW", "Explicit raw ELF viewing did not show the raw model.")
        require(output, b".00000020", "Explicit raw ELF viewing did not map the selected byte.")
        require(output, b"nop", "Explicit raw ELF viewing did not decode x86 bytes.")

    print("Linux behavior probe passed.")


# This process entry point runs the probe only for direct script execution.
# Imported helpers remain available without starting terminal sessions.
if __name__ == "__main__":
    main()
