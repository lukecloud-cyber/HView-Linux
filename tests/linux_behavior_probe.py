#!/usr/bin/env python3
"""Check Real16, invalid-byte fallback, and raw ELF Code viewing."""

from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


CTRL_Q = b"\x11"


def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


def after_last(output: bytes, text: bytes) -> bytes:
    """Return output after the final text value."""
    position = output.rfind(text)
    if position < 0:
        raise AssertionError(f"The terminal output lacks: {text!r}")
    return output[position:]


def main() -> None:
    """Run the Linux behavior checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: linux_behavior_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-linux-behavior-") as temporary:
        root = Path(temporary)
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

        session = root / "real16.sav"
        run_session(
            binary,
            ["--mode=code", "--session", str(session), str(code)],
            [b"o", b"o", b"o", CTRL_Q],
        )
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"Real16", "The saved session did not restore Real16.")

        elf = root / "raw.elf"
        elf.write_bytes(b"\x7fELF\x90\xc3")
        output = run_session(
            binary,
            ["--mode=code", "--offset=4", str(elf)],
            [CTRL_Q],
        )
        require(output, b"00000004: 90", "Raw ELF Code viewing did not decode the selected byte.")
        require(output, b"nop", "Raw ELF Code viewing did not decode x86 bytes.")

    print("Linux behavior probe passed.")


if __name__ == "__main__":
    main()
