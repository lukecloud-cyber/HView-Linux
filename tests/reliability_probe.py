#!/usr/bin/env python3
"""Check editing, assembly, save, and recovery workflows."""

from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


CTRL_Q = b"\x11"
CTRL_S = b"\x13"
F2 = b"\x1b[12~"
F3 = b"\x1b[13~"
F9 = b"\x1b[20~"
RIGHT = b"\x1b[C"


def recovery_directories(folder: Path) -> list[Path]:
    """List private save recovery directories."""
    return sorted(folder.glob(".HView-save-*"))


def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


def main() -> None:
    """Run the reliability checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: reliability_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-reliability-") as temporary:
        root = Path(temporary)

        edit_folder = root / "edit"
        edit_folder.mkdir()
        edited = edit_folder / "edited.bin"
        edited.write_bytes(b"\x12")
        run_session(
            binary,
            ["--mode=hex", str(edited)],
            [F3, b"abcd", b"\x1b", CTRL_Q],
        )
        if edited.read_bytes() != b"\x12":
            raise AssertionError("Edit cancellation changed the file.")
        run_session(binary, ["--mode=hex", str(edited)], [F3, b"abcd", F9, CTRL_Q])
        if edited.read_bytes() != b"\xab\xcd":
            raise AssertionError("Nibble editing did not extend the file at EOF.")
        recoveries = recovery_directories(edit_folder)
        if len(recoveries) != 1 or (recoveries[0] / "original.bin").read_bytes() != b"\x12":
            raise AssertionError("Replacement save did not keep the original bytes.")

        undo_folder = root / "undo"
        undo_folder.mkdir()
        undo = undo_folder / "undo.bin"
        undo.write_bytes(b"\x12\x34")
        run_session(binary, ["--mode=hex", str(undo)], [F3, b"a", F3, b"cd", F9, CTRL_Q])
        if undo.read_bytes() != b"\x12\xcd":
            raise AssertionError("Current-byte undo did not restore the selected byte.")

        assembly_folder = root / "assembly"
        assembly_folder.mkdir()
        att_config = assembly_folder / "att.ini"
        att_config.write_bytes(
            b"[HView-Linux 1]\nDefaultCodeSize=32\nDisassemblySyntax=ATT\n"
        )
        assembly = assembly_folder / "assembly.bin"
        assembly.write_bytes(b"\x89\xd8")
        output = run_session(
            binary,
            ["--config", str(att_config), "--mode=code", str(assembly)],
            [F3, F2, b"nop\r", b"\x1b", F9, CTRL_Q],
        )
        require(output, b"%ebx", "AT&T display syntax did not appear.")
        require(output, b"eax, ebx", "The assembly seed did not keep Intel syntax.")
        if assembly.read_bytes() != b"\x90\xd8":
            raise AssertionError("The Intel assembly edit produced unexpected bytes.")

        extension = assembly_folder / "extension.bin"
        extension.write_bytes(b"\xc3")
        run_session(
            binary,
            ["--mode=code", str(extension)],
            [RIGHT, F3, F2, b"nop\r", b"\x1b", F9, CTRL_Q],
        )
        if extension.read_bytes() != b"\xc3\x90":
            raise AssertionError("Assembly did not extend the buffer at EOF.")

        switch_folder = root / "switch"
        switch_folder.mkdir()
        original = switch_folder / "original.bin"
        destination = switch_folder / "copy.bin"
        session = switch_folder / "state.sav"
        original.write_bytes(b"\x56")
        run_session(
            binary,
            ["--mode=hex", "--session", str(session), str(original)],
            [CTRL_S, str(destination).encode(), b"\r", F3, b"ab", F9, CTRL_Q],
        )
        if original.read_bytes() != b"\x56" or destination.read_bytes() != b"\xab":
            raise AssertionError("Save As did not switch replacement saves to the new file.")
        recoveries = recovery_directories(switch_folder)
        if len(recoveries) != 1 or (recoveries[0] / "original.bin").read_bytes() != b"\x56":
            raise AssertionError("The new target replacement did not keep its original bytes.")
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"copy.bin", "The Save As path did not survive session restart.")

        refusal_folder = root / "refusal"
        refusal_folder.mkdir()
        source = refusal_folder / "source.bin"
        existing = refusal_folder / "existing.bin"
        source.write_bytes(b"source")
        existing.write_bytes(b"existing")
        output = run_session(
            binary,
            [str(source)],
            [CTRL_S, str(existing).encode(), b"\r", b"\r", CTRL_Q],
        )
        require(output, b"destination already exists", "Save As did not report an existing destination.")
        if existing.read_bytes() != b"existing":
            raise AssertionError("Save As changed an existing destination.")
        recoveries = recovery_directories(refusal_folder)
        if len(recoveries) != 1 or (recoveries[0] / "new.bin").read_bytes() != b"source":
            raise AssertionError("Save As did not retain recoverable bytes after refusal.")

        cancel_folder = root / "cancel"
        cancel_folder.mkdir()
        cancel_source = cancel_folder / "source.bin"
        cancel_source.write_bytes(b"cancel")
        entries = set(cancel_folder.iterdir())
        run_session(
            binary,
            [str(cancel_source)],
            [CTRL_S, b"\x1b", CTRL_Q],
        )
        if set(cancel_folder.iterdir()) != entries:
            raise AssertionError("A canceled Save As changed the directory.")

        external_folder = root / "external"
        external_folder.mkdir()
        external = external_folder / "external.bin"
        external.write_bytes(b"\x90")
        output = run_session(
            binary,
            ["--mode=hex", str(external)],
            [
                F3,
                b"ab",
                lambda: external.write_bytes(b"\xee"),
                F9,
                b"\r",
                b"\x1b",
                CTRL_Q,
            ],
        )
        require(output, b"changed outside", "Replacement save did not report an external change.")
        if external.read_bytes() != b"\xee":
            raise AssertionError("Replacement save changed externally written bytes.")
        if recovery_directories(external_folder):
            raise AssertionError("External change refusal left recovery data.")

    print("Reliability probe passed.")


if __name__ == "__main__":
    main()
