#!/usr/bin/env python3
"""Check editing, assembly, save, and recovery workflows."""

# These imports provide disposable files and terminal sessions for failure-path checks.
from pathlib import Path
import sys
import tempfile

from terminal_probe import run_session


# These byte sequences select current save, assembly, edit, and quit controls.
CTRL_Q = b"\x11"
CTRL_S = b"\x13"
ALT_A = b"\x1ba"
ALT_E = b"\x1be"
ALT_S = b"\x1bs"
RIGHT = b"\x1b[C"


# This helper finds private recovery directories after save operations.
# Callers inspect their bounded contents or require complete cleanup.
def recovery_directories(folder: Path) -> list[Path]:
    """List private save recovery directories."""
    return sorted(folder.glob(".HView-save-*"))


# This assertion connects one expected notice to its failure-path reason.
def require(output: bytes, text: bytes, reason: str) -> None:
    """Require terminal output text."""
    if text not in output:
        raise AssertionError(reason)


# This entry point creates isolated files and runs each reliability workflow.
# Every terminal session must restore the terminal before the next workflow starts.
def main() -> None:
    """Run the reliability checks."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: reliability_probe.py <hview-linux>")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"The executable does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="hview-reliability-") as temporary:
        root = Path(temporary)

        # This section cancels one Hex edit, then saves a second edit with recovery bytes.
        edit_folder = root / "edit"
        edit_folder.mkdir()
        edited = edit_folder / "edited.bin"
        edited.write_bytes(b"\x12")
        run_session(
            binary,
            ["--mode=hex", str(edited)],
            [ALT_E, b"abcd", b"\x1b", CTRL_Q],
        )
        if edited.read_bytes() != b"\x12":
            raise AssertionError("Edit cancellation changed the file.")
        run_session(binary, ["--mode=hex", str(edited)], [ALT_E, b"abcd", ALT_S, CTRL_Q])
        if edited.read_bytes() != b"\xab\xcd":
            raise AssertionError("Nibble editing did not extend the file at EOF.")
        recoveries = recovery_directories(edit_folder)
        if len(recoveries) != 1 or (recoveries[0] / "original.bin").read_bytes() != b"\x12":
            raise AssertionError("Replacement save did not keep the original bytes.")

        # This section proves that Ctrl+Z restores the group cursor before the next nibble pair.
        undo_folder = root / "undo"
        undo_folder.mkdir()
        undo = undo_folder / "undo.bin"
        undo.write_bytes(b"\x12\x34")
        run_session(binary, ["--mode=hex", str(undo)], [ALT_E, b"a", b"\x1a", b"cd", ALT_S, CTRL_Q])
        if undo.read_bytes() != b"\xcd\x34":
            raise AssertionError("Grouped undo did not restore the original cursor.")

        # This section keeps Intel assembly input while the configured view uses AT&T syntax.
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
            [ALT_E, ALT_A, b"nop\r", b"\r", b"\x1b", ALT_S, CTRL_Q],
        )
        require(output, b"%ebx", "AT&T display syntax did not appear.")
        require(output, b"eax, ebx", "The assembly seed did not keep Intel syntax.")
        if assembly.read_bytes() != b"\x90\xd8":
            raise AssertionError("The Intel assembly edit produced unexpected bytes.")

        # This section assembles at EOF and verifies the saved buffered growth.
        extension = assembly_folder / "extension.bin"
        extension.write_bytes(b"\xc3")
        run_session(
            binary,
            ["--mode=code", str(extension)],
            [RIGHT, ALT_E, ALT_A, b"nop\r", b"\r", b"\x1b", ALT_S, CTRL_Q],
        )
        if extension.read_bytes() != b"\xc3\x90":
            raise AssertionError("Assembly did not extend the buffer at EOF.")

        # This section makes Save As the active path before replacement Save and session restart.
        switch_folder = root / "switch"
        switch_folder.mkdir()
        original = switch_folder / "original.bin"
        destination = switch_folder / "copy.bin"
        session = switch_folder / "state.sav"
        original.write_bytes(b"\x56")
        run_session(
            binary,
            ["--mode=hex", "--session", str(session), str(original)],
            [CTRL_S, str(destination).encode(), b"\r", ALT_E, b"ab", ALT_S, CTRL_Q],
        )
        if original.read_bytes() != b"\x56" or destination.read_bytes() != b"\xab":
            raise AssertionError("Save As did not switch replacement saves to the new file.")
        recoveries = recovery_directories(switch_folder)
        if len(recoveries) != 1 or (recoveries[0] / "original.bin").read_bytes() != b"\x56":
            raise AssertionError("The new target replacement did not keep its original bytes.")
        output = run_session(binary, ["--session", str(session)], [CTRL_Q])
        require(output, b"copy.bin", "The Save As path did not survive session restart.")

        # This section refuses an existing Save As target and retains recoverable source bytes.
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

        # This section cancels Save As before publication and requires no directory changes.
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

        # This section changes the source externally before Save and requires complete refusal cleanup.
        external_folder = root / "external"
        external_folder.mkdir()
        external = external_folder / "external.bin"
        external.write_bytes(b"\x90")
        output = run_session(
            binary,
            ["--mode=hex", str(external)],
            [
                ALT_E,
                b"ab",
                lambda: external.write_bytes(b"\xee"),
                ALT_S,
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
