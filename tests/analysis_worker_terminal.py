#!/usr/bin/env python3
"""Run the ignored analysis worker test through a controlled Linux pseudoterminal."""

# These imports provide bounded terminal I/O, resize control, process management, and artifact parsing.
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import termios
import time


# This helper waits for one output marker while it retains all terminal bytes for later assertions.
# The fixed deadline turns missing worker progress or restoration into a clear harness failure.
def wait_for(
    fd: int,
    output: bytearray,
    marker: bytes,
    start: int,
    seconds: float = 5.0,
) -> int:
    """Read until one marker appears after the phase offset."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if marker in output[start:]:
            return output.index(marker, start) + len(marker)
        ready, _, _ = select.select([fd], [], [], min(0.05, deadline - time.monotonic()))
        if not ready:
            continue
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            break
    raise AssertionError(f"The terminal output lacks {marker!r}: {output[-1200:]!r}")


# This helper empties output that is already available before a resize assertion starts.
# The short idle interval separates the old frame from the redraw caused by the new dimensions.
def drain_ready(fd: int, output: bytearray) -> None:
    """Drain terminal output until one short idle interval."""
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            return
        try:
            output.extend(os.read(fd, 65536))
        except OSError:
            return
    raise AssertionError("The terminal produced continuous output during the quiet worker interval.")


# This parser selects the main Rust test executable from Cargo's saved JSON artifact messages.
# The separate artifact input keeps shell command substitution out of the test route.
def test_executable(messages: Path) -> Path:
    """Return the compiled HView-Linux unit-test executable."""
    for line in messages.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        target = record.get("target", {})
        executable = record.get("executable")
        if (
            record.get("reason") == "compiler-artifact"
            and target.get("name") == "hview-linux"
            and record.get("profile", {}).get("test") is True
            and executable
        ):
            return Path(executable)
    raise AssertionError("Cargo did not report the HView-Linux unit-test executable.")


# This entry point controls completion, cancellation, resize, queued input, and error phases.
# The test executable contains the worker synchronization and exact decoded-key assertions.
def main() -> None:
    """Run the controlled worker terminal check."""
    if len(sys.argv) != 2:
        raise SystemExit("Usage: analysis_worker_terminal.py CARGO_MESSAGES")
    executable = test_executable(Path(sys.argv[1]))

    # This section creates one 80-by-24 pseudoterminal and records its restorable input state.
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    # This pipe supplies one test-only gate byte after the idle resize redraw is visible.
    # The descriptor exists only in the Rust test process and cannot change the production executable.
    worker_gate, owner_gate = os.pipe()
    environment = os.environ.copy()
    environment["HVIEW_TEST_GATE_FD"] = str(worker_gate)
    process = subprocess.Popen(
        [
            str(executable),
            "--exact",
            "console::tests::analysis_worker_terminal_harness",
            "--ignored",
            "--nocapture",
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=environment,
        pass_fds=(worker_gate,),
    )
    os.close(worker_gate)
    output = bytearray()
    try:
        # This section requires restoration after completion before the cancellation worker starts.
        phase = 0
        phase = wait_for(master, output, b"COMPLETION RESTORED", phase)
        phase = wait_for(master, output, b"CANCEL READY", phase)
        phase = wait_for(master, output, b"Entropy... 50%", phase)
        drain_ready(master, output)

        # This section resizes the quiet worker and requires the same progress at both terminal sizes.
        # Returning to 24 rows hides the cancellation marker under the active progress footer.
        resize_start = len(output)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 96, 0, 0))
        wait_for(master, output, b"Entropy... 50%", resize_start)
        restore_size_start = len(output)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        wait_for(master, output, b"Entropy... 50%", restore_size_start)
        drain_ready(master, output)
        cancel_start = len(output)
        os.write(owner_gate, b"R")

        # This section supplies retained normal and fragmented Alt input plus one retired function key.
        os.write(master, b"x")
        os.write(master, b"\x1b")
        time.sleep(0.005)
        os.write(master, b"h")
        os.write(master, b"\x1bOP")
        os.write(master, b"\x1b")
        time.sleep(0.05)
        os.write(master, b"z")

        # This section requires cancellation restoration before the controlled native input error starts.
        phase = wait_for(master, output, b"CANCELLATION RESTORED", cancel_start)
        phase = wait_for(master, output, b"INPUT ERROR READY", phase)
        phase = wait_for(master, output, b"InputError... Working", phase)
        os.write(master, b"y\xc2")
        phase = wait_for(master, output, b"INPUT ERROR RESTORED", phase)

        # This section requires inner-error restoration and dismisses its exact modal notice.
        phase = wait_for(master, output, b"INNER ERROR READY", phase)
        phase = wait_for(master, output, b"INNER ERROR RESTORED", phase)
        wait_for(master, output, b"Analysis failed: controlled analysis error", phase)
        os.write(master, b"\r")

        # This section requires bounded test completion and verifies terminal restoration after Console drops.
        deadline = time.monotonic() + 5.0
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    break
        if process.poll() is None:
            process.kill()
            raise AssertionError("The analysis worker terminal test did not stop.")
        if process.returncode != 0:
            raise AssertionError(f"The analysis worker terminal test failed: {output[-1600:]!r}")
        if termios.tcgetattr(slave) != before:
            raise AssertionError("The analysis worker terminal test did not restore terminal settings.")
        for marker in [b"Completion... Working", b"test result: ok"]:
            if marker not in output:
                raise AssertionError(f"The terminal output lacks {marker!r}.")
    finally:
        # This cleanup stops an unfinished test and closes both pseudoterminal descriptors.
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(owner_gate)
        os.close(master)
        os.close(slave)
    print("Analysis worker terminal check passed.")


# This standard entry route keeps the harness outside the automatic application-probe package list.
if __name__ == "__main__":
    main()
