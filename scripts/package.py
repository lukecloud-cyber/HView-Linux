#!/usr/bin/env python3
"""Build an isolated Linux release package and check its native files."""

# Standard-library modules supply hashing, isolated builds, file copies, and command execution.
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


# These constants select one build target and the exact nonnative package files.
# Native library metadata supplies the remaining binary and notice names.
TARGET = "x86_64-unknown-linux-gnu"
PACKAGE_FILES = "package-manifest.json"
PACKAGE_DOCUMENTS = ("README.md", "hview-linux.ini.example")
PACKAGE_LICENSES = (
    "THIRD-PARTY-NOTICES.txt",
    "UNICODE-COPYRIGHT.txt",
    "UNICODE-APACHE-2.0.txt",
    "UNICODE-MIT.txt",
)


# Calculate one file digest in bounded blocks.
# The digest becomes the package manifest value or verifies pinned native metadata.
def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Accept only one portable ASCII basename.
# Callers separately reject duplicate package destinations.
def safe_name(name):
    return (
        isinstance(name, str)
        and name not in {"", ".", ".."}
        and Path(name).name == name
        and "\\" not in name
        and all(character.isascii() and (character.isalnum() or character in "._-") for character in name)
    )


# Read the pinned native manifest and return its complete flat file list.
# Each native source must match its recorded architecture, name, and hash.
def native_files(root):
    metadata_path = root / "lib" / "native-dependencies.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("schema_version") != 1:
        raise ValueError("The native dependency schema is not supported.")

    # Keep the metadata file first and reject duplicate names from dependency records.
    names = [metadata_path.name]
    for dependency in metadata.get("dependencies", []):
        if dependency.get("architecture") != "linux-x86_64":
            raise ValueError("A native dependency has an incorrect architecture.")
        files = [dependency["shared_library"], *dependency.get("licenses", [])]
        for item in files:
            name = item.get("file")
            if not safe_name(name) or name in names:
                raise ValueError(f"The native file name is not safe and unique: {name}")
            source = root / "lib" / name
            if not source.is_file():
                raise FileNotFoundError(f"The native file does not exist: {source}")
            if sha256(source) != item.get("sha256"):
                raise ValueError(f"The native file hash does not match: {source}")
            names.append(name)
    return names


# Build one release binary in a private target directory.
# Copy the checked binary, native files, documents, and Unicode notices into one new package directory.
def package(output_argument=None):
    root = Path(__file__).resolve().parents[1]
    names = native_files(root)
    if set(names) & set(PACKAGE_LICENSES):
        raise ValueError("A Unicode notice name conflicts with a native package file.")

    # Select a unique default destination or normalize the caller-supplied destination.
    # Refuse every existing entry before the private build starts.
    package_id = uuid.uuid4().hex[:8]
    output = (
        Path(output_argument).expanduser().resolve()
        if output_argument
        else root / "target" / "packages" / f"hview-linux-x86_64-{package_id}"
    )
    if output.exists():
        raise FileExistsError(f"The package directory exists: {output}")

    # The private build directory prevents earlier target artifacts from becoming package inputs.
    target_root = root / "target"
    target_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="package-build-", dir=target_root) as build:
        subprocess.run(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--target",
                TARGET,
                "--target-dir",
                build,
            ],
            cwd=root,
            check=True,
        )
        binary = Path(build) / TARGET / "release" / "hview-linux"
        if not binary.is_file():
            raise FileNotFoundError(f"The release binary does not exist: {binary}")

        # Create the final directory only after the release binary exists.
        # Copy every source as one regular flat package file.
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir()
        shutil.copy2(binary, output / binary.name)
        for name in names:
            shutil.copy2(root / "lib" / name, output / name)

        # Project documents and Unicode notices have fixed trusted basenames.
        # Each source must remain a regular nonsymbolic file.
        for name in PACKAGE_DOCUMENTS:
            source = root / name
            if not source.is_file() or source.is_symlink():
                raise FileNotFoundError(f"The package document is not a regular file: {source}")
            shutil.copy2(source, output / name)
        for name in PACKAGE_LICENSES:
            source = root / "licenses" / name
            if not source.is_file() or source.is_symlink():
                raise FileNotFoundError(f"The package notice is not a regular file: {source}")
            shutil.copy2(source, output / name)

    # Record every copied file after all copies complete.
    # The manifest excludes itself because its final bytes depend on the file table.
    files = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        files.append({"file": path.name, "sha256": sha256(path), "size": path.stat().st_size})
    manifest = {"schema_version": 1, "target": TARGET, "files": files}
    (output / PACKAGE_FILES).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Check the complete flat package before any application probe runs.
    # Portable loading then proves that each probe uses only packaged native libraries.
    subprocess.run(
        [sys.executable, str(root / "tests" / "package_probe.py"), str(output)],
        cwd=root,
        check=True,
    )

    # Remove inherited loader controls before each application probe uses the packaged binary.
    environment = {name: value for name, value in os.environ.items() if not name.startswith("LD_")}
    environment["HVIEW_PORTABLE"] = "1"
    for probe in sorted((root / "tests").glob("*_probe.py")):
        if probe.name == "package_probe.py":
            continue
        subprocess.run(
            [sys.executable, str(probe), str(output / "hview-linux")],
            cwd=root,
            env=environment,
            check=True,
        )
    print(f"Package ready: {output}")
    return output


# Parse one optional output path and convert expected operating errors into a stable command result.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", help="Use a new directory for the package.")
    arguments = parser.parse_args()
    try:
        package(arguments.output)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Package failed: {error}", file=sys.stderr)
        return 1
    return 0


# Exit through main so imported package tests can call the helpers without starting a build.
if __name__ == "__main__":
    raise SystemExit(main())
