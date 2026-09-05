#!/usr/bin/env python3
"""Build an isolated Linux release package and check its native files."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


TARGET = "x86_64-unknown-linux-gnu"
PACKAGE_FILES = "package-manifest.json"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_name(name):
    return (
        isinstance(name, str)
        and name not in {"", ".", ".."}
        and Path(name).name == name
        and "\\" not in name
        and all(character.isascii() and (character.isalnum() or character in "._-") for character in name)
    )


def native_files(root):
    metadata_path = root / "lib" / "native-dependencies.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("schema_version") != 1:
        raise ValueError("The native dependency schema is not supported.")

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


def package(output_argument=None):
    root = Path(__file__).resolve().parents[1]
    names = native_files(root)
    package_id = uuid.uuid4().hex[:8]
    output = (
        Path(output_argument).expanduser().resolve()
        if output_argument
        else root / "target" / "packages" / f"hview-linux-x86_64-{package_id}"
    )
    if output.exists():
        raise FileExistsError(f"The package directory exists: {output}")

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

        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir()
        shutil.copy2(binary, output / binary.name)
        for name in names:
            shutil.copy2(root / "lib" / name, output / name)

    files = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        files.append({"file": path.name, "sha256": sha256(path), "size": path.stat().st_size})
    manifest = {"schema_version": 1, "target": TARGET, "files": files}
    (output / PACKAGE_FILES).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, str(root / "tests" / "package_probe.py"), str(output)],
        cwd=root,
        check=True,
    )
    print(f"Package ready: {output}")
    return output


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


if __name__ == "__main__":
    raise SystemExit(main())
