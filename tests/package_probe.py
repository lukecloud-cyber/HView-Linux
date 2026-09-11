#!/usr/bin/env python3
"""Check one Linux package outside the source checkout."""

# Standard-library modules inspect bytes, execute tools, and create one disposable package copy.
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


# These names define the complete flat package contract.
# Native dependency metadata adds the two shared libraries and their notices.
MANIFEST = "package-manifest.json"
NATIVE_METADATA = "native-dependencies.json"
PACKAGE_DOCUMENTS = {"README.md", "hview-linux.ini.example"}
PACKAGE_LICENSES = {
    "THIRD-PARTY-NOTICES.txt",
    "UNICODE-COPYRIGHT.txt",
    "UNICODE-APACHE-2.0.txt",
    "UNICODE-MIT.txt",
}


# Convert one failed package condition into a clear probe assertion.
def require(condition, message):
    if not condition:
        raise AssertionError(message)


# Calculate the exact digest for one package file in bounded blocks.
def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Accept only one portable ASCII basename without path separators.
def safe_name(name):
    return (
        isinstance(name, str)
        and name not in {"", ".", ".."}
        and Path(name).name == name
        and "\\" not in name
        and all(character.isascii() and (character.isalnum() or character in "._-") for character in name)
    )


# Verify the binary architecture and reject unsafe dynamic-loader control tags.
# The header check runs before readelf supplies the complete dynamic table.
def check_elf_x86_64(path):
    with path.open("rb") as source:
        header = source.read(20)
    require(len(header) == 20, f"The ELF header is incomplete: {path.name}")
    require(header[:7] == b"\x7fELF\x02\x01\x01", f"The file is not an ELF64 little-endian file: {path.name}")
    require(int.from_bytes(header[18:20], "little") == 62, f"The ELF machine is not x86-64: {path.name}")
    # Use the host readelf only for read-only package inspection.
    readelf = shutil.which("readelf")
    require(readelf is not None, "The package check cannot find readelf.")
    dynamic = subprocess.run(
        [readelf, "-d", str(path)],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    require(dynamic.returncode == 0, dynamic.stdout + dynamic.stderr)
    for tag in ("(RPATH)", "(RUNPATH)", "(AUDIT)", "(DEPAUDIT)"):
        require(tag not in dynamic.stdout, f"The ELF file contains a forbidden {tag} tag: {path.name}")


# Remove loader overrides and require portable native loading from the package directory.
def isolated_environment():
    environment = {name: value for name, value in os.environ.items() if not name.startswith("LD_")}
    environment["HVIEW_PORTABLE"] = "1"
    return environment


# Derive the exact required file set from checked native metadata and fixed project notices.
# Return the library names separately for ELF and runtime checks.
def expected_files(package):
    metadata = json.loads((package / NATIVE_METADATA).read_text(encoding="utf-8"))
    require(metadata.get("schema_version") == 1, "The native dependency schema is not supported.")
    names = {"hview-linux", NATIVE_METADATA, *PACKAGE_DOCUMENTS, *PACKAGE_LICENSES}

    # Fixed Unicode notices must exist before the exact manifest comparison starts.
    for name in PACKAGE_LICENSES:
        require((package / name).is_file(), f"The Unicode notice does not exist: {name}")

    # Native metadata supplies checked library and notice names with pinned hashes.
    libraries = []
    for dependency in metadata.get("dependencies", []):
        require(
            dependency.get("architecture") == "linux-x86_64",
            "A native dependency has an incorrect architecture.",
        )
        files = [dependency["shared_library"], *dependency.get("licenses", [])]
        for item in files:
            name = item.get("file")
            require(safe_name(name), f"The native file name is not safe: {name}")
            require(name not in names, f"The native file name is not unique: {name}")
            require(
                sha256(package / name) == item.get("sha256"),
                f"The native file hash does not match pinned metadata: {name}",
            )
            names.add(name)
        libraries.append(dependency["shared_library"]["file"])
    require(set(libraries) == {"libcapstone.so", "libkeystone.so"}, "The native library set is incorrect.")
    return names, libraries


# Verify one package manifest, every package byte, and isolated native loading behavior.
def check(package):
    package = package.resolve(strict=True)
    require(package.is_dir(), f"The package path is not a directory: {package}")
    manifest = json.loads((package / MANIFEST).read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == 1, "The package manifest schema is not supported.")
    require(manifest.get("target") == "x86_64-unknown-linux-gnu", "The package target is incorrect.")

    # Require a flat regular-file package before trusting manifest paths.
    entries = list(package.iterdir())
    require(
        all(entry.is_file() and not entry.is_symlink() for entry in entries),
        "The package contains a directory or symbolic link.",
    )

    # Parse each recorded manifest item only after the flat-file guard passes.
    listed = {}
    for item in manifest.get("files", []):
        name = item.get("file")
        require(safe_name(name), f"The package file name is not safe: {name}")
        require(name not in listed, f"The package file name is not unique: {name}")
        listed[name] = item

    # Compare the recorded and actual sets before reading individual file metadata.
    required, libraries = expected_files(package)
    require(set(listed) == required, "The package manifest file list is incorrect.")
    actual = {entry.name for entry in entries}
    require(actual == required | {MANIFEST}, "The package file set does not match the manifest.")
    for name, item in listed.items():
        path = package / name
        require(path.stat().st_size == item.get("size"), f"The package file size does not match: {name}")
        require(sha256(path) == item.get("sha256"), f"The package file hash does not match: {name}")

    # Check the executable, user documents, configuration defaults, and native ELF files.
    binary = package / "hview-linux"
    require(os.access(binary, os.X_OK), "The packaged hview-linux file is not executable.")
    readme = (package / "README.md").read_text(encoding="utf-8")
    require(readme.startswith("# HView-Linux\n"), "The packaged README file has an invalid title.")
    sample = (package / "hview-linux.ini.example").read_bytes()
    require(
        sample.startswith(b"[HView-Linux 1]\n") and b"\r" not in sample,
        "The packaged configuration sample does not use the native header and LF lines.",
    )
    sample_text = sample.decode("utf-8")
    require(
        "\nDisassemblySyntax=Intel\nInvalidCode=Error\n" in sample_text,
        "The packaged configuration sample does not show the native Code defaults.",
    )
    check_elf_x86_64(binary)
    for name in libraries:
        check_elf_x86_64(package / name)

    # Copy the package away from the checkout and run with portable native loading.
    with tempfile.TemporaryDirectory(prefix="hview-package-") as folder:
        isolated = Path(folder) / "package"
        shutil.copytree(package, isolated)
        environment = isolated_environment()

        # Use one command shape for the accepted package and each missing-library check.
        def run():
            return subprocess.run(
                [str(isolated / "hview-linux"), "--self-test"],
                cwd=folder,
                env=environment,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
            )

        # The complete package must pass its self-test without loader environment overrides.
        result = run()
        require(result.returncode == 0, result.stdout + result.stderr)
        require("Native self-test passed." in result.stdout, result.stdout + result.stderr)

        # A nested probe must reject a missing Unicode notice before it runs application checks.
        notice = isolated / "UNICODE-COPYRIGHT.txt"
        hidden_notice = notice.with_suffix(".txt.disabled")
        notice.rename(hidden_notice)
        try:
            missing = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), str(isolated)],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
            )
            require(missing.returncode != 0, "The package check accepted a missing Unicode notice.")
            require(notice.name in missing.stdout + missing.stderr, missing.stdout + missing.stderr)
        finally:
            hidden_notice.rename(notice)

        # Remove each native engine separately and require a named self-test failure.
        for name in libraries:
            library = isolated / name
            hidden = library.with_name(f"{name}.disabled")
            library.rename(hidden)
            try:
                result = run()
                require(result.returncode != 0, f"The self-test accepted a missing {name}.")
                require(name in result.stdout + result.stderr, result.stdout + result.stderr)
            finally:
                hidden.rename(library)
    print("Package hashes and isolated native engine checks passed.")


# Parse one package path and report all expected validation failures without a traceback.
def main():
    if len(sys.argv) != 2:
        print("Usage: package_probe.py PACKAGE_DIRECTORY", file=sys.stderr)
        return 2
    try:
        check(Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(f"Package check failed: {error}", file=sys.stderr)
        return 1
    return 0


# Exit through main so a nested missing-file probe can use the same validation route.
if __name__ == "__main__":
    raise SystemExit(main())
