#!/usr/bin/env python3
"""Build and run the portable C parser tests with MSVC on Windows."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build-host-tests"
FIXTURE = ROOT / "tests" / "fixtures" / "wpa.cap"


def main() -> int:
    BUILD.mkdir(exist_ok=True)
    if os.name == "nt":
        visual_studio_root = Path(r"C:\Program Files\Microsoft Visual Studio\2022")
        editions = ("BuildTools", "Community", "Professional", "Enterprise")
        installs = [visual_studio_root / edition for edition in editions]
        install = next((path for path in installs if (path / "VC" / "Tools" / "MSVC").is_dir()), None)
        if install is None:
            raise SystemExit("Visual Studio C++ tools not found in a standard VS 2022 location")
        tool_versions = sorted(
            (path for path in (install / "VC" / "Tools" / "MSVC").iterdir() if path.is_dir()),
            key=lambda path: tuple(int(part) for part in path.name.split(".")),
        )
        if not tool_versions:
            raise SystemExit("No MSVC tool version found")
        msvc = tool_versions[-1]
        compiler = msvc / "bin" / "Hostx64" / "x64" / "cl.exe"

        kits = Path(r"C:\Program Files (x86)\Windows Kits\10")
        sdk_versions = sorted(
            (path for path in (kits / "Include").iterdir() if path.is_dir()),
            key=lambda path: tuple(int(part) for part in path.name.split(".")),
        )
        if not compiler.is_file() or not sdk_versions:
            raise SystemExit("MSVC compiler or Windows SDK not found")
        sdk_version = sdk_versions[-1].name
        include_root = kits / "Include" / sdk_version
        library_root = kits / "Lib" / sdk_version
        environment = os.environ.copy()
        environment["INCLUDE"] = os.pathsep.join(
            str(path)
            for path in (
                msvc / "include",
                include_root / "ucrt",
                include_root / "shared",
                include_root / "um",
                include_root / "winrt",
            )
        )
        environment["LIB"] = os.pathsep.join(
            str(path)
            for path in (
                msvc / "lib" / "x64",
                library_root / "ucrt" / "x64",
                library_root / "um" / "x64",
            )
        )
        environment["PATH"] = os.pathsep.join(
            (str(compiler.parent), str(install / "Common7" / "IDE"), environment["PATH"])
        )
        executable = BUILD / "parser_test.exe"
        subprocess.run(
            [
                str(compiler),
                "/nologo",
                "/std:c11",
                "/W4",
                "/WX",
                f'/I{ROOT}',
                str(ROOT / "acf_parser.c"),
                f'/Tc{ROOT / "tests" / "parser_test.c.host"}',
                f'/Fe:{executable}',
            ],
            check=True,
            cwd=BUILD,
            env=environment,
        )
    else:
        compiler = shutil.which("cc")
        if not compiler:
            raise SystemExit("C compiler not found")
        executable = BUILD / "parser_test"
        subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", f"-I{ROOT}", str(ROOT / "acf_parser.c"), "-x", "c", str(ROOT / "tests" / "parser_test.c.host"), "-o", str(executable)],
            check=True,
        )
    args = [str(executable)]
    if FIXTURE.exists():
        args.append(str(FIXTURE))
    subprocess.run(args, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
