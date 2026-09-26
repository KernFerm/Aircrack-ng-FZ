#!/usr/bin/env python3
"""Build and run the portable C parser tests with MSVC on Windows."""
from pathlib import Path
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build-host-tests"
FIXTURE = ROOT / "tests" / "fixtures" / "wpa.cap"


def main() -> int:
    BUILD.mkdir(exist_ok=True)
    if os.name == "nt":
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if not vswhere.exists():
            raise SystemExit("Visual Studio vswhere.exe not found")
        install = subprocess.check_output(
            [str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
            text=True,
        ).strip()
        vcvars = Path(install) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
        command = f'call "{vcvars}" >nul && cl /nologo /std:c11 /W4 /WX /I"{ROOT}" "{ROOT / "acf_parser.c"}" /Tc"{ROOT / "tests" / "parser_test.c.host"}" /Fe:"{BUILD / "parser_test.exe"}"'
        subprocess.run(command, check=True, shell=True, cwd=BUILD)
        executable = BUILD / "parser_test.exe"
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
