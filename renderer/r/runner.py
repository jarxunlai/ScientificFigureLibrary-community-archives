#!/usr/bin/env python3
"""Auditable R-entry contract bootstrap; untrusted intake is disabled."""

from __future__ import annotations

import os
import subprocess
import sys


EXPECTED_PYTHON = "3.12.12"
EXPECTED_R = "4.4.3"
EXPECTED_UID = 65532
EXPECTED_GID = 65532
TRUSTED_ENTRYPOINT = "payload/code/render.R"
EXPECTED_R_PACKAGES = {
    "dplyr": "1.1.4",
    "ggplot2": "3.5.2",
    "jsonlite": "1.9.1",
    "readr": "2.1.5",
    "scales": "1.4.0",
    "tidyr": "1.3.1",
}
EXPECTED_PYTHON_PACKAGES = {
    "matplotlib": "3.10.3",
    "numpy": "2.2.6",
    "pandas": "2.2.3",
    "seaborn": "0.13.2",
}


def verify_runtime_identity() -> None:
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        raise SystemExit("renderer runtime identity requires Linux UID/GID support")
    if os.getuid() != EXPECTED_UID or os.getgid() != EXPECTED_GID:
        raise SystemExit("renderer runtime identity does not match the non-root contract")


def verify_runtime() -> None:
    verify_runtime_identity()
    if ".".join(str(value) for value in sys.version_info[:3]) != EXPECTED_PYTHON:
        raise SystemExit("Python runtime version does not match renderer lock")
    import importlib.metadata

    for package, expected in EXPECTED_PYTHON_PACKAGES.items():
        if importlib.metadata.version(package) != expected:
            raise SystemExit(f"Python package version mismatch: {package}")
    expression = ";".join(
        [f'stopifnot(getRversion() == "{EXPECTED_R}")']
        + [f'stopifnot(as.character(packageVersion("{name}")) == "{version}")' for name, version in EXPECTED_R_PACKAGES.items()]
    )
    subprocess.run(["/opt/sfl/.pixi/envs/default/bin/Rscript", "--vanilla", "-e", expression], check=True)


def main() -> int:
    if sys.argv[1:] == ["--verify-runtime"]:
        verify_runtime()
        return 0
    raise SystemExit("v2 intake is disabled for this renderer bootstrap")


if __name__ == "__main__":
    raise SystemExit(main())
