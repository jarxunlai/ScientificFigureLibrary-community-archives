"""Shared executable-deny policy for bootstrap sanitization and rootfs audit."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


SHELL_NAMES = frozenset({"sh", "bash", "dash", "ash", "zsh", "fish", "csh", "tcsh", "ksh"})
FORBIDDEN_EXACT = frozenset(
    {
        *SHELL_NAMES,
        "busybox", "toybox",
        "apt", "apt-get", "apt-cache", "apt-config", "apt-key", "apk", "dnf",
        "yum", "rpm", "pacman", "dpkg", "conda", "mamba", "micromamba", "pixi",
        "pip", "pip3", "easy_install", "install", "npm", "npx", "yarn", "pnpm",
        "gem", "cargo", "rustup",
        "curl", "wget", "aria2c", "ftp", "sftp", "scp", "ssh", "git", "hg", "svn",
        "make", "gmake", "cmake", "ninja", "meson", "cc", "c++", "gcc", "g++",
        "clang", "clang++", "ld", "as", "ar", "ranlib", "strip", "objcopy",
        "objdump", "nm", "patch", "autoconf", "automake", "libtool", "pkg-config",
    }
)
FORBIDDEN_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?:^|[-_.])(?:ba|da|a|z|fi|c|tc|k)?sh(?:[-_.]?[0-9].*)?$",
        r"^(?:apt|dpkg|curl|wget|git|pip|conda|mamba|pixi)(?:[-_.0-9].*)?$",
        r"^(?:easy_install|npm|npx|yarn|pnpm|cargo|rustup)(?:[-_.0-9].*)?$",
        r"^(?:gcc|g\+\+|clang\+\+|clang|cmake|ninja|meson|make|gmake)(?:[-_.0-9].*)?$",
        r"^.*-(?:gcc|g\+\+|cc|c\+\+|clang|clang\+\+|ld|as|ar|ranlib|strip|objcopy|objdump|nm)$",
        r"^(?:ld\.(?:bfd|gold|lld)|ranlib|strip|objcopy|objdump|nm)(?:[-_.0-9].*)?$",
    )
)
FORBIDDEN_PYTHON_COMPONENTS = (
    re.compile(r"^pip(?:-[^/]+\.dist-info)?$", re.IGNORECASE),
    re.compile(r"^setuptools(?:-[^/]+\.dist-info)?$", re.IGNORECASE),
    re.compile(r"^ensurepip$", re.IGNORECASE),
)


def forbidden_tool_name(name: str) -> bool:
    folded = name.casefold()
    return folded in FORBIDDEN_EXACT or any(pattern.fullmatch(folded) for pattern in FORBIDDEN_PATTERNS)


def forbidden_python_path(path: str) -> bool:
    wrapped = f"/{path}/"
    if "/site-packages/" not in wrapped and "/lib/python" not in wrapped:
        return False
    return any(
        pattern.fullmatch(component)
        for component in PurePosixPath(path).parts
        for pattern in FORBIDDEN_PYTHON_COMPONENTS
    )
