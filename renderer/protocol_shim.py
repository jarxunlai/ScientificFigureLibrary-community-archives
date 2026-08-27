#!/opt/sfl/.pixi/envs/default/bin/python
"""Narrow ``/bin/sh -c`` protocol broker for the reviewed mixed helper.

This file is deliberately not a command shell.  R's Unix ``system2()`` always
asks ``/bin/sh -c`` to start even a fixed absolute executable.  The broker
decodes only that argv-shaped command string, rejects shell control and
redirection syntax, and directly execs the fixed helper with the fixed Python
runtime.  Every other request exits silently with status 126.
"""

from __future__ import annotations

import os
import shlex
import sys
import unicodedata
from pathlib import PurePosixPath


PYTHON = "/opt/sfl/.pixi/envs/default/bin/python"
RSCRIPT = "/opt/sfl/.pixi/envs/default/bin/Rscript"
MIXED_HELPER = "/opt/sfl/mixed_helper.py"
REJECTED = 126
MAX_COMMAND_CHARACTERS = 65536
SHELL_PUNCTUATION = "();<>|&$`"
SAFE_ENV_KEYS = frozenset({"LANG", "LC_ALL", "TZ"})


def _canonical_python_helper(value: str) -> bool:
    if (
        not value.startswith("payload/code/")
        or not value.endswith(".py")
        or value == "payload/code/render.py"
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        return False
    parts = PurePosixPath(value).parts
    return (
        len(parts) >= 3
        and parts[:2] == ("payload", "code")
        and all(part not in {"", ".", ".."} for part in parts)
        and PurePosixPath(*parts).as_posix() == value
    )


def _tokens(command: str) -> list[str] | None:
    if (
        not command
        or len(command) > MAX_COMMAND_CHARACTERS
        or any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in command)
    ):
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=SHELL_PUNCTUATION)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        result = list(lexer)
    except ValueError:
        return None
    # Quoted punctuation may also produce one of these tokens.  Rejecting it is
    # intentional: the supported protocol never needs a control-only argument.
    if any(token and all(character in SHELL_PUNCTUATION for character in token) for token in result):
        return None
    return result


def parse_allowed_command(arguments: list[str]) -> list[str] | None:
    """Return helper arguments only for the exact reviewed ``-c`` protocol."""
    if len(arguments) != 3 or arguments[1] != "-c":
        return None
    command = _tokens(arguments[2])
    if (
        command is None
        or len(command) < 3
        or command[0] != MIXED_HELPER
        or command[1] != "--helper"
        or not _canonical_python_helper(command[2])
        or (len(command) > 3 and command[3] != "--")
    ):
        return None
    # A literal ``--`` is mandatory before helper-owned arguments.  Keeping it
    # in argv makes argparse stop interpreting a second ``--helper`` as an
    # override of the broker-validated Python helper identity.
    return command[1:]


def safe_environment() -> dict[str, str]:
    """Return the same closed environment used by the future intake runner."""
    environment = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
    environment.update(
        {
            "HOME": "/nonexistent",
            "PATH": "/opt/sfl/.pixi/envs/default/bin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "R_ENVIRON_USER": "/nonexistent",
            "R_PROFILE_USER": "/nonexistent",
            "R_HISTFILE": "/nonexistent",
            "MPLCONFIGDIR": "/tmp/sfl-matplotlib",
            "SFL_MIXED_HELPER_RUNNER": MIXED_HELPER,
            "SFL_PYTHON": PYTHON,
            "SFL_RSCRIPT": RSCRIPT,
        }
    )
    return environment


def main() -> int:
    helper_arguments = parse_allowed_command(sys.argv)
    if (
        helper_arguments is None
        or not os.path.isfile(MIXED_HELPER)
        or os.path.islink(MIXED_HELPER)
    ):
        return REJECTED
    try:
        os.execve(
            PYTHON,
            [PYTHON, "-I", "-B", MIXED_HELPER, *helper_arguments],
            safe_environment(),
        )
    except OSError:
        return REJECTED
    return REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
