#!/opt/sfl/.pixi/envs/default/bin/python
"""Shell-free replacement for the conda R_HOME/bin/R launcher."""

from __future__ import annotations

import os
import sys


PREFIX = "/opt/sfl/.pixi/envs/default"
R_HOME = f"{PREFIX}/lib/R"
R_EXECUTABLE = f"{R_HOME}/bin/exec/R"


def main() -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "R_HOME": R_HOME,
            "R_SHARE_DIR": f"{R_HOME}/share",
            "R_INCLUDE_DIR": f"{R_HOME}/include",
            "R_DOC_DIR": f"{R_HOME}/doc",
            "R_ARCH": "",
            "LD_LIBRARY_PATH": f"{R_HOME}/lib:{PREFIX}/lib",
        }
    )
    os.execve(R_EXECUTABLE, [R_EXECUTABLE, *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
