#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""make.fun entrypoint: hand the trial to the statically linked forge binary.

The harness runs `python3 -P -s /bot/main.py` at the repository root, with
MAKEFUN_ENV_URL and MAKEFUN_SHOP_TOKEN in the environment. The forge itself is
a single static Linux amd64 binary next to this file; it binds an ephemeral
port, POSTs {"port": N} to $MAKEFUN_ENV_URL/register, serves the four surfaces
(git smart HTTP, REST v3, GraphQL v4 and MCP) from one epoll event loop, and
polls GET $MAKEFUN_ENV_URL/done until the suite is over.

This launcher carries no logic of its own: it execs the binary so the trial
runs in one process, exactly as the lifecycle requires.
"""

import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(HERE, "forge")


def main() -> int:
    if not os.path.isfile(BINARY):
        sys.stderr.write("[entry] %s is missing from the repository\n" % BINARY)
        return 1
    mode = os.stat(BINARY).st_mode
    if not mode & stat.S_IXUSR:
        os.chmod(BINARY, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    try:
        os.execv(BINARY, [BINARY])
    except OSError as err:
        sys.stderr.write("[entry] exec %s failed: %s\n" % (BINARY, err))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
