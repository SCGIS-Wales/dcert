"""Console script ``dcert-mcp-proxy``.

Kept free of third party imports so that a missing ``proxy`` extra produces one
clear line instead of a traceback.
"""

from __future__ import annotations

import sys


def main() -> None:
    """Run the proxy command, or explain how to install what it needs."""
    from dcert_mcp import PROXY_EXTRA_MODULES, missing_extra_message

    try:
        from dcert_mcp.cli import main as run
    except ModuleNotFoundError as exc:
        root = (exc.name or "").split(".")[0]
        if root not in PROXY_EXTRA_MODULES:
            raise
        sys.stderr.write(f"Error: {missing_extra_message(root)}\n")
        sys.exit(1)
    run()


if __name__ == "__main__":
    main()
