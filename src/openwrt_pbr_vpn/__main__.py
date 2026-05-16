"""Entry point for `python -m openwrt_pbr_vpn`.

Must propagate the CLI's return code so callers (especially the Next.js UI
that wraps execFile and reads exitCode) get a non-zero on failure.
"""

import sys

from openwrt_pbr_vpn.cli import main

if __name__ == "__main__":
    sys.exit(main())
