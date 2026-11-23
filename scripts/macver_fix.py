"""Startup patch for Macs where platform.mac_ver() returns '' (seen on some macOS 26 'Tahoe' setups).
pip (truststore) and uv crash on an empty macOS version. Loaded via a .pth file inside .venv only."""
import sys

if sys.platform == "darwin":
    import os
    import platform
    import subprocess

    _orig = platform.mac_ver

    def _mac_ver(release="", versioninfo=("", "", ""), machine=""):
        r = _orig(release, versioninfo, machine)
        if r[0]:
            return r
        v = ""
        try:
            v = subprocess.run(["/usr/bin/sw_vers", "-productVersion"], capture_output=True,
                               text=True, timeout=5).stdout.strip()
        except Exception:
            pass
        if not v:  # derive from the Darwin kernel: 20->11 ... 24->15, 25->26
            d = int(os.uname().release.split(".")[0])
            v = f"{d + 1 if d >= 25 else d - 9}.0"
        return (v, r[1], r[2] or machine or os.uname().machine)

    platform.mac_ver = _mac_ver
