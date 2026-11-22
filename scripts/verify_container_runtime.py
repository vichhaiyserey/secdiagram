"""Exercise the installed minimal runtime and offline Studio launcher in Linux CI."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path

from secdiagram_core import studio


def main() -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is None or getuid() != 10001:
        raise RuntimeError("container must run as secdiagram (UID 10001)")
    bootstrap = ("pip", "ensurepip", "setuptools")
    present = [name for name in bootstrap if importlib.util.find_spec(name) is not None]
    if present:
        raise RuntimeError(f"build-only packages remain in runtime: {present}")
    with tempfile.TemporaryDirectory(prefix="secdiagram-runtime-") as tmp:
        root = Path(tmp)
        project = root / "project"
        project.mkdir()
        home = root / "studio"
        result = studio.install(studio.InstallOptions(home=home, project_root=project))
        if not result.venv_created or result.manifest["source_checkout"]:
            raise RuntimeError("Studio must create a private environment for a package install")
        if not studio.status(home)["healthy"]:
            raise RuntimeError("installed Studio failed health verification")
        probe = subprocess.run(
            [str(home / studio.VENV_DIRNAME / "bin/python"), "-I", "-c",
             "import importlib.util,json; print(json.dumps({name: importlib.util.find_spec(name) is not None for name in ('pip','setuptools')}))"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        if json.loads(probe.stdout) != {"pip": False, "setuptools": False}:
            raise RuntimeError("private Studio environment restored bootstrap packages")
        launcher = subprocess.run(
            [str(home / "bin/secdiagram-studio"), "--help"],
            check=True, capture_output=True, text=True, timeout=30, cwd=project,
        )
        if "usage: secdiagram-server " not in launcher.stdout or "--scan-root" not in launcher.stdout:
            raise RuntimeError("generated launcher did not reach the server CLI")
    print("Verified UID 10001, no bootstrap packages, offline private venv and Studio launcher")


if __name__ == "__main__":
    main()
