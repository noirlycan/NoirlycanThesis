"""Verify the final Windows EXE, including its embedded UAC manifest."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pefile


def main() -> None:
    executable = Path(sys.argv[1]).resolve()
    with pefile.PE(str(executable)) as image:
        assert image.FILE_HEADER.Machine == 0x8664, "Expected Windows x64 executable"
        assert image.OPTIONAL_HEADER.Subsystem == 2, "Expected desktop/windowed executable"
        manifests = []
        for resource in image.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource.id != 24:  # RT_MANIFEST
                continue
            for name in resource.directory.entries:
                for language in name.directory.entries:
                    data = language.data.struct
                    manifests.append(image.get_data(data.OffsetToData, data.Size))
        assert any(b'requireAdministrator' in manifest for manifest in manifests), "Missing Administrator manifest"
    result = subprocess.run([str(executable), "--smoke-test"], timeout=60, check=False)
    assert result.returncode == 0, f"Packaged GUI/sensors/credentials check failed ({result.returncode})"
    print(f"Verified windowed x64 EXE, Administrator manifest, Tk, Frida hooks, signing and DPAPI: {executable}")


if __name__ == "__main__":
    main()
