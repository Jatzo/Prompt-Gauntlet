"""SHA-256 over text files with line endings normalised.

A Windows checkout can turn LF into CRLF. Hashing the LF form means a pin taken on Linux still
matches there, so a line-ending change never looks like tampering and real tampering always does.
"""

import hashlib
from pathlib import Path


def sha256_text(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def read_pin(path: Path) -> str:
    """The first token of a `sha256sum`-style line: `<hex>  <name>`."""
    return path.read_text().split()[0]
