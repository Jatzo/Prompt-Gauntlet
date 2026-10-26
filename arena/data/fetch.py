"""Downloads the approved data sources at their pinned revisions, with a SHA-256 manifest.

Files land in `private/data/raw/<source>/` (gitignored) and `manifest.json` records each file's URL,
hash and size. A file that no longer matches its hash stops the build instead of quietly changing
the data. `HF_TOKEN`, when set, is sent to huggingface.co only, for gated datasets.
"""

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

MANIFEST = "manifest.json"
_CHUNK = 1 << 20
# The only host HF_TOKEN is ever sent to.
_HF_HOST = "huggingface.co"


@dataclass(frozen=True)
class FetchedFile:
    path: str
    url: str


class ChangedSource(RuntimeError):
    """A fetched file no longer matches the hash recorded when it was first fetched."""


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            sha.update(chunk)
    return sha.hexdigest()


def _manifest(raw_dir: Path) -> dict:
    path = raw_dir / MANIFEST
    return json.loads(path.read_text()) if path.exists() else {}


def _save(raw_dir: Path, manifest: dict) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    staged = raw_dir / f"{MANIFEST}.part"
    staged.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    staged.replace(raw_dir / MANIFEST)


def verify(raw_dir: Path, source: str, files: Sequence[FetchedFile]) -> list[str]:
    """The paths not fetched yet. Raises when a fetched file differs from its recorded hash."""
    manifest = _manifest(raw_dir)
    missing = []
    for file in files:
        key, target = f"{source}/{file.path}", raw_dir / source / file.path
        entry = manifest.get(key)
        if not target.exists() or entry is None or entry["url"] != file.url:
            missing.append(file.path)
        elif _digest(target) != entry["sha256"]:
            raise ChangedSource(f"{key} no longer matches its recorded SHA-256. Nothing was built.")
    return missing


Opener = Callable[[urllib.request.Request], object]


def _open(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=120)  # noqa: S310


def _download(url: str, target: Path, token: str | None, opener: Opener) -> None:
    parts = urllib.parse.urlsplit(url)
    # Pinned https URLs only: never a file: path or another scheme from an edited sources.toml.
    if parts.scheme != "https":
        raise ValueError(f"Only https sources are fetched, not {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "prompt-gauntlet-data-fetch"})  # noqa: S310
    if token and parts.hostname == _HF_HOST:
        request.add_header("Authorization", f"Bearer {token}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(target.name + ".part")
    with opener(request) as response, staged.open("wb") as out:
        while chunk := response.read(_CHUNK):
            out.write(chunk)
    staged.replace(target)


def fetch_all(
    raw_dir: Path,
    sources: Mapping[str, Sequence[FetchedFile]],
    *,
    token: str | None = None,
    opener: Opener = _open,
) -> list[tuple[str, str]]:
    """Fetch every file not already present, as (source/path, outcome) pairs. A file present with
    a changed hash, or a refetch that differs from the recorded hash, raises `ChangedSource`."""
    manifest = _manifest(raw_dir)
    results = []
    for source, files in sources.items():
        for file in files:
            key, target = f"{source}/{file.path}", raw_dir / source / file.path
            entry = manifest.get(key)
            # A new URL is a new pin, chosen on purpose: fetch it fresh and record its hash.
            expected = entry["sha256"] if entry and entry["url"] == file.url else None
            if expected and target.exists():
                if _digest(target) != expected:
                    raise ChangedSource(f"{key} no longer matches its recorded SHA-256.")
                results.append((key, "present"))
                continue
            try:
                _download(file.url, target, token, opener)
            except urllib.error.HTTPError as error:
                gated = (
                    error.code in (401, 403)
                    and urllib.parse.urlsplit(file.url).hostname == _HF_HOST
                )
                outcome = "refused: gated, set HF_TOKEN" if gated else f"failed: HTTP {error.code}"
                results.append((key, outcome))
                continue
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
                results.append((key, f"failed: {error}"))
                continue
            digest = _digest(target)
            if expected and digest != expected:
                target.unlink()
                raise ChangedSource(f"{key} changed at its pinned URL. The new copy was removed.")
            manifest[key] = {"url": file.url, "sha256": digest, "bytes": target.stat().st_size}
            # Saved after each file, so a run stopped halfway keeps what it fetched.
            _save(raw_dir, manifest)
            results.append((key, "fetched"))
    return results
