"""Refuse to let private or runtime files into git.

The repo is public, so this runs in CI and as a pre-commit hook over everything git tracks or has
staged. It exits non-zero and names each offending path. If git itself cannot run, it fails rather
than passing, because a guard that silently did nothing would look the same as a clean result.
"""

import re
import subprocess
import sys

# PLAN.md section 12b.9, plus CLAUDE.md (kept private), .env files, and the data/test rule anchored
# so only the exact hash file is allowed. Case-insensitive: git on Linux is case-sensitive, so
# `VOICE.md` would otherwise slip past a rule written for `voice.md`.
FORBIDDEN = re.compile(
    r"^(private|runs)/"
    r"|\.db$"
    r"|(^|/)voice\.md$"
    r"|(^|/)CLAUDE\.md$"
    r"|(^|/)\.env(\.[^/]*)?$"
    r"|^data/test(?!\.sha256$)",
    re.IGNORECASE,
)

# Recorded model outputs can contain anything a model said. Only hand-written cassettes under
# tests/fixtures/ may be committed; record mode writes to runs/ or private/, both gitignored.
CASSETTE = re.compile(r"\.cassette\.jsonl$")
CASSETTE_HOME = "tests/fixtures/"


def forbidden_paths(paths: list[str]) -> list[str]:
    """Return every path that must not be tracked, in input order."""
    bad = []
    for path in paths:
        if FORBIDDEN.search(path):
            bad.append(path)
        elif CASSETTE.search(path) and not path.startswith(CASSETTE_HOME):
            bad.append(path)
    return bad


def tracked_paths() -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True, text=True)
    return [path for path in result.stdout.split("\0") if path]


def main() -> int:
    try:
        paths = tracked_paths()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Could not list tracked files, so nothing was checked: {error}", file=sys.stderr)
        return 2
    bad = forbidden_paths(paths)
    for path in bad:
        print(f"Must not be tracked: {path}", file=sys.stderr)
    if bad:
        print(
            "Remove these with `git rm --cached <path>` and keep them in private/.",
            file=sys.stderr,
        )
        return 1
    print(f"Tracked-files guard: {len(paths)} paths checked, none forbidden.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
