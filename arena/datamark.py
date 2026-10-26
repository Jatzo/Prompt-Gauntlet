"""Untrusted text, quoted for a model: delimited and datamarked (Spotlighting).

The markers are hygiene, not the safeguard: words are joined with `^`, so a forged end marker inside
the text cannot keep its spaces, and the nonce depends on the seed and the text. The detector keeps
its own copy beside its scorer, since only the Judge may run that module.
"""

import hashlib


def quote(text: str, seed: int) -> str:
    nonce = hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()[:12]
    marked = "^".join(text.split())
    return f"<<<DATA {nonce}>>>\n{marked}\n<<<END DATA {nonce}>>>"
