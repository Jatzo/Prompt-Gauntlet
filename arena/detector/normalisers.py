"""The fixed normaliser registry. The Defender may choose and order these, never add to them.

Decoders append what they decode rather than replacing the text, so a rule can match either the
original or the decoded form.
"""

import base64
import binascii
import codecs
import re
import typing
import unicodedata
from collections.abc import Callable

from arena.schemas import NormaliserName

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_SPACE = re.compile(r"\s+")
_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Common look-alikes from Cyrillic and Greek, folded to Latin.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "α": "a",
        "ο": "o",
        "ν": "v",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
    }
)
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)


def _decode_base64(text: str) -> str:
    decoded = []
    for token in _BASE64_TOKEN.findall(text):
        try:
            value = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if value.isprintable():
            decoded.append(value)
    return text if not decoded else f"{text}\n{' '.join(decoded)}"


REGISTRY: dict[str, Callable[[str], str]] = {
    "unicode_nfkc": lambda text: unicodedata.normalize("NFKC", text),
    "lowercase": str.lower,
    "strip_zero_width": lambda text: _ZERO_WIDTH.sub("", text),
    "collapse_whitespace": lambda text: _SPACE.sub(" ", text).strip(),
    "fold_homoglyphs": lambda text: text.translate(_HOMOGLYPHS),
    "fold_leetspeak": lambda text: f"{text}\n{text.translate(_LEET)}",
    "decode_base64": _decode_base64,
    "decode_rot13": lambda text: f"{text}\n{codecs.decode(text, 'rot13')}",
}

# The registry and the schema's list of names are one list: a mismatch fails at import.
if set(REGISTRY) != set(typing.get_args(NormaliserName)):
    raise RuntimeError("The normaliser registry and NormaliserName disagree.")


def normalise(text: str, names: list[str]) -> str:
    for name in names:
        text = REGISTRY[name](text)
    return text
