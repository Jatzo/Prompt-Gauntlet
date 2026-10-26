"""Static ReDoS checks for detector rules (PLAN section 12a.5).

A nested quantifier, such as `(a+)+` or `(\\w*)*`, can take exponential time on a crafted input.
Such a rule is refused before it is ever run. Other slow patterns, such as overlapping alternations,
are caught at run time by the per-match timeout in `rules.py`.

The check walks the pattern rather than matching it with one regex, so that a `+` inside a character
class is not read as a quantifier and a quantifier inside a nested group still counts.
"""

import re

_BRACE = re.compile(r"\{(\d*)(,?)(\d*)\}")


class UnsafePattern(ValueError):
    pass


def _quantifier_at(pattern: str, i: int) -> tuple[str | None, int]:
    """The quantifier starting at `i`, if any, and the index after it and any lazy or possessive
    suffix. A `{` that is not a valid repeat is a literal in Python patterns."""
    if i < len(pattern) and pattern[i] in "*+?":
        kind, end = pattern[i], i + 1
    elif match := _BRACE.match(pattern, i):
        kind, end = match.group(0), match.end()
    else:
        return None, i
    if end < len(pattern) and pattern[end] in "?+":
        end += 1
    return kind, end


def _varies(kind: str) -> bool:
    """True when the quantifier can repeat a varying number of times, which is what makes nesting
    ambiguous. `?`, `{0,1}` and an exact count such as `{3}` do not."""
    if kind in "*+":
        return True
    if kind == "?":
        return False
    low, comma, high = _BRACE.match(kind).groups()
    if not comma:
        return False
    return high == "" or int(high) > max(int(low or 0), 1)


def _class_end(pattern: str, i: int) -> int:
    """The index after the character class opening at `i`."""
    j = i + 1
    if pattern.startswith("^", j):
        j += 1
    if pattern.startswith("]", j):
        j += 1
    while j < len(pattern):
        if pattern[j] == "\\":
            j += 2
        elif pattern[j] == "]":
            return j + 1
        else:
            j += 1
    return len(pattern)


def _has_nested_quantifier(pattern: str) -> bool:
    # One entry per open group: whether its body, nested groups included, holds a repeat.
    quantified: list[bool] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "(":
            quantified.append(False)
            # The `?` of `(?:`, `(?P<name>` or a lookaround is not a quantifier.
            i += 2 if pattern.startswith("?", i + 1) else 1
            continue
        if char == ")":
            inner = quantified.pop() if quantified else False
            kind, i = _quantifier_at(pattern, i + 1)
            varies = kind is not None and _varies(kind)
            if inner and varies:
                return True
            if quantified and (inner or varies):
                quantified[-1] = True
            continue
        if char == "\\":
            i += 2
        elif char == "[":
            i = _class_end(pattern, i)
        else:
            i += 1
        kind, i = _quantifier_at(pattern, i)
        if kind is not None and _varies(kind) and quantified:
            quantified[-1] = True
    return False


def check_pattern(pattern: str) -> str:
    if _has_nested_quantifier(pattern):
        raise UnsafePattern(
            f"The rule {pattern!r} nests one quantifier inside another, which can take exponential "
            "time. Rewrite it without the outer repeat."
        )
    return pattern
