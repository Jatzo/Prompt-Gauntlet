"""One adapter per source: its fetched files to `Raw` rows. `finish` turns rows into samples.

Every file is data, never code: AgentDojo's Python files are parsed with `ast` and never imported,
and the archives are read member by member without extracting anything to disk. An adapter that
finds nothing where its source's format promised rows raises `SourceFormatChanged`.
"""

import ast
import email
import email.errors
import email.policy
import hashlib
import json
import tarfile
from collections.abc import Callable, Iterator
from pathlib import Path

from arena.data.sources import Raw, Source


class SourceFormatChanged(RuntimeError):
    """A source file no longer has the shape its adapter reads."""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _parquet(path: Path, columns: list[str]) -> list[dict]:
    import pyarrow.parquet as pq  # the `data` extra

    return pq.read_table(path, columns=columns).to_pylist()


def _nonempty(rows: list[Raw], where: Path) -> list[Raw]:
    if not rows:
        raise SourceFormatChanged(f"{where} held no rows in the expected format.")
    return rows


def deepset(folder: Path, source: Source) -> Iterator[Raw]:
    for name in ("train.parquet", "test.parquet"):
        for row in _parquet(folder / name, ["text", "label"]):
            label = "attack" if row["label"] == 1 else "benign"
            yield Raw(row["text"], _digest(row["text"]), label=label, category="instructions")


def bipia(folder: Path, source: Source) -> Iterator[Raw]:
    """Attack instruction lists only, by category: `{"Task Automation": ["...", ...], ...}`."""
    for name in ("text_attack_train", "text_attack_test", "code_attack_train", "code_attack_test"):
        kind = name.split("_")[0]
        groups = json.loads((folder / f"{name}.json").read_text(encoding="utf-8"))
        rows = [
            Raw(text, f"{kind}-{category}")
            for category, texts in groups.items()
            for text in texts
            if isinstance(text, str)
        ]
        yield from _nonempty(rows, folder / f"{name}.json")


def injecagent(folder: Path, source: Source) -> Iterator[Raw]:
    """Each attacker instruction placed in one user case's tool response, as the paper's base and
    enhanced settings. The user case is picked from the instruction's hash, so it is stable."""
    users = [
        json.dumps(case["Tool Response Template"])
        for case in _jsonl(folder / "user_cases.jsonl")
        if "<Attacker Instruction>" in json.dumps(case["Tool Response Template"])
    ]
    _nonempty([Raw(u, "") for u in users], folder / "user_cases.jsonl")
    prefix = source.options["enhanced_prefix"]
    # Direct harm asks for an action; data stealing sends the user's data out.
    for setting, impact in (("dh", "unauthorised_action"), ("ds", "data_theft")):
        cases = _jsonl(folder / f"attacker_cases_{setting}.jsonl")
        for index, case in enumerate(cases):
            instruction = case["Attacker Instruction"]
            template = users[int(_digest(instruction), 16) % len(users)]
            for injected in (instruction, prefix + instruction):
                # The slot sits inside a JSON string, so the text goes in JSON-escaped.
                text = template.replace("<Attacker Instruction>", json.dumps(injected)[1:-1])
                yield Raw(text, f"{setting}-{index}", impact_class=impact)


def _resolve(node: ast.expr, names: dict[str, str]) -> str | None:
    """A string constant, or an f-string or `+` built only from string names already seen."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                plain = part.conversion == -1 and part.format_spec is None
                if not (plain and isinstance(part.value, ast.Name) and part.value.id in names):
                    return None
                parts.append(names[part.value.id])
            else:
                parts.append(_resolve(part, names))
        return None if None in parts else "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _resolve(node.left, names), _resolve(node.right, names)
        return None if left is None or right is None else left + right
    return None


def _strings(body: list[ast.stmt], names: dict[str, str]) -> dict[str, str]:
    for statement in body:
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign) and statement.value is not None
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name):
                value = _resolve(statement.value, names)
                if value is not None:
                    names[target.id] = value
    return names


def _classes(path: Path) -> Iterator[tuple[ast.ClassDef, dict[str, str]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module = _strings(tree.body, {})
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            yield node, _strings(node.body, dict(module))


def _super_init_string(cls: ast.ClassDef) -> str | None:
    for node in ast.walk(cls):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__init__"
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
            and node.args
        ):
            return _resolve(node.args[0], {})
    return None


def _templates(folder: Path, wanted: list[str]) -> dict[str, str]:
    found = {}
    for name in ("baseline_attacks.py", "important_instructions_attacks.py"):
        for cls, scope in _classes(folder / name):
            template = scope.get("_JB_STRING") or _super_init_string(cls)
            if scope.get("name") in wanted and template:
                found[scope["name"]] = template
    missing = sorted(set(wanted) - set(found))
    if missing:
        raise SourceFormatChanged(f"AgentDojo attack templates not found: {', '.join(missing)}")
    return found


def agentdojo(folder: Path, source: Source) -> Iterator[Raw]:
    """Each injection goal in each named attack template, and each user task as benign text."""
    options = source.options
    templates = _templates(folder, options["attacks"])
    for suite in sorted(path.name for path in folder.iterdir() if path.is_dir()):
        goals = [
            (cls.name, scope["GOAL"])
            for cls, scope in _classes(folder / suite / "injection_tasks.py")
            if "GOAL" in scope
        ]
        _nonempty([Raw(goal, "") for _, goal in goals], folder / suite / "injection_tasks.py")
        for task, goal in goals:
            for template in templates.values():
                text = (
                    template.replace("{goal}", goal)
                    .replace("{user}", options["user"])
                    .replace("{model}", options["model"])
                )
                yield Raw(text, f"{suite}-{task}", label="attack")
        for cls, scope in _classes(folder / suite / "user_tasks.py"):
            if "PROMPT" in scope:
                yield Raw(
                    scope["PROMPT"],
                    f"{suite}-{cls.name}",
                    label="benign",
                    channel="user",
                    category="instructions",
                )


def llmail(folder: Path, source: Source) -> Iterator[Raw]:
    """One JSON object keyed by the submitted email text. Rows the organisers' judge marked as no
    attack attempt are left out."""
    submissions = json.loads(
        (folder / "labelled_unique_submissions_phase2.json").read_text(encoding="utf-8")
    )
    for text, verdict in submissions.items():
        if str(verdict.get("attack_attempt", "True")) != "False":
            yield Raw(text, _digest(text))


def _email_body(raw: bytes) -> str | None:
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
        part = message.get_body(preferencelist=("plain",))
        body = part.get_content() if part is not None else ""
        subject = str(message.get("subject", ""))
    except (ValueError, LookupError, UnicodeError, email.errors.MessageError):
        # A malformed message in a 0.5-million-message archive is skipped, not fatal.
        return None
    # Keep what this sender wrote: stop at the first quoted or forwarded message.
    for marker in ("-----Original Message-----", "----- Forwarded by", "\n>"):
        body = body.split(marker, 1)[0]
    return f"Subject: {subject}\n\n{body.strip()}" if body.strip() else None


def enron(folder: Path, source: Source) -> Iterator[Raw]:
    """A stable hash-picked subset of the maildir archive, read in one pass, never extracted.
    Each sample's group is its mailbox, so one person's mail stays in one partition."""
    every = source.options["sample_every"]
    with tarfile.open(folder / "enron_mail_20150507.tar.gz", mode="r|gz") as archive:
        for member in archive:
            if not member.isfile() or int(_digest(member.name), 16) % every:
                continue
            handle = archive.extractfile(member)
            body = _email_body(handle.read()) if handle else None
            if body and len(body) >= 80:
                parts = member.name.split("/")
                yield Raw(body, parts[1] if len(parts) > 2 else "unknown")


def dolly(folder: Path, source: Source) -> Iterator[Raw]:
    for row in _jsonl(folder / "databricks-dolly-15k.jsonl"):
        yield Raw(row["instruction"], _digest(row["instruction"]))


def _passages(markdown: str) -> Iterator[str]:
    """Prose paragraphs only: code blocks, headings, tables, images and HTML are dropped."""
    fenced = False
    paragraph: list[str] = []
    for line in [*markdown.splitlines(), ""]:
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        if not line.strip():
            if paragraph:
                yield " ".join(paragraph)
                paragraph = []
        elif not line.lstrip().startswith(("#", "|", "!", "<")):
            paragraph.append(line.strip())


def owasp(folder: Path, source: Source) -> Iterator[Raw]:
    found = []
    with tarfile.open(folder / "cheatsheets.tar.gz", mode="r|gz") as archive:
        for member in archive:
            parts = member.name.split("/")
            if member.isfile() and len(parts) == 3 and parts[1] == "cheatsheets":
                handle = archive.extractfile(member)
                if handle is None or not parts[2].endswith(".md"):
                    continue
                sheet = parts[2].removesuffix(".md")
                found += [
                    Raw(passage, sheet)
                    for passage in _passages(handle.read().decode("utf-8", "replace"))
                    if len(passage) >= 200
                ]
    yield from _nonempty(found, folder / "cheatsheets.tar.gz")


def tatoeba(folder: Path, source: Source) -> Iterator[Raw]:
    """Tab-separated: source language, target language, source sentence, target sentence. The
    sentence that is not English is kept."""
    for file in source.files:
        rows = []
        for line in (folder / file.path).read_text(encoding="utf-8").splitlines():
            fields = line.split("\t")
            if len(fields) == 4:
                text = fields[2] if fields[0] != "eng" else fields[3]
                rows.append(Raw(text, _digest(text)))
        yield from _nonempty(rows, folder / file.path)


def codesearchnet(folder: Path, source: Source) -> Iterator[Raw]:
    for file in source.files:
        for row in _parquet(folder / file.path, ["repository_name", "whole_func_string"]):
            yield Raw(row["whole_func_string"], row["repository_name"])


ADAPTERS: dict[str, Callable[[Path, Source], Iterator[Raw]]] = {
    "deepset": deepset,
    "bipia": bipia,
    "injecagent": injecagent,
    "agentdojo": agentdojo,
    "llmail": llmail,
    "enron": enron,
    "dolly": dolly,
    "owasp": owasp,
    "tatoeba": tatoeba,
    "codesearchnet": codesearchnet,
}
