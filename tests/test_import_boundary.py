"""Agents may not reach the Judge, the databases or dynamic imports, checked by reading their AST.

The allowed route to memory is the public API of `arena.memory.memory`. Everything else an agent
needs comes through the dispatcher.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "arena" / "agents"
BAD_FIXTURE = ROOT / "tests" / "fixtures" / "bad_agent.py"

FORBIDDEN_MODULES = ("arena.judge", "arena.judge_client", "arena.db", "sqlite3", "importlib")
MEMORY_API = "arena.memory.memory"


def _forbidden(module: str) -> bool:
    return any(module == name or module.startswith(name + ".") for name in FORBIDDEN_MODULES)


def violations(source: str, package: str = "arena.agents") -> list[str]:
    """Every boundary break in one module's source, as readable strings."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _forbidden(alias.name) or _memory_internal(alias.name):
                    found.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = _resolve(node, package)
            names = [alias.name for alias in node.names]
            targets = [module] + [f"{module}.{name}" for name in names]
            if any(_forbidden(target) for target in targets):
                found.append(f"from {module} import {', '.join(names)}")
            elif any(
                _memory_internal(target) for target in targets[1:] if module == "arena.memory"
            ):
                found.append(f"from {module} import {', '.join(names)}")
            elif module == MEMORY_API and any(name.startswith("_") for name in names):
                found.append(f"from {module} import {', '.join(names)}")
            elif _memory_internal(module):
                found.append(f"from {module} import {', '.join(names)}")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "__import__":
                found.append("__import__()")
    return found


def _memory_internal(module: str) -> bool:
    return module.startswith("arena.memory.") and not (
        module == MEMORY_API or module.startswith(MEMORY_API + ".")
    )


def _resolve(node: ast.ImportFrom, package: str) -> str:
    if not node.level:
        return node.module or ""
    base = package.split(".")[: len(package.split(".")) - node.level + 1]
    return ".".join(base + ([node.module] if node.module else []))


def test_the_agent_package_has_modules_to_scan():
    assert {path.stem for path in AGENTS.glob("*.py")} >= {
        "ceo",
        "researcher",
        "attacker",
        "defender",
    }


@pytest.mark.parametrize("path", sorted(AGENTS.rglob("*.py")), ids=lambda p: p.name)
def test_no_agent_module_crosses_the_boundary(path):
    assert violations(path.read_text()) == []


def test_the_checker_catches_every_break_in_the_bad_fixture():
    found = violations(BAD_FIXTURE.read_text())
    assert found == [
        "import importlib",
        "import sqlite3",
        "import arena.judge.process",
        "from arena import db",
        "from arena.judge_client import JudgeClient",
        "from arena.memory import briefing",
        "from arena.memory.memory import _WORD",
        "from arena.judge import store",
        "__import__()",
    ]


@pytest.mark.parametrize(
    "source",
    [
        "from arena.memory.memory import Memory",
        "from arena import dispatcher",
        "from arena.schemas import CEOPlan",
        "import json",
    ],
)
def test_the_allowed_routes_pass(source):
    assert violations(source) == []


# The executors the Judge drives: everything reaches them as arguments, so they need no storage,
# no environment and no Judge internals.
EXECUTORS = [
    *sorted((ROOT / "arena" / "detector").glob("*.py")),
    *sorted((ROOT / "arena" / "target").glob("*.py")),
    ROOT / "arena" / "simulated.py",
    ROOT / "arena" / "sim_profiles.py",
]
EXECUTOR_FORBIDDEN = ("arena.judge", "sqlite3", "os")
# Only the Judge and the executors themselves may run detectors and target episodes.
SCORING = ("arena.detector.scorer", "arena.target.app", "arena.target.arms")


def _imports(source: str) -> list[str]:
    names = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names += [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
    return names


def _writes_files(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                found.append("open()")
            if isinstance(func, ast.Attribute) and func.attr in (
                "write_text",
                "write_bytes",
                "open",
            ):
                found.append(f".{func.attr}()")
    return found


@pytest.mark.parametrize("path", EXECUTORS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_an_executor_touches_no_storage_and_no_judge_internals(path):
    source = path.read_text()
    bad = [
        name
        for name in _imports(source)
        if any(name == f or name.startswith(f + ".") for f in EXECUTOR_FORBIDDEN)
    ]
    assert bad == [] and _writes_files(source) == []


def test_only_the_judge_and_executors_run_detectors_and_episodes():
    allowed = {path.resolve() for path in EXECUTORS}
    offenders = []
    for path in (ROOT / "arena").rglob("*.py"):
        if "judge" in path.relative_to(ROOT / "arena").parts or path.resolve() in allowed:
            continue
        for name in _imports(path.read_text()):
            if any(name == s or name.startswith(s + ".") for s in SCORING):
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {name}")
    assert offenders == []
