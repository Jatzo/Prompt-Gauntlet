"""Draws the README figures as static SVG, in a light and a dark version each.

Colours are the dashboard's role tokens (arena/static/index.html) for dark, and darker steps of the
same hues for light. Every number drawn comes from docs/run-record.md; none is computed here.
Usage: python3 make_figures.py OUT_DIR
"""

# Each drawing call keeps its coordinates and label on one line, so a figure reads top to
# bottom like the picture it draws.
# ruff: noqa: E501

import sys
from pathlib import Path
from xml.sax.saxutils import escape

THEMES = {
    "dark": {
        "ground": "#0c0916",
        "raised": "#1a1230",
        "line": "#3a2f57",
        "ink": "#ece9f4",
        "muted": "#a49cb8",
        "attacker": "#ff7b72",
        "defender": "#5ba8ec",
        "judge": "#c3abe8",
        "held": "#e9c46a",
        "ceo": "#c3abe8",
        "quiet": "#7a85a0",
        "live": "#3fbf8f",
    },
    "light": {
        "ground": "#ffffff",
        "raised": "#f5f3fa",
        "line": "#d6d0e4",
        "ink": "#1d1730",
        "muted": "#5c5672",
        "attacker": "#c2362f",
        "defender": "#1d6bb3",
        "judge": "#6b45b8",
        "held": "#8a5d00",
        "ceo": "#6b45b8",
        "quiet": "#5f6a85",
        "live": "#1f7a58",
    },
}
FONT = "'IBM Plex Sans', 'Segoe UI', system-ui, -apple-system, sans-serif"
MONO = "'IBM Plex Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace"


def text(x, y, s, c, size=13, weight=400, anchor="start", mono=False, opacity=1.0):
    family = MONO if mono else FONT
    return (
        f'<text x="{x}" y="{y}" fill="{c}" font-family="{family}" font-size="{size}" '
        f'font-weight="{weight}" text-anchor="{anchor}" opacity="{opacity}">{escape(s)}</text>'
    )


def box(x, y, w, h, t, accent, title, lines=(), dashed=False, tag=None):
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    out = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{t["raised"]}" '
        f'stroke="{accent}" stroke-width="1.5"{dash}/>',
        f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{accent}"/>',
        text(x + 16, y + 24, title, t["ink"], 14, 600),
    ]
    for i, line in enumerate(lines):
        out.append(text(x + 16, y + 44 + i * 17, line, t["muted"], 12))
    if tag:
        out.append(text(x + w - 12, y + 22, tag, accent, 11, 600, "end", mono=True))
    return "\n".join(out)


def arrow(x1, y1, x2, y2, c, label=None, lx=None, ly=None, dashed=False):
    dash = ' stroke-dasharray="4 4"' if dashed else ""
    out = [
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="1.5"'
        f' marker-end="url(#head)"{dash}/>'
    ]
    if label:
        out.append(text(lx, ly, label, c, 11, 400, "middle"))
    return "\n".join(out)


def tag_label(x, y, s, t):
    """A small label on the ground colour, so a line passing under it stays readable."""
    w = 7 * len(s) + 10
    return (
        f'<rect x="{x - w / 2}" y="{y - 12}" width="{w}" height="17" rx="4" fill="{t["ground"]}"/>'
        + text(x, y, s, t["muted"], 11, 400, "middle")
    )


def svg(w, h, t, body, title):
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{escape(title)}">
<title>{escape(title)}</title>
<defs><marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="{t["muted"]}"/></marker></defs>
<rect width="{w}" height="{h}" rx="12" fill="{t["ground"]}"/>
{body}
</svg>
"""


def architecture(t):
    b = [
        text(32, 44, "Architecture", t["ink"], 20, 700),
        text(
            32,
            66,
            "Agents propose. A separate Judge process measures. Only aggregates cross back.",
            t["muted"],
            13,
        ),
        box(
            32,
            96,
            260,
            120,
            t,
            t["ceo"],
            "CEO agent",
            [
                "reads a code-built briefing",
                "picks a focus from a shortlist",
                "writes hypothesis + prediction",
            ],
            tag="OPUS 5.5",
        ),
        box(
            32,
            232,
            260,
            92,
            t,
            t["attacker"],
            "Attacker",
            ["writes a batch of injections", "for the toy assistant"],
            tag="SONNET 5.5",
        ),
        box(
            32,
            340,
            260,
            92,
            t,
            t["defender"],
            "Defender",
            ["proposes one DetectorConfig", "patch: data only, no code"],
            tag="SONNET 5.5",
        ),
        box(
            32,
            448,
            260,
            76,
            t,
            t["quiet"],
            "Researcher",
            ["curated sources only"],
            dashed=True,
            tag="PLANNED",
        ),
        box(
            336,
            96,
            240,
            112,
            t,
            t["quiet"],
            "Dispatcher + llm.py",
            [
                "role tool allowlists",
                "forced-JSON, schema-checked",
                "raw output stored by (cycle, step)",
            ],
        ),
        box(
            336,
            232,
            240,
            112,
            t,
            t["ceo"],
            "Memory (SQLite)",
            [
                "all writes through memory.py",
                "lessons, backlog, predictions",
                "agent text datamarked on read",
            ],
        ),
        box(336, 368, 240, 76, t, t["quiet"], "Dashboard", ["read-only feed: codes and counts"]),
    ]
    # Trust boundary
    b.append(
        f'<line x1="618" y1="88" x2="618" y2="540" stroke="{t["held"]}" stroke-width="1.5" stroke-dasharray="6 5"/>'
    )
    b.append(text(626, 104, "TRUST BOUNDARY", t["held"], 11, 600, mono=True))
    b.append(text(626, 120, "JSON lines over stdin/stdout", t["muted"], 11))
    b += [
        box(
            660,
            136,
            268,
            132,
            t,
            t["judge"],
            "Judge process",
            [
                "owns the data partitions",
                "eval cache, statistics, keep rule",
                "hash-pinned; agents cannot reach it",
                "returns aggregates only",
            ],
        ),
        box(
            660,
            288,
            268,
            96,
            t,
            t["defender"],
            "Detector",
            ["normalisers, capped regex rules,", "LLM classifier (Haiku 5.5)"],
        ),
        box(
            660,
            404,
            268,
            120,
            t,
            t["judge"],
            "Toy assistant + checker",
            [
                "mock email, docs, web, send tools",
                "dummy canary, example.invalid",
                "Sonnet 5.5 strong / Haiku 5.5 weak",
            ],
        ),
        # Every agent call goes through the dispatcher.
        arrow(292, 156, 336, 156, t["muted"]),
        arrow(292, 278, 336, 180, t["muted"]),
        arrow(292, 386, 336, 196, t["muted"]),
        arrow(456, 208, 456, 232, t["muted"]),
        arrow(456, 344, 456, 368, t["muted"]),
        arrow(576, 170, 660, 170, t["muted"]),
        arrow(660, 240, 576, 290, t["muted"]),
        tag_label(618, 158, "candidates", t),
        tag_label(618, 283, "aggregates", t),
        arrow(794, 268, 794, 288, t["muted"]),
        arrow(794, 384, 794, 404, t["muted"]),
    ]
    return svg(
        960,
        560,
        t,
        "\n".join(b),
        "Prompt Gauntlet architecture: agents, memory and the separate Judge process",
    )


def cycle(t):
    steps = [
        ("1  Plan", t["ceo"], ["CEO picks a focus,", "predicts the change"]),
        ("2  Attack", t["attacker"], ["Attacker writes", "a batch"]),
        ("3  Validity", t["judge"], ["Judge plays each one", "with no defence"]),
        ("4  Defend", t["defender"], ["Defender sees half", "of the evasions"]),
        ("5  Keep rule", t["judge"], ["fold 1 vs parent;", "held-back half tests it"]),
        ("6  Post-mortem", t["ceo"], ["lessons with evidence", "go to memory"]),
    ]
    b = [
        text(32, 44, "One cycle", t["ink"], 20, 700),
        text(
            32,
            66,
            "Each cycle is one experiment. Every step's raw output is stored before it is used, so a killed run resumes.",
            t["muted"],
            13,
        ),
    ]
    w, gap, y = 136, 20, 104
    for i, (title, c, lines) in enumerate(steps):
        x = 32 + i * (w + gap)
        b.append(box(x, y, w, 96, t, c, title, lines))
        if i < len(steps) - 1:
            b.append(arrow(x + w, y + 48, x + w + gap, y + 48, t["muted"]))
    # Loop back
    last = 32 + 5 * (w + gap) + w / 2
    b.append(
        f'<path d="M{last} 200 V236 H100 V204" fill="none" stroke="{t["muted"]}" stroke-width="1.5" stroke-dasharray="4 4" marker-end="url(#head)"/>'
    )
    b.append(text(480, 254, "next cycle reads the updated briefing", t["muted"], 11, 400, "middle"))
    b.append(
        text(
            32,
            290,
            "Held back: half of the attacks that got past are never shown to the Defender, to test whether a fix generalises.",
            t["held"],
            12,
        )
    )
    b.append(
        text(
            32,
            310,
            "Controls: a placebo patch generator and a scripted hill-climb run through the same keep rule.",
            t["muted"],
            12,
        )
    )
    return svg(
        960,
        330,
        t,
        "\n".join(b),
        "One cycle: plan, attack, validity check, defend, keep rule, post-mortem",
    )


def ladder(t):
    # docs/run-record.md, "The same pass under the current rule" and "Rung 3": attacks that reached
    # the attacker, 2 trials each. Every count is 0, so each row draws an empty track.
    rungs = [
        (
            "Rung 0",
            "Claude Sonnet 5.5, task tools only",
            "0 of 2,331",
            "4,662 episodes, 42 ended by a refusal",
        ),
        (
            "Rung 1",
            "Claude Haiku 5.5, task tools only",
            "0 of 2,331",
            "4,662 episodes, 43 ended by a refusal",
        ),
        (
            "Rung 2",
            "Claude Haiku 5.5, every tool, risky placements",
            "0 of 2,331",
            "4,662 episodes, 30 ended by a refusal",
        ),
        (
            "Rung 3",
            "Gemma 4 12B, local, task tools only",
            "0 of 1,000 (dev)",
            "2,000 episodes, run on dev only",
        ),
    ]
    x0, width = 330, 520
    b = [
        text(32, 44, "Public attacks against the undefended assistant", t["ink"], 18, 700),
        text(
            32,
            66,
            "Paired attacks from BIPIA, InjecAgent, AgentDojo and LLMail-Inject, 2 trials each.",
            t["muted"],
            13,
        ),
    ]
    for i, (name, desc, fired, note) in enumerate(rungs):
        y = 96 + i * 72
        b.append(text(32, y + 16, name, t["ink"], 14, 600))
        b.append(text(32, y + 34, desc, t["muted"], 12))
        b.append(
            f'<rect x="{x0}" y="{y}" width="{width}" height="26" rx="4" fill="none" stroke="{t["line"]}" stroke-width="1"/>'
        )
        b.append(
            f'<line x1="{x0}" y1="{y}" x2="{x0}" y2="{y + 26}" stroke="{t["attacker"]}" stroke-width="3"/>'
        )
        b.append(text(x0 + 14, y + 18, f"{fired} reached the attacker", t["ink"], 13, 600))
        b.append(text(x0, y + 44, note, t["muted"], 11))
    b.append(
        text(
            32,
            404,
            "Reached the attacker: the canary leaked, a message went to the attacker, or a fetched URL named the attacker.",
            t["muted"],
            12,
        )
    )
    b.append(
        text(
            32,
            422,
            "Refused episodes count as not fired. On rungs 0, 1 and 3 only 2 of the 10 tasks can send a message.",
            t["muted"],
            12,
        )
    )
    return svg(
        960, 442, t, "\n".join(b), "0 public attacks reached the attacker on any of four targets"
    )


def roadmap(t):
    cols = [
        (
            "Done: part 1",
            t["live"],
            [
                "Four targets, 0 got through",
                "Positive control: 2 of 400",
                "Shortcut probe found",
                "Write-up and figures",
            ],
        ),
        (
            "Next",
            t["defender"],
            ["Shortcut fix and rebuild", "Valid live baseline"],
        ),
        (
            "Part 2",
            t["attacker"],
            [
                "Attacker-only discovery loop",
                "Findings log with replays",
                "Novelty against public corpora",
                "Report what works",
            ],
        ),
        (
            "Then",
            t["held"],
            [
                "Defender against the findings",
                "Adaptive attacker, T2 and T3",
                "Memory ablation",
                "Case studies",
            ],
        ),
    ]
    b = [
        text(32, 44, "Plan of action", t["ink"], 20, 700),
        text(
            32,
            66,
            "In order. Part 2 gets its own plan and pre-registration before any result is reported.",
            t["muted"],
            13,
        ),
    ]
    w, gap = 210, 20
    for i, (title, c, items) in enumerate(cols):
        x = 32 + i * (w + gap)
        b.append(box(x, 92, w, 40 + 22 * max(len(col[2]) for col in cols), t, c, title))
        for j, item in enumerate(items):
            yy = 140 + j * 22
            b.append(f'<circle cx="{x + 20}" cy="{yy - 4}" r="3" fill="{c}"/>')
            b.append(text(x + 30, yy, item, t["muted"], 12))
        if i < len(cols) - 1:
            b.append(arrow(x + w, 112, x + w + gap, 112, t["muted"]))
    return svg(960, 240, t, "\n".join(b), "Plan of action: part 1 done, next, part 2, then")


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, draw in (
        ("architecture", architecture),
        ("cycle", cycle),
        ("checker-ladder", ladder),
        ("roadmap", roadmap),
    ):
        for theme, t in THEMES.items():
            (out / f"{name}-{theme}.svg").write_text(draw(t))
    print(sorted(p.name for p in out.iterdir()))


if __name__ == "__main__":
    main(sys.argv[1])
