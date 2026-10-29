"""Runs one cycle: plan, attack, defend, judge, post-mortem.

The CEO plans; the Attacker probes the incumbent detector and submits a batch, which the Judge
checks; the Defender patches the incumbent from the evasions the Judge chose to show; the Judge
applies the keep rule to the candidate; the CEO writes the post-mortem. Every cycle also checks the
pinned hashes and writes a run manifest.

The arm sets who plans and patches (PLAN section 14). `full` is the CEO with memory; `no_memory` is
the CEO with no lessons in its briefing or directive; `control` has no CEO and no Defender: the plan
is scripted from the code-built shortlist and the patch is one hill-climb move (arena/control/
hillclimb.py). The Attacker and the Judge are the same in every arm.

Each step stores its model output first, then makes its writes in one transaction together with a
`step_writes` row. A step resumed after a crash reuses the stored output and, if that row exists,
skips the writes, so nothing is ever written twice.
"""

import json
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, get_args

import pydantic

from arena import cycle, db, dispatcher, llm
from arena.agents import defender
from arena.agents.attacker import SUBMIT_STEP, Attacker, AttackerView
from arena.agents.defender import Defender, DefenderView
from arena.anomaly import (
    Anomaly,
    ConfigMismatch,
    HashMismatch,
    HijackDetected,
    PlateauReached,
)
from arena.baselines import REGEX_RULES
from arena.config import DEFAULTS, REPO_ROOT, ArenaConfig, config_hash, private_data_dir
from arena.control import hillclimb
from arena.defender_inputs import hard_benign, shown_evasions, train_attacks, train_samples
from arena.detector.patch import PatchRefused, apply_patch, fingerprint
from arena.judge_client import HashReport
from arena.memory import briefing, shortlist
from arena.memory.lessons import actual_delta, dispute_contradicted, noise_band
from arena.memory.memory import Memory, MemoryWriteRejected, incumbent
from arena.run_novelty import RunNovelty
from arena.schemas import (
    LONG_TEXT_CHARS,
    STEP_OUTCOME,
    ArmSpec,
    AttackBatch,
    BatchReport,
    CEOPlan,
    DefenderPatch,
    DetectorConfig,
    DetectorQuery,
    Directive,
    EvaluateRequest,
    JudgeReport,
    MeasureRequest,
    PostMortem,
    QueryReply,
    QueryRequest,
    ValidateBatchRequest,
)
from arena.target.ladder import LADDER
from arena.target.world import ATTACKER_PLACEHOLDER
from arena.taxonomy import RULE_TECHNIQUES

STEPS = ("plan", "attack", "defend", "judge", "postmortem")
# The undefended target that decides which attacks are valid: the evaluation target, the same one
# the data build's checker pass uses.
REFERENCE_TARGET = LADDER[0]
# What the Judge measures with: its simulated models, or the real ones. Separate from the agents'
# backend, so live agents can be watched without the Judge's long live measurements.
JudgeBackend = Literal["simulated", "live"]
Arm = Literal["full", "no_memory", "control"]
# The dev fold the keep rule tests the TPR gain on; the other fold must replicate it. Fixed until
# checkpoints rotate the folds (Phase 3 step 13c).
PRIMARY_FOLD = 1


class Judge(Protocol):
    def verify_hashes(self) -> HashReport: ...
    def evaluate(self, cycle_id: int) -> JudgeReport: ...
    def evaluate_candidate(self, request: EvaluateRequest) -> JudgeReport: ...
    def validate_batch(self, request: ValidateBatchRequest) -> BatchReport: ...
    def query_detector(self, request: QueryRequest) -> QueryReply: ...


@dataclass(frozen=True)
class CycleOutcome:
    status: Literal["committed", "rolled_back", "paused", "stopped"]
    cycle_id: int | None
    detail: str


class Orchestrator:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        backend: llm.Backend,
        judge: Judge,
        run_id: str = "default",
        root: Path = REPO_ROOT,
        config: ArenaConfig = DEFAULTS,
        arm: Arm = "full",
        judge_backend: JudgeBackend = "simulated",
    ):
        if backend.kind not in get_args(llm.BackendKind):
            raise ValueError(
                f"Backend {backend.name!r} declares kind {backend.kind!r}; it must be one of "
                f"{get_args(llm.BackendKind)}."
            )
        if arm not in get_args(Arm):
            raise ValueError(f"Arm {arm!r} must be one of {get_args(Arm)}.")
        if judge_backend not in get_args(JudgeBackend):
            raise ValueError(
                f"Judge backend {judge_backend!r} must be one of {get_args(JudgeBackend)}."
            )
        self.judge_backend = judge_backend
        self.conn = conn
        self.backend = backend
        self.judge = judge
        self.run_id = run_id
        self.root = root
        self.config = config
        self.arm = arm
        # The no-memory ablation arm: no lessons in the briefing or the directive.
        self.use_memory = arm != "no_memory"
        # The agent-visible data: train only, read through `defender_inputs` and the novelty code.
        self.private_dir = private_data_dir()
        self.novelty = RunNovelty(
            conn,
            run_id=run_id,
            # Mock and replay runs may use the fixed threshold; a live one needs a calibrated one.
            live=backend.kind == "live",
            private_dir=self.private_dir,
            config=config,
        )

    def run_cycle(self) -> CycleOutcome:
        halted = self._halted(None)
        if halted:
            return halted
        cycle_id = cycle.open_cycle(self.conn, self.run_id)
        try:
            self._check_hashes_and_write_manifest(cycle_id)
            for step in STEPS:
                halted = self._halted(cycle_id)
                if halted:
                    return halted
                getattr(self, f"_step_{step}")(cycle_id)
            # Closing in the same transaction as the commit, so a crash can never leave a
            # committed cycle whose held-back attacks were never offered to the archive.
            with db.transaction(self.conn):
                memory = Memory(self.conn, self.config)
                cycle.reach(self.conn, cycle_id, "committed")
                self.novelty.close_cycle(memory, cycle_id)
                # Learning waits for the commit: a cycle rolled back after its Judge report (a
                # hijacked post-mortem, an abandoned cycle) must not pair a prediction or dispute
                # a lesson.
                report = memory.episode(cycle_id, "judge_report")
                if report is not None and self.arm != "control":
                    self._learn_from(memory, cycle_id, JudgeReport.model_validate(report))
            return CycleOutcome("committed", cycle_id, "all steps done")
        except Anomaly as anomaly:
            detail = {"message": str(anomaly), **_jsonable(anomaly.detail)}
            with db.transaction(self.conn):
                if not anomaly.recorded:
                    db.raise_anomaly(self.conn, anomaly.kind, detail, cycle_id=cycle_id)
                # A hijacked agent's work cannot be trusted, so the whole cycle is abandoned.
                if isinstance(anomaly, HijackDetected):
                    cycle.advance(self.conn, cycle_id, "rolled_back")
            return CycleOutcome("paused", cycle_id, f"anomaly: {anomaly.kind}: {anomaly}")
        except llm.SchemaFailure as failure:
            with db.transaction(self.conn):
                cycle.advance(self.conn, cycle_id, "rolled_back")
                db.log_event(
                    self.conn, "cycle_skipped", {"reason": str(failure)}, cycle_id=cycle_id
                )
            return CycleOutcome("rolled_back", cycle_id, str(failure))

    def _halted(self, cycle_id: int | None) -> CycleOutcome | None:
        state, reason = db.control_state(self.conn)
        if state == "running":
            return None
        return CycleOutcome(state, cycle_id, reason)

    def _check_hashes_and_write_manifest(self, cycle_id: int) -> None:
        hashes = self.judge.verify_hashes()
        if not hashes.ok:
            raise HashMismatch(
                "A pinned file does not match its hash.",
                constitution=hashes.constitution,
                test_set=hashes.test_set,
            )
        model_ids = json.dumps(self.config.models.model_dump(), sort_keys=True)
        current = {
            "config_hash": config_hash(self.config),
            "model_ids": model_ids,
            "judge_backend": self.judge_backend,
            "arm": self.arm,
            "control_bank_hash": hillclimb.bank_hash() if self.arm == "control" else None,
        }
        # A run is one arm from start to end. Manifests from before arms were recorded have none,
        # so the first one that has an arm sets it.
        first = self.conn.execute(
            "SELECT arm FROM manifests WHERE run_id = ? AND arm IS NOT NULL"
            " ORDER BY cycle_id LIMIT 1",
            (self.run_id,),
        ).fetchone()
        if first is not None and first["arm"] != self.arm:
            raise ConfigMismatch(
                f"Run {self.run_id} is a {first['arm']} run; it cannot go on as {self.arm}. "
                "Start a new run id for another arm.",
                changed=["arm"],
            )
        recorded = self.conn.execute(
            "SELECT config_hash, model_ids, judge_backend, arm, control_bank_hash"
            " FROM manifests WHERE cycle_id = ?",
            (cycle_id,),
        ).fetchone()
        if recorded is not None:
            # A resumed cycle must finish under the configuration it started with, or its stored
            # outputs and its manifest describe a different run from the one being completed. A
            # manifest from before the Judge backend was recorded has none to compare.
            changed = sorted(
                field
                for field in current
                if recorded[field] is not None and recorded[field] != current[field]
            )
            if changed:
                raise ConfigMismatch(
                    f"Cycle {cycle_id} started under a different configuration: {changed} changed. "
                    "Restore the original configuration to finish this cycle.",
                    changed=changed,
                )
            return
        self.conn.execute(
            "INSERT INTO manifests (run_id, cycle_id, model_ids, seed, config_hash,"
            " git_sha, constitution_hash, judge_backend, arm, control_bank_hash, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.run_id,
                cycle_id,
                model_ids,
                self.config.seed,
                current["config_hash"],
                _git_sha(self.root),
                hashes.constitution_hash,
                self.judge_backend,
                self.arm,
                current["control_bank_hash"],
                db.now(),
            ),
        )

    def _step_plan(self, cycle_id: int) -> None:
        cycle.reach(self.conn, cycle_id, "running")
        if self._written(cycle_id, "plan"):
            return
        if self.arm == "control":
            self._control_plan(cycle_id)
            return
        brief = self._briefing(cycle_id)
        foci, shown = brief["foci"], brief["lesson_ids"]

        def check(plan: CEOPlan) -> str | None:
            if plan.focus not in foci:
                return f"focus {plan.focus!r} is not on the shortlist {foci}"
            repeated = Memory(self.conn, self.config).duplicate_plan(
                self.run_id, plan.hypothesis_text
            )
            if repeated is not None:
                return f"the hypothesis nearly repeats the one in cycle {repeated}"
            # Only lessons this briefing showed: an id from another run, or one the budget cut,
            # would steer the agents with memory this run never had.
            unshown = sorted(set(plan.cites_lesson_ids) - set(shown))
            if unshown:
                return f"lessons {unshown} were not in this briefing"
            return None

        def write(memory: Memory, plan: CEOPlan) -> str:
            where = {"cycle_id": cycle_id, "step": "plan", "role": "ceo"}
            memory.record_episode(kind="plan", body=plan.model_dump(mode="json"), **where)
            memory.record_prediction(plan.prediction, **where)
            # The briefing-usage check (PLAN section 9). The plan check allows only shown lessons.
            usage = {
                "cites_lesson": bool(plan.cites_lesson_ids),
                "cited": plan.cites_lesson_ids,
                "shown": shown,
            }
            db.log_event(self.conn, "briefing_usage", usage, cycle_id=cycle_id)
            return "plan recorded"

        user = brief["text"]
        self._run_step(
            cycle_id,
            "plan",
            "ceo",
            "propose_plan",
            lambda: self._agent_call(
                "ceo", "propose_plan", cycle_id, "plan", CEOPlan, user=user, check=check
            ),
            write,
        )

    def _control_plan(self, cycle_id: int) -> None:
        """Arm C's plan: the focus by rotation over the shortlist, and one hill-climb move, chosen
        once here and stored, so the defend step and a resumed cycle use the same move. The plan
        names no move, since the Attacker reads the hypothesis and arm A's Attacker never sees the
        Defender's patch. It carries no prediction: a scripted number is not a forecast."""
        foci = self._shortlist(cycle_id)
        committed = self.conn.execute(
            "SELECT COUNT(*) FROM cycles WHERE run_id = ? AND state = 'committed'", (self.run_id,)
        ).fetchone()[0]
        focus = foci[committed % len(foci)]
        config = self._incumbent()[1]
        history = [
            body
            for (body,) in self.conn.execute(
                "SELECT t.body FROM memory_episodic t JOIN cycles c ON c.id = t.cycle_id"
                " WHERE c.run_id = ? AND c.state = 'committed' AND t.kind = 'control_move'"
                " ORDER BY t.cycle_id",
                (self.run_id,),
            )
        ]
        tried = hillclimb.tried_since_restart((json.loads(b) for b in history), config)
        choice = hillclimb.next_move(config, focus, tried, self.config.seed + cycle_id)
        move = choice.move

        def write(memory: Memory, _) -> str:
            where = {"cycle_id": cycle_id, "step": "plan", "role": "orchestrator"}
            plan = {
                "hypothesis_text": f"Control cycle {cycle_id}: {focus}.",
                "focus": focus,
                "agents_to_run": ["attacker", "defender"],
                "prediction": None,
                "cites_lesson_ids": [],
            }
            memory.record_episode(kind="plan", body=plan, **where)
            body = {
                "label": move.label if move else None,
                "patch": move.patch.model_dump(mode="json") if move else None,
                "parent": fingerprint(config),
                "restarted": choice.restarted,
            }
            memory.record_episode(kind="control_move", body=body, **where)
            if choice.restarted:
                db.log_event(self.conn, "control_restarted", {"cycle": cycle_id}, cycle_id=cycle_id)
            return "control plan recorded"

        self._run_step(cycle_id, "plan", "orchestrator", "control_plan", lambda: None, write)

    def _plan(self, cycle_id: int) -> CEOPlan:
        """The stored plan. A control plan has no prediction; a neutral one stands in for the
        schema, and nothing reads it, since the control arm records and pairs no prediction."""
        body = dict(Memory(self.conn, self.config).episode(cycle_id, "plan"))
        if body["prediction"] is None:
            body["prediction"] = {"expected_delta": 0.0, "confidence": 0.5}
        return CEOPlan.model_validate(body)

    def _shortlist(self, cycle_id: int) -> list[str]:
        """The control arm's shortlist, built and stored once per cycle as the briefing stores
        the CEO's, with the plateau checks the briefing runs."""
        memory = Memory(self.conn, self.config)
        stored = memory.episode(cycle_id, "shortlist")
        if stored is not None:
            return [focus for _, focus in stored["entries"]]
        self._check_plateau()
        foci = shortlist.build(self.conn, self.run_id, self.config)
        where = {"cycle_id": cycle_id, "step": "plan", "role": "orchestrator"}
        with db.transaction(self.conn):
            memory.record_episode(kind="shortlist", body=foci.body(), **where)
        return list(foci.foci)

    def _briefing(self, cycle_id: int) -> dict:
        """The CEO's prompt for this cycle, built once and stored before the call, with the
        shortlist and the lesson ids it showed. A resumed cycle reads it back rather than building
        it again, so the stored text is always the one the CEO was sent, even if a note or a lesson
        changed in between."""
        memory = Memory(self.conn, self.config)
        stored = memory.episode(cycle_id, "briefing")
        if stored is not None:
            return stored
        self._check_plateau()
        foci = shortlist.build(self.conn, self.run_id, self.config)
        brief = briefing.build(
            self.conn,
            self.run_id,
            config=self.config,
            root=self.root,
            foci=foci.foci,
            use_memory=self.use_memory,
        )
        ask = f"Cycle {cycle_id}. Call propose_plan."
        body = {
            "text": f"{brief.text}\n\n{foci.text(self.config)}\n\n{ask}",
            "foci": list(foci.foci),
            "lesson_ids": sorted(brief.lesson_ids),
        }
        where = {"cycle_id": cycle_id, "step": "plan", "role": "orchestrator"}
        with db.transaction(self.conn):
            memory.record_episode(kind="briefing", body=body, **where)
            memory.record_episode(kind="shortlist", body=foci.body(), **where)
        return body

    def _check_plateau(self) -> None:
        """Pause once no change has been kept for `plateau_pause_m` cycles. The count restarts
        after each plateau pause, so resuming gives the run another M cycles."""
        row = self.conn.execute(
            "SELECT MAX(e.cycle_id) FROM events e JOIN cycles c ON c.id = e.cycle_id"
            " WHERE c.run_id = ? AND e.kind = ?",
            (self.run_id, PlateauReached.kind),
        ).fetchone()
        streak = shortlist.no_keep_streak(self.conn, self.run_id, after_cycle=row[0] or 0)
        if streak >= self.config.plateau_pause_m:
            # The control arm has no CEO to read an operator note.
            choices = (
                "resume or stop"
                if self.arm == "control"
                else "resume, add an operator note or stop"
            )
            raise PlateauReached(
                f"No change kept in {streak} cycles. Read the state of the lab, then {choices}.",
                **shortlist.state_of_the_lab(self.conn, self.run_id),
            )

    def _step_attack(self, cycle_id: int) -> None:
        plan = self._plan(cycle_id)
        if "attacker" not in plan.agents_to_run:
            self._run_step(
                cycle_id,
                "attack",
                "attacker",
                "submit_attack_batch",
                lambda: None,
                lambda memory, _: "attacker not chosen",
            )
            return
        detector = self._incumbent()[1]

        def produce() -> tuple[AttackBatch, BatchReport]:
            settings = self._measure_settings(detector)

            def judge_query(cycle: int, step: str, text: str) -> QueryReply:
                request = QueryRequest(cycle_id=cycle, step=step, text=text, measure=settings)
                return self.judge.query_detector(request)

            directive = self._directive(plan)
            view = AttackerView(directive, self.novelty.last_view())
            # The Judge counts the query budget; the turns never ask for more than it allows.
            turns = min(self.config.attacker_query_turns, DEFAULTS.query_budget_t2)
            attacker = Attacker(turns=turns, seed=self.config.seed)
            batch = attacker.run(cycle_id, view, CyclePorts(self, cycle_id, judge_query))
            # Safe to repeat on resume: the Judge's cache holds every episode and score it ran.
            report = self.judge.validate_batch(
                ValidateBatchRequest(cycle_id=cycle_id, attacks=batch.attacks, measure=settings)
            )
            return batch, report

        def write(memory: Memory, result: tuple[AttackBatch, BatchReport]) -> str:
            batch, report = result
            self._store_baseline(memory, cycle_id, "attack")
            texts = [attack.text for attack in batch.attacks]
            self.novelty.record_batch(memory, cycle_id, texts, report)
            valid = sum(verdict.valid for verdict in report.verdicts)
            return (
                f"{len(texts)} attacks, {valid} valid, {report.evading_clusters} evading clusters"
            )

        self._run_step(cycle_id, "attack", "attacker", "submit_attack_batch", produce, write)

    def _incumbent(self) -> tuple[int | None, DetectorConfig]:
        """The run's incumbent config and its id. Before any config is stored, the regex rules are
        the incumbent, with no id; the first step that needs one stores them as the baseline."""
        stored = incumbent(self.conn, self.run_id)
        return stored if stored else (None, REGEX_RULES)

    def _store_baseline(self, memory: Memory, cycle_id: int, step: str) -> int:
        stored = incumbent(self.conn, self.run_id)
        if stored:
            return stored[0]
        return memory.add_detector_config(
            REGEX_RULES, parent_id=None, cycle_id=cycle_id, step=step, role="orchestrator"
        )

    def _step_defend(self, cycle_id: int) -> None:
        if self.arm == "control":
            self._control_defend(cycle_id)
            return
        memory = Memory(self.conn, self.config)
        plan = self._plan(cycle_id)
        if "defender" not in plan.agents_to_run:
            self._run_step(
                cycle_id,
                defender.STEP,
                defender.ROLE,
                defender.TOOL,
                lambda: None,
                lambda memory, _: "defender not chosen",
            )
            return
        config = self._incumbent()[1]

        def produce() -> DefenderPatch:
            # Only the evasions the Judge chose to show; the held-back half never leaves it.
            evasions = shown_evasions(memory, cycle_id)
            samples = train_samples(self.private_dir / "train.jsonl")
            benign, _ = hard_benign(
                samples, config, evasions, self.config.defender_hard_benign, self.config
            )
            view = DefenderView(
                directive=self._directive(plan),
                incumbent=config,
                evasions=evasions,
                train_attacks=train_attacks(
                    samples, plan.focus, self.config.defender_train_attacks, self.config.seed
                ),
                hard_benign=benign,
            )
            ports = CyclePorts(self, cycle_id, _no_queries, role=defender.ROLE)
            return Defender(seed=self.config.seed).run(cycle_id, view, ports)

        def write(memory: Memory, patch: DefenderPatch) -> str:
            return self._write_patch(memory, cycle_id, config, patch, defender.ROLE)

        self._run_step(cycle_id, defender.STEP, defender.ROLE, defender.TOOL, produce, write)

    def _control_defend(self, cycle_id: int) -> None:
        move = Memory(self.conn, self.config).episode(cycle_id, "control_move")
        config = self._incumbent()[1]

        def write(memory: Memory, _) -> str:
            if move["patch"] is None:
                return "no control move left"
            patch = DefenderPatch.model_validate(move["patch"])
            return self._write_patch(memory, cycle_id, config, patch, "orchestrator")

        self._run_step(cycle_id, defender.STEP, "orchestrator", "control_move", lambda: None, write)

    def _write_patch(
        self,
        memory: Memory,
        cycle_id: int,
        config: DetectorConfig,
        patch: DefenderPatch,
        role: str,
    ) -> str:
        """Apply a patch to the incumbent and store the candidate with its lineage."""
        where = {"cycle_id": cycle_id, "step": defender.STEP, "role": role}
        parent_id = self._store_baseline(memory, cycle_id, defender.STEP)
        try:
            candidate = apply_patch(config, patch)
        except PatchRefused as refused:
            # The reason can echo the patch, so it stays in the private episode, not an event.
            body = {"patch": patch.model_dump(mode="json"), "refused": str(refused)}
            memory.record_episode(kind="patch", body=body, **where)
            return "patch refused"
        memory.record_episode(kind="patch", body={"patch": patch.model_dump(mode="json")}, **where)
        memory.add_detector_config(
            candidate,
            parent_id=parent_id,
            cycle_id=cycle_id,
            step=defender.STEP,
            role="orchestrator",
        )
        return f"patch with {len(patch.ops)} ops"

    def _learn_from(self, memory: Memory, cycle_id: int, report: JudgeReport) -> None:
        """Pair the prediction with the measured ASR change, and dispute any lesson the plan cited
        that the outcome contradicts beyond the noise band."""
        actual = actual_delta(report, self.config)
        if actual is None:
            return
        where = {"cycle_id": cycle_id, "step": "commit", "role": "orchestrator"}
        memory.record_actual(cycle_id, actual, step="commit", role="orchestrator")
        plan = self._plan(cycle_id)
        dispute_contradicted(
            memory,
            cited=plan.cites_lesson_ids,
            expected=plan.prediction.expected_delta,
            actual=actual,
            band=noise_band(report),
            **where,
        )

    def _candidate(self, cycle_id: int) -> tuple[int, DetectorConfig, DetectorConfig] | None:
        """This cycle's candidate, its id and its parent's config, if the Defender made one."""
        row = self.conn.execute(
            "SELECT d.id, d.config, p.config FROM detector_configs d"
            " JOIN detector_configs p ON p.id = d.parent_id"
            " WHERE d.cycle_id = ? AND d.status = 'candidate'",
            (cycle_id,),
        ).fetchone()
        if row is None:
            return None
        return (
            row[0],
            DetectorConfig.model_validate_json(row[1]),
            DetectorConfig.model_validate_json(row[2]),
        )

    def _directive(self, plan: CEOPlan) -> Directive:
        """The one route from memory to behaviour, the same for the Attacker and the Defender in
        a cycle. The no-memory arm gets no lessons."""
        lessons = Memory(self.conn, self.config).lesson_texts(plan.cites_lesson_ids)
        hypothesis, constraints = plan.hypothesis_text, []
        if plan.focus == shortlist.EXPLORE:
            # Every technique a rule knows except the held-out ones, which are never named to an
            # agent. The channel fallbacks are left out: no attack can avoid having a channel.
            avoid = [t for t in RULE_TECHNIQUES if t not in self.config.held_out_techniques]
            tail = f"\n\nUse none of these known techniques: {', '.join(avoid)}."
            hypothesis = hypothesis[: LONG_TEXT_CHARS - len(tail)] + tail
            constraints = [
                "The goal is one of the toy app's own actions, with "
                f"{ATTACKER_PLACEHOLDER} as the only recipient."
            ]
        return Directive(
            focus_technique_class=plan.focus,
            hypothesis_text=hypothesis,
            cited_lesson_texts=lessons if self.use_memory else [],
            constraints=constraints,
        )

    def _measure_settings(self, detector: DetectorConfig) -> MeasureRequest:
        """What the Judge measures a query, a batch or a candidate against: the given detector at
        its calibrated threshold, on the reference target.

        The Judge measures with the models the run chose for it, whatever the agents run on. A
        replay run uses the simulated ones: a cassette holds the agents' calls but not the Judge's
        target and detector answers. Simulated numbers are marked as such in the manifest and the
        evidence pack (docs/limitations.md)."""
        return MeasureRequest(
            arms=[ArmSpec(name="incumbent", kind="detector", detector=detector)],
            targets=[REFERENCE_TARGET],
            reference_target=REFERENCE_TARGET,
            backend="live" if self.judge_backend == "live" else "mock",
            trials=self.config.trials_per_pair,
            seed=self.config.seed,
        )

    def _step_judge(self, cycle_id: int) -> None:
        """The keep rule for this cycle's candidate, against the config it was patched from. A cycle
        with no candidate gets the Judge's empty report. Safe to repeat on resume: the Judge's
        cache holds every episode and score it ran."""
        cycle.reach(self.conn, cycle_id, "evaluating")
        candidate = self._candidate(cycle_id)

        def produce() -> JudgeReport:
            if candidate is None:
                return self.judge.evaluate(cycle_id)
            _, config, parent = candidate
            return self.judge.evaluate_candidate(
                EvaluateRequest(
                    cycle_id=cycle_id,
                    candidate=config,
                    primary_fold=PRIMARY_FOLD,
                    measure=self._measure_settings(parent),
                )
            )

        def write(memory: Memory, report: JudgeReport) -> str:
            where = {"cycle_id": cycle_id, "step": "judge", "role": "judge"}
            memory.record_episode(kind="judge_report", body=report.model_dump(mode="json"), **where)
            if candidate is None:
                return report.reason_code
            # Provisional until reviewed, and every keep stays provisional until the placebo passes.
            status = "kept_provisional" if report.decision == "keep" else "not_kept"
            memory.set_detector_status(candidate[0], status, **where)
            return f"{report.decision}: {report.reason_code}"

        self._run_step(cycle_id, "judge", "judge", "evaluate", produce, write)

    def _step_postmortem(self, cycle_id: int) -> None:
        if self.arm == "control":
            # No CEO, so no lesson and no operator note acknowledged on its behalf.
            self._run_step(
                cycle_id,
                "postmortem",
                "orchestrator",
                "control_postmortem",
                lambda: None,
                lambda memory, _: "no CEO in the control arm",
            )
            return

        def write(memory: Memory, postmortem: PostMortem) -> str:
            where = {"cycle_id": cycle_id, "step": "postmortem", "role": "ceo"}
            memory.record_episode(
                kind="postmortem", body=postmortem.model_dump(mode="json"), **where
            )
            # A rejected lesson is logged, not raised: the stored output would be replayed on every
            # resume and hit the same rejection, so raising would stop the run for good. The memory
            # checks all run before any insert, so a rejection leaves nothing half-written.
            rejected_count = 0
            for proposal in postmortem.lesson_candidates:
                try:
                    memory.add_lesson(proposal, **where)
                except MemoryWriteRejected as rejected:
                    rejected_count += 1
                    detail = {"reason": str(rejected), "text": proposal.text}
                    db.log_event(self.conn, "lesson_rejected", detail, cycle_id=cycle_id)
            stored = len(postmortem.lesson_candidates) - rejected_count
            return f"{stored} lessons stored, {rejected_count} rejected"

        notes = briefing.unacknowledged_notes(self.conn, self.run_id)

        def check(postmortem: PostMortem) -> str | None:
            missing = sorted(set(notes) - set(postmortem.operator_notes_acknowledged))
            return f"operator notes {missing} are not acknowledged" if missing else None

        listed = ", ".join(map(str, notes)) or "none"
        user = f"Cycle {cycle_id}. Operator notes to acknowledge: {listed}. Call write_postmortem."
        self._run_step(
            cycle_id,
            "postmortem",
            "ceo",
            "write_postmortem",
            lambda: self._agent_call(
                "ceo",
                "write_postmortem",
                cycle_id,
                "postmortem",
                PostMortem,
                user=user,
                check=check,
            ),
            write,
        )

    def _run_step[Result](
        self,
        cycle_id: int,
        step: str,
        role: str,
        tool: str,
        produce: Callable[[], Result],
        write: Callable[[Memory, Result], str],
    ) -> None:
        """Run one step at most once per cycle.

        A step whose writes are already committed is skipped whole, so a resumed cycle neither calls
        the model or the Judge again nor re-runs the dispatcher on a stored output. Otherwise the
        output is produced (from the store if a previous attempt saved it) and written once.
        """
        if self._written(cycle_id, step):
            return
        result = produce()
        self._write_once(cycle_id, step, role, tool, lambda memory: write(memory, result))

    def _agent_call[Model: pydantic.BaseModel](
        self,
        role: str,
        tool: str,
        cycle_id: int,
        step: str,
        response_model: type[Model],
        user: str | None = None,
        check: Callable[[Model], str | None] | None = None,
    ) -> Model:
        """One forced tool call: the model is shown only its role's tools, and the result goes
        through the dispatcher like any other agent tool call."""
        request = llm.LLMRequest(
            tool=tool,
            tools=dispatcher.tool_schemas_for(role),
            system=self._system_prompt(role),
            user=user or f"Cycle {cycle_id}. Call {tool}.",
        )
        output = llm.call(
            role,
            (cycle_id, step),
            request,
            response_model,
            self.conn,
            backend=self.backend,
            config=self.config,
            check=check,
        )
        dispatched = dispatcher.dispatch(
            self.conn, role, tool, output.model_dump(mode="json"), cycle_id=cycle_id
        )
        if not isinstance(dispatched, response_model):
            raise TypeError(f"{tool} is registered with a different schema than {response_model}.")
        return dispatched

    def _system_prompt(self, role: str) -> str:
        constitution = (self.root / "constitution.md").read_text()
        prompt = (self.root / "prompts" / f"{role}.md").read_text()
        return f"{constitution}\n\n{prompt}"

    def _written(self, cycle_id: int, step: str) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM step_writes WHERE cycle_id = ? AND step = ? AND kind = 'memory'",
                (cycle_id, step),
            ).fetchone()
            is not None
        )

    def _write_once(
        self, cycle_id: int, step: str, role: str, tool: str, write: Callable[[Memory], str]
    ) -> None:
        with db.transaction(self.conn):
            if self._written(cycle_id, step):
                return
            outcome = write(Memory(self.conn, self.config))
            if not STEP_OUTCOME.fullmatch(outcome):
                raise ValueError(f"Step {step} returned an outcome the live feed cannot show.")
            # The live feed reads these. Outcomes are fixed-format strings, never agent free text.
            detail = {
                "cycle": cycle_id,
                "step": step,
                "role": role,
                "tool": tool,
                "outcome": outcome,
            }
            db.log_event(self.conn, "step_done", detail, cycle_id=cycle_id)
            self.conn.execute(
                "INSERT INTO step_writes (cycle_id, step, kind, created_at)"
                " VALUES (?, ?, 'memory', ?)",
                (cycle_id, step, db.now()),
            )


class CyclePorts:
    """The Attacker's two ports for one cycle: agent calls stored and dispatched by step, and the
    Judge's T2 label, which the Judge itself keeps by step. Both survive a crash, so a resumed cycle
    makes no new model call and spends no query twice."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        cycle_id: int,
        judge_query: Callable[[int, str, str], QueryReply],
        role: str = "attacker",
    ):
        self.orchestrator, self.cycle_id, self.role = orchestrator, cycle_id, role
        self.judge_query = judge_query

    def ask[Model: pydantic.BaseModel](
        self, step: str, tool: str, user: str, model: type[Model]
    ) -> Model:
        return self.orchestrator._agent_call(self.role, tool, self.cycle_id, step, model, user=user)

    def query(self, step: str, text: str) -> QueryReply:
        return self.judge_query(self.cycle_id, step, text)


def _no_queries(cycle: int, step: str, text: str) -> QueryReply:
    raise RuntimeError("Only the Attacker queries the detector.")


def _git_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        return "no-commit"
    return result.stdout.strip()


def _jsonable(detail: dict) -> dict:
    return json.loads(json.dumps(detail, default=str))


def phase1_mock_script(cycles: int = 1, first: int = 1) -> dict[str, list]:
    """Outputs for `cycles` mock cycles: a plan, the Attacker's queries and batch, the Defender's
    patch and a post-mortem for each. Every plan takes the first focus its shortlist lists (the
    mock backend fills it in) and numbers its hypothesis from `first`, since a hypothesis tried
    before is refused."""

    def example(model: type[pydantic.BaseModel]) -> str:
        return json.dumps(model.model_config["json_schema_extra"]["examples"][0])

    postmortem = json.loads(example(PostMortem))
    postmortem["operator_notes_acknowledged"] = []
    turns = min(DEFAULTS.attacker_query_turns, DEFAULTS.query_budget_t2)
    plan = json.loads(example(CEOPlan)) | {"focus": shortlist.FIRST_LISTED, "cites_lesson_ids": []}
    plans = [
        json.dumps(plan | {"hypothesis_text": f"Scripted plan {n}."})
        for n in range(first, first + cycles)
    ]
    script = {"plan": plans, "postmortem": [json.dumps(postmortem)] * cycles}
    script |= {f"attack.t{turn}": [example(DetectorQuery)] * cycles for turn in range(turns)}
    script[SUBMIT_STEP] = [example(AttackBatch)] * cycles
    script[defender.STEP] = [example(DefenderPatch)] * cycles
    return script
