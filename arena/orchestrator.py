"""Runs one cycle: plan, attack, defend, judge, post-mortem.

The CEO plans; the Attacker probes the incumbent detector and submits a batch, which the Judge
checks; the Defender patches the incumbent from the evasions the Judge chose to show; the Judge
applies the keep rule to the candidate; the CEO writes the post-mortem. Every cycle also checks the
pinned hashes and writes a run manifest.

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
from arena.anomaly import Anomaly, ConfigMismatch, HashMismatch, HijackDetected
from arena.baselines import REGEX_RULES
from arena.config import DEFAULTS, REPO_ROOT, ArenaConfig, config_hash, private_data_dir
from arena.defender_inputs import hard_benign, shown_evasions, train_attacks, train_samples
from arena.detector.patch import PatchRefused, apply_patch
from arena.judge_client import HashReport
from arena.memory.memory import Memory, MemoryWriteRejected, incumbent
from arena.run_novelty import RunNovelty
from arena.schemas import (
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

STEPS = ("plan", "attack", "defend", "judge", "postmortem")
# The undefended target that decides which attacks are valid: the evaluation target, the same one
# the data build's checker pass uses.
REFERENCE_TARGET = LADDER[0]
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
        use_memory: bool = True,
    ):
        if backend.kind not in get_args(llm.BackendKind):
            raise ValueError(
                f"Backend {backend.name!r} declares kind {backend.kind!r}; it must be one of "
                f"{get_args(llm.BackendKind)}."
            )
        self.conn = conn
        self.backend = backend
        self.judge = judge
        self.run_id = run_id
        self.root = root
        self.config = config
        # The no-memory ablation arm: no lessons in the directive, no last batch for the Attacker.
        self.use_memory = use_memory
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
                cycle.reach(self.conn, cycle_id, "committed")
                self.novelty.close_cycle(Memory(self.conn, self.config), cycle_id)
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
        current = {"config_hash": config_hash(self.config), "model_ids": model_ids}
        recorded = self.conn.execute(
            "SELECT config_hash, model_ids FROM manifests WHERE cycle_id = ?", (cycle_id,)
        ).fetchone()
        if recorded is not None:
            # A resumed cycle must finish under the configuration it started with, or its stored
            # outputs and its manifest describe a different run from the one being completed.
            changed = sorted(field for field in current if recorded[field] != current[field])
            if changed:
                raise ConfigMismatch(
                    f"Cycle {cycle_id} started under a different configuration: {changed} changed. "
                    "Restore the original configuration to finish this cycle.",
                    changed=changed,
                )
            return
        self.conn.execute(
            "INSERT INTO manifests (run_id, cycle_id, model_ids, seed, config_hash,"
            " git_sha, constitution_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.run_id,
                cycle_id,
                model_ids,
                self.config.seed,
                current["config_hash"],
                _git_sha(self.root),
                hashes.constitution_hash,
                db.now(),
            ),
        )

    def _step_plan(self, cycle_id: int) -> None:
        cycle.reach(self.conn, cycle_id, "running")

        def write(memory: Memory, plan: CEOPlan) -> str:
            where = {"cycle_id": cycle_id, "step": "plan", "role": "ceo"}
            memory.record_episode(kind="plan", body=plan.model_dump(mode="json"), **where)
            memory.record_prediction(plan.prediction, **where)
            return "plan recorded"

        self._run_step(
            cycle_id,
            "plan",
            "ceo",
            "propose_plan",
            lambda: self._agent_call("ceo", "propose_plan", cycle_id, "plan", CEOPlan),
            write,
        )

    def _step_attack(self, cycle_id: int) -> None:
        plan = CEOPlan.model_validate(Memory(self.conn, self.config).episode(cycle_id, "plan"))
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
            view = AttackerView(directive, self.novelty.last_view() if self.use_memory else ())
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
        memory = Memory(self.conn, self.config)
        plan = CEOPlan.model_validate(memory.episode(cycle_id, "plan"))
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
            where = {"cycle_id": cycle_id, "step": defender.STEP, "role": defender.ROLE}
            parent_id = self._store_baseline(memory, cycle_id, defender.STEP)
            try:
                candidate = apply_patch(config, patch)
            except PatchRefused as refused:
                # The reason can echo the patch, so it stays in the private episode, not an event.
                body = {"patch": patch.model_dump(mode="json"), "refused": str(refused)}
                memory.record_episode(kind="patch", body=body, **where)
                return "patch refused"
            memory.record_episode(
                kind="patch", body={"patch": patch.model_dump(mode="json")}, **where
            )
            memory.add_detector_config(
                candidate,
                parent_id=parent_id,
                cycle_id=cycle_id,
                step=defender.STEP,
                role="orchestrator",
            )
            return f"patch with {len(patch.ops)} ops"

        self._run_step(cycle_id, defender.STEP, defender.ROLE, defender.TOOL, produce, write)

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
        return Directive(
            focus_technique_class=plan.focus,
            hypothesis_text=plan.hypothesis_text,
            cited_lesson_texts=lessons if self.use_memory else [],
            constraints=[],
        )

    def _measure_settings(self, detector: DetectorConfig) -> MeasureRequest:
        """What the Judge measures a query or a batch against: the incumbent detector at its
        calibrated threshold, on the reference target.

        A live run measures live. A mock or replay run measures with the Judge's simulated models:
        a cassette holds the agents' calls but not the Judge's target and detector answers, so a
        replayed cycle could not finish otherwise. The Judge's numbers in a replay run are therefore
        simulated, as in a mock run (docs/limitations.md)."""
        return MeasureRequest(
            arms=[ArmSpec(name="incumbent", kind="detector", detector=detector)],
            targets=[REFERENCE_TARGET],
            reference_target=REFERENCE_TARGET,
            backend="live" if self.backend.kind == "live" else "mock",
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

        self._run_step(
            cycle_id,
            "postmortem",
            "ceo",
            "write_postmortem",
            lambda: self._agent_call("ceo", "write_postmortem", cycle_id, "postmortem", PostMortem),
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


def phase1_mock_script() -> dict[str, list]:
    """Outputs for a mock cycle: a plan, the Attacker's queries and batch, the Defender's patch
    and a post-mortem."""

    def example(model: type[pydantic.BaseModel]) -> str:
        return json.dumps(model.model_config["json_schema_extra"]["examples"][0])

    postmortem = json.loads(example(PostMortem))
    postmortem["operator_notes_acknowledged"] = []
    turns = min(DEFAULTS.attacker_query_turns, DEFAULTS.query_budget_t2)
    script = {"plan": [example(CEOPlan)], "postmortem": [json.dumps(postmortem)]}
    script |= {f"attack.t{turn}": [example(DetectorQuery)] for turn in range(turns)}
    script[SUBMIT_STEP] = [example(AttackBatch)]
    script[defender.STEP] = [example(DefenderPatch)]
    return script
