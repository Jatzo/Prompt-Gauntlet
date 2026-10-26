# Debug log

Non-trivial bugs: what broke, how it was found, the fix, and the test that would catch it again.

## A replay run was treated as a live run

**Phase 3, attack step.**

**What broke.** The orchestrator decided whether a run was live from the backend's name:
`live=backend.name not in ("mock", "replay")`. A replay backend is named `replay-<digest>`, so that
the evaluation cache never mixes two cassettes, and the check read every replay run as live. A live
run needs a novelty threshold calibrated from at least 50 train attacks, so a replay run of the
attack step on a machine without the real data build would have paused with `NotCalibrated`
instead of using the fixed threshold mock and replay runs are allowed.

**How it was found.** Reading the code the attack step would touch, before building it. The check
sat in `Orchestrator.__init__`, and the novelty threshold it controls was only ever read inside
`record_batch`, which no cycle called until the attack step existed. So no test could fail: the
mock tests pass a backend literally named `mock`, and no replay test reached the novelty hooks.
The same name string also had to feed the Judge's `MeasureRequest.backend`, which accepts only
`mock`, `replay` or `live`, so the attack step would have needed a second mapping from names.

**The fix.** Each backend class now declares a `kind` (`mock`, `replay` or `live`; a recording run
counts as live), the `Backend` protocol requires it, and the orchestrator refuses a backend whose
kind is anything else. The novelty flag and the Judge's measurement settings both read `kind`, so
there is one source for both. `name` is unchanged, because it is part of every cache key.

**Regression tests.**
- `tests/test_orchestrator.py::test_a_replay_run_is_not_treated_as_live` fails on the old check
  (`assert True is False`) and passes on the fix.
- `tests/test_llm.py::test_every_backend_declares_a_kind_the_run_and_the_judge_accept` fails if a
  new backend class is added without a kind.
- `tests/test_orchestrator.py::test_a_backend_with_an_unknown_kind_is_refused`.
