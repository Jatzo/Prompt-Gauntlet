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
mock tests pass a backend named exactly `mock`, and no replay test reached the novelty hooks.
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

## The live target could see the operator's account connectors

**Phase 2, checker pass.**

**What broke.** Each live call is one SDK session, and `LiveBackend._options` turned off the built-in
tools (`tools=[]`) and the settings files (`setting_sources=[]`). Neither covers the connectors
attached to the operator's account (file storage, a CRM, a docs service), so every live session
offered them to the model. The target reads attack text, so attack text could steer a model that had
a way out of the toy app.

**How it was found.** Writing up the checker pass. The outcome counts showed 110 rejected outputs
that named a tool no part of the project defines. The CLI's own session transcripts showed 113 calls
to account connectors in 110 sessions: searching, reading, listing and creating files. Every one
failed with a permission prompt nobody answered. The toy tools fail differently ("No such tool
available"), so the connectors were really offered, and only the missing grant stopped them. No data
moved either way, and the harness had rejected each of those outputs as a hijack.

**The fix.** The session now loads no MCP server from any source (`--strict-mcp-config`, plus the
setting that turns off account connectors) and runs in `dontAsk` mode, which denies any tool use not
approved in advance. The SDK's init message, which lists the session's tools, MCP servers, plugins
and permission mode, is checked before anything else is read: anything beyond the answer tool, a
plugin not built into the CLI, or no init at all, raises `ToolExposure` and stops the run. One live
call after the fix showed the answer tool alone, no MCP server, `dontAsk`, and three plugins that
ship with the CLI and add no tool; those built-in plugins are let through, since the CLI cannot turn
them off.

**Regression tests.**
- `tests/test_live_backend.py::test_a_session_offering_more_than_its_answer_tool_stops_before_the_reply`
  (a connector tool, an MCP server, a plugin, the wrong permission mode).
- `tests/test_live_backend.py::test_a_session_that_sends_no_init_stops_rather_than_trusting_its_tools`.
- `tests/test_live_backend.py::test_the_cli_command_carries_every_lock` builds the real SDK's CLI
  command without starting it.

## Stopping a run left the Judge making live calls

**Phase 2, checker pass.**

**What broke.** The Judge runs as a child process. Killing the CLI with `pkill` ends it with SIGTERM,
which skips `JudgeClient.close()`. A Judge in the middle of a measurement is not reading stdin, so it
never sees the pipe close, and it went on calling the model.

**How it was found.** The call timestamps in the Judge's cache ran on after each stop: 1,142 calls
in the 23 minutes after the stop at 23:05 on 29 October, and 917 in the 27 minutes after 20:22 on
30 October. Runs that ended on an error stored nothing afterwards. The calls were cached and later
reused, so none were wasted, but the stop command did not stop the calls.

**The fix.** On Linux the Judge starts with `PR_SET_PDEATHSIG`, so it is sent SIGTERM when the CLI
ends, however it ends. prctl is looked up in the parent, and the child exits at once if its parent
died before the call took effect.

**Regression test.** `tests/test_judge.py::test_a_killed_cli_takes_its_judge_with_it` stands in a
Judge that ignores stdin, as a busy one does, kills the CLI and checks the Judge goes too. It fails
with the signal removed.
