"""The Judge: a separate process that owns the test data and returns aggregates only.

Nothing outside this package opens the Judge database or reads the test set. The orchestrator
talks to it only through `arena.judge_client`. Every file here is hash-pinned by the tests, so
any change needs an explicit instruction and a deliberate pin update.
"""
