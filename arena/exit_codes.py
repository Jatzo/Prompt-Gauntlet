"""The exit codes of the operator commands, so a script that wraps them can act on the result."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    # The command could not run, such as a Judge that refused or could not be reached.
    FAILED = 1
    # The run stopped for the operator: a cycle paused or stopped, an unmeasurable headline arm, or
    # a baseline gate that needs a decision or the next ladder rung measured. The output says which.
    NEEDS_OPERATOR = 3
    # A shortcut probe comes too close to the headline arm, so the benchmark measures nothing.
    BENCHMARK_INVALID = 4
    # No ladder rung gave a usable baseline; the claim narrows to an engineered target.
    NARROWED = 5
