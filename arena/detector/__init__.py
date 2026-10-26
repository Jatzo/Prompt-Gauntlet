"""Runs a DetectorConfig over text: normalisers, regex rules and an LLM classifier, in layers.

The public entry point is `build_scorer` in `arena.detector.scorer`. Like the target app, nothing
here reads files or opens a database; text and settings arrive as arguments.
"""
