# Every check fails loudly if its tool is missing: a skipped secret scan must never look like a pass.

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
GITLEAKS ?= gitleaks

.PHONY: test-phase1 test-phase2 test lint guard secrets ci

test-phase1: lint guard test secrets
	@echo "Phase 1 checks passed."

# Phase 2 adds no new tools: the same checks, now covering measurement.
test-phase2: lint guard test secrets
	@echo "Phase 2 checks passed."

test:
	ARENA_LLM_BACKEND=mock $(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

guard:
	$(PYTHON) scripts/check_tracked_files.py

secrets:
	@command -v $(GITLEAKS) >/dev/null 2>&1 || { echo "gitleaks is not installed, so no secret scan ran. Install it, then run make secrets again." >&2; exit 1; }
	$(GITLEAKS) dir . --config .gitleaks.toml --redact --no-banner
	@if git rev-parse --verify -q HEAD >/dev/null; then \
		$(GITLEAKS) git . --config .gitleaks.toml --redact --no-banner; \
	else \
		echo "No commits yet, so only the working tree was scanned."; \
	fi

ci: test-phase2
