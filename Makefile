# Targets run in a fixed order: format check, lint, type check, tests with coverage.
.PHONY: check fmt fmt-check lint typecheck test
MAKEFLAGS += --no-print-directory

COVERAGE_MIN ?= 80
RUN := uv run --locked

check:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) typecheck
	$(MAKE) test

fmt:
	$(RUN) ruff format .

fmt-check:
	$(RUN) ruff format --check .

lint:
	$(RUN) ruff check .

typecheck:
	$(RUN) mypy --strict src tests

test:
	$(RUN) pytest --cov=linkguard --cov-branch --cov-report=term-missing --cov-fail-under=$(COVERAGE_MIN)
