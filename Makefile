# Targets run in a fixed order: format check, lint, type check, tests with coverage,
# then a stricter per-module coverage gate for security-critical modules.
.PHONY: check fmt fmt-check lint typecheck test coverage-gate
MAKEFLAGS += --no-print-directory

COVERAGE_MIN ?= 80
CRITICAL_COVERAGE_MIN ?= 90
CRITICAL_MODULES := */linkguard/parse.py,*/linkguard/host.py
RUN := uv run --locked

check:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) typecheck
	$(MAKE) test
	$(MAKE) coverage-gate

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

# Reads the data written by `make test`; run that first.
coverage-gate:
	$(RUN) coverage report --include="$(CRITICAL_MODULES)" --fail-under=$(CRITICAL_COVERAGE_MIN)
