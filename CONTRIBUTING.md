# Contributing

1. Open an issue before large changes.
2. Write the failing test first, then the code.
3. Run `make check`. It must pass; CI runs the same command.
4. Use conventional commit messages: `feat`, `fix`, `test`, `docs`, `chore`, `ci`.
   One logical change per commit.
5. Do not add a dependency without a written reason in `SPEC.md`.
6. Install the hooks once: `pre-commit install` (see `.pre-commit-config.yaml`).

Every pull request must be explainable line by line by its author.

Security issues: see `SECURITY.md`, not the issue tracker.
