# diff-explainer

A zero-dependency unified-diff reviewer for the first five minutes of a pull request.

It answers three questions without calling an LLM:

1. **Scope** — how many files, additions, and deletions?
2. **Review order** — which file should I open first?
3. **Risk cues** — which changes deserve a closer look (secrets, removed guards, binary files, schema/build changes)?

## Quick start

Requires Python 3.8+, no third-party packages.

```bash
python diff_explainer.py --diff examples/change.diff
```

Example output:

```text
2 files changed, +4/-2.

Review order:
1. src/auth.py
2. README.md

Risks:
- [HIGH] src/auth.py: Added line looks like it may contain a secret or token.
- [MEDIUM] src/auth.py: A guard/control-flow line was removed; verify the check is not lost.
```

JSON for scripts and CI:

```bash
python diff_explainer.py --diff examples/change.diff --json
```

Pipe from git:

```bash
git diff HEAD~1 | python diff_explainer.py
```

## What it detects

| Signal | Level | Why |
| --- | --- | --- |
| Credential-like added line (`api_key`, `secret`, `password`, `token`, private key) | high | Prevents accidental secret commits |
| Sensitive file type (`.pem`, `.key`, `.p12`, `.env`) | high | Credential-bearing content |
| Binary file | high | Cannot review line by line |
| Removed guard/control-flow line (`if`, `assert`, `raise`, `except`) | medium | A safety check may have been lost |
| Dependency/schema/build file (`requirements.txt`, lockfiles, `.sql`, `Dockerfile`) | medium | Broad blast radius |
| CI workflow change | medium | Permissions/triggers can change |
| More than 300 hunk lines | medium | Review fatigue |

The checks are intentionally simple and transparent. They are **cues**, not a security review.

## Design choices

- **No model required.** Fast, deterministic, and works offline.
- **Diff in, text or JSON out.** Easy to place in a pre-commit hook or CI step.
- **Review order is risk-first, then churn.** A file with a detected risk moves ahead of a larger but boring change.
- **Provider-neutral.** It parses the standard unified diff produced by `git diff`, `git show`, and GNU `diff -u`.

## Limitations

- Heuristics can produce false positives and false negatives.
- It does not understand code semantics or runtime behavior.
- Binary files are flagged, not inspected.
- Renames without content changes may appear as a file with zero additions/deletions.
- A clean report is not proof that a change is safe.

## Tests

```bash
python -m unittest -v
```

13 tests cover parsing, binary diffs, malformed headers, risk detection, ordering, JSON output, and CLI errors.

## Files

```text
diff-explainer/
├── diff_explainer.py
├── test_diff_explainer.py
├── examples/change.diff
├── README.md
├── .gitignore
└── .github/workflows/tests.yml
```
