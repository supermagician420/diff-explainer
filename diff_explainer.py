#!/usr/bin/env python3
"""Explain a unified diff without an LLM: scope, review order, and risk cues."""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


class ParseError(ValueError):
    """The input is not a unified diff this tool understands."""


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: Tuple[Tuple[str, str], ...]


@dataclass
class FileDiff:
    old_path: Optional[str]
    new_path: Optional[str]
    hunks: List[Hunk]
    binary: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or "(unknown)"


@dataclass(frozen=True)
class ParsedDiff:
    files: Tuple[FileDiff, ...]


@dataclass(frozen=True)
class FileStat:
    path: str
    added: int
    removed: int
    hunks: int
    binary: bool


@dataclass(frozen=True)
class Risk:
    path: str
    level: str
    reason: str


@dataclass(frozen=True)
class Explanation:
    summary: str
    files: Tuple[FileStat, ...]
    review_order: Tuple[str, ...]
    risks: Tuple[Risk, ...]
    notes: Tuple[str, ...]


_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)
_SECRET_RE = re.compile(
    r"(api[_-]?key|secret|password|passwd|token|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16})",
    re.IGNORECASE,
)
_GUARD_RE = re.compile(r"^\s*(if|assert|raise|except|elif)\b")
_HIGH_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".env"}
_MEDIUM_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pipfile.lock",
    "dockerfile",
    "makefile",
}
_LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def _normalize_path(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    if value == "/dev/null":
        return None
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value or None


def _strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def _parse_hunk_header(line: str) -> Tuple[int, int, int, int]:
    match = _HUNK_RE.match(line)
    if not match:
        raise ParseError("invalid hunk header: %s" % line[:120])
    old_count = int(match.group("old_count")) if match.group("old_count") is not None else 1
    new_count = int(match.group("new_count")) if match.group("new_count") is not None else 1
    return int(match.group("old_start")), old_count, int(match.group("new_start")), new_count


def parse_unified_diff(text: str) -> ParsedDiff:
    """Parse the subset of unified diff produced by git and GNU diff."""
    files: List[FileDiff] = []
    current: Optional[FileDiff] = None
    in_hunk = False
    hunk_lines: List[Tuple[str, str]] = []
    hunk_header: Optional[Tuple[int, int, int, int]] = None

    def flush_hunk() -> None:
        nonlocal hunk_header, hunk_lines
        if current is not None and hunk_header is not None:
            current.hunks.append(Hunk(*hunk_header, tuple(hunk_lines)))
        hunk_header = None
        hunk_lines = []

    def flush_file() -> None:
        nonlocal current, in_hunk
        flush_hunk()
        if current is not None and (current.hunks or current.binary):
            files.append(current)
        current = None
        in_hunk = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")

        if line.startswith("diff --git "):
            flush_file()
            rest = line[len("diff --git ") :]
            old_path = new_path = None
            if " b/" in rest:
                old_raw, new_raw = rest.split(" b/", 1)
                old_path = _normalize_path(old_raw)
                new_path = _normalize_path("b/" + new_raw)
            current = FileDiff(old_path, new_path, [])
            continue

        if line.startswith("--- ") and not in_hunk:
            if current is None:
                current = FileDiff(None, None, [])
            current.old_path = _normalize_path(line[4:])
            continue

        if line.startswith("+++ ") and not in_hunk:
            if current is None:
                current = FileDiff(None, None, [])
            current.new_path = _normalize_path(line[4:])
            continue

        if line.startswith("@@"):
            flush_hunk()
            if current is None:
                current = FileDiff(None, None, [])
            hunk_header = _parse_hunk_header(line)
            in_hunk = True
            continue

        if current is None:
            continue

        if "GIT binary patch" in line or line.startswith("Binary files "):
            current.binary = True
            continue

        if not in_hunk:
            # Metadata such as index lines, file modes, and similarity scores.
            continue

        if line.startswith("\\"):
            continue
        if line.startswith((" ", "+", "-")):
            hunk_lines.append((line[0], line[1:]))
            continue
        # A non-content line ends the hunk without a new header.
        flush_hunk()
        in_hunk = False

    flush_file()
    if not files:
        raise ParseError("no file changes found (expected a unified diff)")
    return ParsedDiff(tuple(files))


def _file_stat(file_diff: FileDiff) -> FileStat:
    added = 0
    removed = 0
    for hunk in file_diff.hunks:
        for marker, _content in hunk.lines:
            if marker == "+":
                added += 1
            elif marker == "-":
                removed += 1
    return FileStat(file_diff.path, added, removed, len(file_diff.hunks), file_diff.binary)


def _path_risks(file_diff: FileDiff) -> List[Risk]:
    path = file_diff.path
    lowered = path.lower()
    suffix = Path(lowered).suffix
    risks: List[Risk] = []

    if file_diff.binary:
        risks.append(Risk(path, "high", "Binary content changed; inspect the asset and its provenance."))
    if suffix in _HIGH_EXTENSIONS or lowered.endswith(".env"):
        risks.append(Risk(path, "high", "Credential/secret-bearing file type changed."))

    name = Path(lowered).name
    if name in _MEDIUM_NAMES or suffix in {".sql", ".lock"}:
        risks.append(Risk(path, "medium", "Dependency, schema, or build configuration changed."))
    if "/.github/workflows/" in "/" + lowered or lowered.startswith(".github/workflows/"):
        risks.append(Risk(path, "medium", "CI workflow changed; review permissions and triggers."))

    added = [content for hunk in file_diff.hunks for marker, content in hunk.lines if marker == "+"]
    removed = [content for hunk in file_diff.hunks for marker, content in hunk.lines if marker == "-"]

    for content in added:
        if _SECRET_RE.search(content):
            risks.append(Risk(path, "high", "Added line looks like it may contain a secret or token."))
            break
    for content in removed:
        if _GUARD_RE.search(content):
            risks.append(Risk(path, "medium", "A guard/control-flow line was removed; verify the check is not lost."))
            break

    total = sum(1 for hunk in file_diff.hunks for _ in hunk.lines)
    if total > 300:
        risks.append(Risk(path, "medium", "Large change (%d hunk lines); split review if possible." % total))
    return risks


def explain(text: str) -> Explanation:
    parsed = parse_unified_diff(text)
    stats = tuple(_file_stat(file_diff) for file_diff in parsed.files)
    additions = sum(stat.added for stat in stats)
    deletions = sum(stat.removed for stat in stats)
    files_word = "file" if len(stats) == 1 else "files"
    summary = "%d %s changed, +%d/-%d." % (len(stats), files_word, additions, deletions)

    risks: List[Risk] = []
    for file_diff in parsed.files:
        seen = set()
        for risk in _path_risks(file_diff):
            key = (risk.path, risk.reason)
            if key not in seen:
                seen.add(key)
                risks.append(risk)
    risks.sort(key=lambda risk: (_LEVEL_ORDER.get(risk.level, 9), risk.path, risk.reason))

    by_path: Dict[str, FileStat] = {stat.path: stat for stat in stats}
    risky_paths = {risk.path for risk in risks}
    order = sorted(
        stats,
        key=lambda stat: (
            0 if stat.path in risky_paths else 1,
            0 if stat.binary else 1,
            -(stat.added + stat.removed),
            stat.path,
        ),
    )
    review_order = tuple(stat.path for stat in order)

    notes = []
    if not risks:
        notes.append("No obvious high-risk patterns found; this is a heuristic, not a guarantee.")
    if any(stat.binary for stat in stats):
        notes.append("Binary files cannot be reviewed line by line.")
    if any(stat.added + stat.removed == 0 for stat in stats):
        notes.append("Some files have no textual additions or deletions (rename/mode-only change).")

    # Keep by_path referenced for type checkers and future extensions.
    _ = by_path
    return Explanation(summary, stats, review_order, tuple(risks), tuple(notes))


def explain_to_text(explanation: Explanation) -> str:
    lines = [explanation.summary, "", "Review order:"]
    for index, path in enumerate(explanation.review_order, 1):
        lines.append("%d. %s" % (index, path))
    lines.extend(["", "Risks:"])
    if explanation.risks:
        for risk in explanation.risks:
            lines.append("- [%s] %s: %s" % (risk.level.upper(), risk.path, risk.reason))
    else:
        lines.append("- None detected by the heuristic.")
    if explanation.notes:
        lines.extend(["", "Notes:"])
        lines.extend("- %s" % note for note in explanation.notes)
    return "\n".join(lines).rstrip() + "\n"


def explain_to_json(explanation: Explanation) -> str:
    return json.dumps(asdict(explanation), ensure_ascii=False, indent=2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Explain a unified diff: summary, order, risk cues")
    parser.add_argument("--diff", help="unified diff path; use - or omit for stdin")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        if args.diff and args.diff != "-":
            text = Path(args.diff).read_text(encoding="utf-8")
        else:
            text = sys.stdin.read()
        explanation = explain(text)
    except OSError as exc:
        print("error: cannot read diff: %s" % exc, file=sys.stderr)
        return 2
    except ParseError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    print(explain_to_json(explanation) if args.json else explain_to_text(explanation), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
