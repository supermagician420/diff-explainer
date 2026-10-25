import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from diff_explainer import ParseError, explain, explain_to_text, main, parse_unified_diff


SIMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 def main():
-    return 1
+    return 2
+    # done
"""

SECOND_FILE_DIFF = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
-old title
+new title
+more words
diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,2 +1,3 @@
 def check(user):
-    if not user.is_admin:
+    if not user.is_staff:
         raise PermissionError
"""


class ParseTests(unittest.TestCase):
    def test_parse_hunk_ranges_and_lines(self) -> None:
        parsed = parse_unified_diff(SIMPLE_DIFF)
        self.assertEqual(len(parsed.files), 1)
        file_diff = parsed.files[0]
        self.assertEqual(file_diff.path, "app.py")
        self.assertEqual(len(file_diff.hunks), 1)
        hunk = file_diff.hunks[0]
        self.assertEqual((hunk.old_start, hunk.old_count), (1, 3))
        self.assertEqual((hunk.new_start, hunk.new_count), (1, 4))
        self.assertEqual(len(hunk.lines), 4)

    def test_binary_file(self) -> None:
        text = """diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
"""
        parsed = parse_unified_diff(text)
        self.assertTrue(parsed.files[0].binary)

    def test_invalid_hunk_header(self) -> None:
        with self.assertRaises(ParseError):
            parse_unified_diff("diff --git a/x b/x\n@@ nope @@\n")

    def test_empty_diff_rejected(self) -> None:
        with self.assertRaises(ParseError):
            parse_unified_diff("   \n")


class ExplainTests(unittest.TestCase):
    def test_summary_and_scope(self) -> None:
        explanation = explain(SIMPLE_DIFF)
        self.assertIn("1 file changed", explanation.summary)
        self.assertIn("+2/-1", explanation.summary)
        self.assertEqual(explanation.review_order, ("app.py",))

    def test_multiple_files_and_order(self) -> None:
        explanation = explain(SECOND_FILE_DIFF)
        self.assertEqual(len(explanation.files), 2)
        self.assertEqual(len(explanation.review_order), 2)
        self.assertEqual(explanation.review_order[0], "src/auth.py")

    def test_removed_guard_is_flagged(self) -> None:
        explanation = explain(SECOND_FILE_DIFF)
        self.assertTrue(any("guard" in risk.reason.lower() for risk in explanation.risks))
        self.assertTrue(any(risk.path == "src/auth.py" for risk in explanation.risks))

    def test_secret_like_addition_is_flagged_high(self) -> None:
        text = """diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1 +1,2 @@
 x = 1
+API_KEY = "abc123"
"""
        explanation = explain(text)
        self.assertTrue(any(risk.level == "high" for risk in explanation.risks))
        self.assertIn("secret", " ".join(risk.reason for risk in explanation.risks).lower())

    def test_sensitive_file_type_is_flagged(self) -> None:
        text = """diff --git a/deploy.key b/deploy.key
--- a/deploy.key
+++ b/deploy.key
@@ -1 +1 @@
-old
+new
"""
        explanation = explain(text)
        self.assertTrue(any(risk.level == "high" for risk in explanation.risks))

    def test_binary_is_flagged_and_noted(self) -> None:
        text = """diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
"""
        explanation = explain(text)
        self.assertTrue(any("Binary" in risk.reason for risk in explanation.risks))
        self.assertTrue(any("line by line" in note for note in explanation.notes))

    def test_text_rendering_has_sections(self) -> None:
        rendered = explain_to_text(explain(SIMPLE_DIFF))
        self.assertIn("Review order:", rendered)
        self.assertIn("Risks:", rendered)
        self.assertIn("app.py", rendered)


class CliTests(unittest.TestCase):
    def test_cli_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "change.diff"
            path.write_text(SIMPLE_DIFF, encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--diff", str(path), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"], "1 file changed, +2/-1.")

    def test_cli_missing_file(self) -> None:
        code = main(["--diff", "does-not-exist.diff"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
