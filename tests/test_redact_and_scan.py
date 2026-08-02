"""Tests for redaction and for the checker's own scanners.

Detection needs its own test. `grep -P '\\x00'` is not available in every grep on this
box and returned no matches while Python found the byte immediately, so an audit built on
grep silently reported everything clean. The NUL test below therefore asserts two things:
that the Python scan finds the byte, and that the grep-based approach does not.

Credential fixtures are assembled at run time from fragments. A complete credential-shaped
string committed to disk gets a push rejected by GitHub's secret scanning, and that scan
reads full history, so a later fix does not help.
"""

import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from canary.redact import redact_env, redact_obj, redact_text  # noqa: E402

sys.path.insert(0, str(ROOT / "checker"))
import independent_check as ic  # noqa: E402


def fake_token(prefix: str, body_char: str, length: int) -> str:
    """Build a credential-shaped fixture at run time; never store one whole on disk."""
    return prefix + body_char * length


class TestRedactText(unittest.TestCase):
    def test_redacts_a_github_shaped_token(self):
        tok = fake_token("ghp_", "A", 36)
        out = redact_text(f"Authorization: {tok}")
        self.assertNotIn(tok, out)
        self.assertIn("<REDACTED:GITHUB_TOKEN>", out)

    def test_redacts_the_home_directory(self):
        import os
        home = os.path.expanduser("~")
        self.assertEqual(redact_text(f"{home}/x/y"), "~/x/y")

    def test_leaves_ordinary_text_alone(self):
        s = "npx -y @playwright/mcp@latest"
        self.assertEqual(redact_text(s), s)

    def test_aws_rule_is_case_sensitive(self):
        # A case-insensitive AKIA rule matches ordinary base64 and turns every page with
        # an embedded image into a false alarm.
        lookalike = "AkiAqaMkgIem1yaUXNKiJ2M"
        self.assertEqual(redact_text(lookalike), lookalike)


class TestRedactObj(unittest.TestCase):
    def test_drops_values_under_credential_shaped_key_names(self):
        out = redact_obj({"headers": {"Authorization": "Bearer abc123-not-a-real-token"}})
        self.assertEqual(out["headers"]["Authorization"], "<REDACTED:BY_KEY_NAME>")

    def test_keeps_env_var_placeholders(self):
        out = redact_obj({"headers": {"Authorization": "Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN}"}})
        self.assertIn("${GITHUB_PERSONAL_ACCESS_TOKEN}", out["headers"]["Authorization"])

    def test_key_name_lists_survive(self):
        # header_keys holds key *names*, which are the finding. Redacting it by the
        # substring rule would silently delete the interesting part of the inventory.
        out = redact_obj({"header_keys": ["Authorization", "X-Api-Key"]})
        self.assertEqual(out["header_keys"], ["Authorization", "X-Api-Key"])

    def test_env_values_never_survive(self):
        out = redact_env({"SECRET_A": "hunter2", "PLACEHOLDER": "${SOME_VAR}", "BLANK": ""})
        self.assertEqual(out["SECRET_A"], "<REDACTED:ENV_VALUE>")
        self.assertEqual(out["PLACEHOLDER"], "${SOME_VAR}")
        self.assertEqual(out["BLANK"], "<EMPTY>")


class TestNulScan(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.dir.name) / "has_nul.txt"
        secret = fake_token("ghp_", "B", 36)
        # A real NUL byte, written here on purpose so the scanner has something to find.
        self.path.write_bytes(b"prefix\x00" + secret.encode() + b"\nsuffix\n")
        self.clean = pathlib.Path(self.dir.name) / "clean.txt"
        self.clean.write_text("nothing to see\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_python_scan_finds_the_nul(self):
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_nul_bytes([self.path])
        self.assertEqual(len(ic.FAILURES), 1)
        self.assertIn("NUL byte", ic.FAILURES[0])

    def test_python_scan_is_quiet_on_a_clean_file(self):
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_nul_bytes([self.clean])
        self.assertEqual(ic.FAILURES, [])
        self.assertEqual(len(ic.NOTES), 1)

    def test_grep_I_skips_the_file_the_python_scan_reads(self):
        """The reason the scan is written in Python and not in grep.

        `grep -I` classifies a file containing a NUL as binary and skips it, so the
        credential in it is invisible to a text sweep. If a future grep on this box starts
        reporting the match, this test fails and the comment above it should be revisited.
        """
        proc = subprocess.run(["grep", "-I", "-c", "ghp_", str(self.path)],
                              capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0,
                            f"grep -I unexpectedly read a NUL-containing file: {proc.stdout!r}")
        # Without -I the same grep does see it, which proves the file really does contain
        # the string and the skip above is about the NUL, not about a missing match.
        proc2 = subprocess.run(["grep", "-a", "-c", "ghp_", str(self.path)],
                               capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 0)
        self.assertEqual(proc2.stdout.strip(), "1")


class TestSecretAndHomeScans(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_secret_scan_flags_a_credential_shaped_string(self):
        p = self.d / "leak.txt"
        p.write_text(fake_token("AKIA", "Q", 16) + "\n")
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_secrets([p])
        self.assertEqual(len(ic.FAILURES), 1)

    def test_secret_scan_ignores_a_base64_lookalike(self):
        p = self.d / "image.txt"
        p.write_text("data:image/png;base64,AkiAqaMkgIem1yaUXNKiJ2M\n")
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_secrets([p])
        self.assertEqual(ic.FAILURES, [])

    def test_home_path_scan_flags_an_absolute_home_path(self):
        p = self.d / "path.txt"
        p.write_text("/home/" + "someuser" + "/Projects/x\n")
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_home_paths([p])
        self.assertEqual(len(ic.FAILURES), 1)

    def test_home_path_scan_ignores_a_tilde_path(self):
        p = self.d / "path2.txt"
        p.write_text("~/Projects/x\n")
        ic.FAILURES.clear()
        ic.NOTES.clear()
        ic.scan_home_paths([p])
        self.assertEqual(ic.FAILURES, [])


if __name__ == "__main__":
    unittest.main()
