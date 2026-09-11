#!/usr/bin/env python3
"""Offline Git fixtures for the pinned usrsctp source checkout helper."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "build_usrsctp", Path(__file__).with_name("build_usrsctp.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def git(*args):
    return subprocess.run(
        ["git", *map(str, args)], check=True,
        capture_output=True, text=True).stdout.strip()


class SourceCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="usrsctp-checkout-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.upstream = self.root / "upstream"
        git("init", self.upstream)
        git("-C", self.upstream, "config", "user.name", "Checkout Test")
        git("-C", self.upstream, "config", "user.email", "test@example.invalid")
        git("-C", self.upstream, "config", "commit.gpgsign", "false")
        (self.upstream / "tracked").write_text("pinned content\n")
        git("-C", self.upstream, "add", "tracked")
        git("-C", self.upstream, "commit", "-m", "pinned revision")
        self.pinned = git("-C", self.upstream, "rev-parse", "HEAD")
        (self.upstream / "tracked").write_text("later content\n")
        git("-C", self.upstream, "commit", "-am", "later revision")
        for name, value in (("REPOSITORY", str(self.upstream)),
                            ("REVISION", self.pinned)):
            replacement = patch.object(builder, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)

    def assert_pinned_clean(self, source):
        self.assertEqual(git("-C", source, "rev-parse", "HEAD"), self.pinned)
        self.assertEqual(git("-C", source, "status", "--porcelain"), "")
        self.assertEqual((source / "tracked").read_text(), "pinned content\n")

    def test_fresh_clone_checks_out_pinned_revision(self):
        source = self.root / "fresh"
        builder.checkout_source(source, offline=False)
        self.assert_pinned_clean(source)

    def test_existing_clean_checkout_can_select_pin_offline(self):
        source = self.root / "existing"
        git("clone", self.upstream, source)
        builder.checkout_source(source, offline=True)
        self.assert_pinned_clean(source)

    def test_existing_modified_checkout_is_preserved(self):
        for kind in ("tracked", "staged", "untracked"):
            with self.subTest(kind=kind):
                source = self.root / kind
                git("clone", self.upstream, source)
                path = source / ("untracked" if kind == "untracked" else "tracked")
                path.write_text("user changes\n")
                if kind == "staged":
                    git("-C", source, "add", "tracked")
                before = git("-C", source, "rev-parse", "HEAD")
                status = git("-C", source, "status", "--porcelain")
                with self.assertRaisesRegex(RuntimeError, "modified source checkout"):
                    builder.checkout_source(source, offline=True)
                self.assertEqual(git("-C", source, "rev-parse", "HEAD"), before)
                self.assertEqual(git("-C", source, "status", "--porcelain"), status)
                self.assertEqual(path.read_text(), "user changes\n")

    def test_offline_missing_checkout_is_rejected(self):
        source = self.root / "missing"
        with self.assertRaisesRegex(RuntimeError, "requires an existing checkout"):
            builder.checkout_source(source, offline=True)
        self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
