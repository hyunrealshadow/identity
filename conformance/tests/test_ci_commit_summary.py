from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_commit_summary import commit_summary, git as publish_git, marker_order, summary_destination


@unittest.skipUnless(shutil.which("git"), "requires Git CLI")
class CommitSummaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.remote = self.directory / "origin.git"
        self.checkout = self.directory / "checkout"
        self.git(self.directory, "init", "--bare", self.remote)
        self.git(self.directory, "clone", self.remote, self.checkout)
        self.git(self.checkout, "checkout", "-b", "main")
        self.git(self.checkout, "config", "user.name", "Test Author")
        self.git(self.checkout, "config", "user.email", "test@example.com")
        (self.checkout / "README.md").write_text("original\n")
        (self.checkout / "conformance").mkdir()
        (self.checkout / "conformance/SUMMARY.md").write_text("No report yet.\n")
        self.git(self.checkout, "add", ".")
        self.git(self.checkout, "commit", "-m", "initial")
        self.git(self.checkout, "push", "origin", "main")
        self.original_head = self.git(self.checkout, "rev-parse", "HEAD").stdout.strip()
        self.environment = {
            "GITHUB_REF": "refs/heads/main", "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_NAME": "main", "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1",
        }
        self.source = self.directory / "generated-summary.md"
        self.write_summary()

    def git(self, repository, *arguments, check=True):
        result = subprocess.run(
            ["git", *map(str, arguments)], cwd=repository,
            capture_output=True, text=True, encoding="utf-8",
        )
        if check and result.returncode:
            self.fail(result.stderr or result.stdout)
        return result

    def write_summary(self, run_id=100, attempt=1):
        self.source.write_text(
            f"<!-- oidc-conformance: run_id={run_id} run_attempt={attempt} -->\n"
            f"# Run {run_id}, attempt {attempt}\n", encoding="utf-8",
        )

    def remote_file(self, path):
        return self.git(self.remote, "show", "main:" + path).stdout

    def publish(self):
        return commit_summary(self.source, self.checkout, self.environment)

    def test_preserves_new_remote_edits_and_local_dirty_checkout(self):
        contributor = self.directory / "contributor"
        self.git(self.directory, "clone", "--branch", "main", self.remote, contributor)
        self.git(contributor, "config", "user.name", "Contributor")
        self.git(contributor, "config", "user.email", "contributor@example.com")
        (contributor / "README.md").write_text("new remote content\n")
        self.git(contributor, "add", "README.md")
        self.git(contributor, "commit", "-m", "concurrent unrelated change")
        remote_parent = self.git(contributor, "rev-parse", "HEAD").stdout.strip()
        self.git(contributor, "push", "origin", "main")

        (self.checkout / "README.md").write_text("local staged change\n")
        self.git(self.checkout, "add", "README.md")
        (self.checkout / "conformance/SUMMARY.md").write_text("local dirty summary\n")
        before_status = self.git(self.checkout, "status", "--porcelain").stdout
        self.assertTrue(self.publish())

        self.assertEqual(self.remote_file("README.md"), "new remote content\n")
        self.assertEqual(self.remote_file("conformance/SUMMARY.md"), self.source.read_text())
        self.assertEqual(self.git(self.remote, "rev-parse", "main^").stdout.strip(), remote_parent)
        self.assertEqual(
            self.git(self.remote, "diff-tree", "--no-commit-id", "--name-only", "-r", "main").stdout.strip(),
            "conformance/SUMMARY.md",
        )
        self.assertEqual(self.git(self.checkout, "status", "--porcelain").stdout, before_status)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD").stdout.strip(), self.original_head)
        self.assertEqual((self.checkout / "conformance/SUMMARY.md").read_text(), "local dirty summary\n")
        self.assertEqual(self.git(self.checkout, "config", "user.name").stdout.strip(), "Test Author")
        self.assertEqual(len(self.git(self.checkout, "worktree", "list", "--porcelain").stdout.split("worktree ")) - 1, 1)

    def test_old_run_and_duplicate_attempt_cannot_replace_newer_summary(self):
        self.assertTrue(self.publish())
        published_head = self.git(self.remote, "rev-parse", "main").stdout
        self.assertFalse(self.publish())
        self.write_summary(99, 5)
        self.environment.update(GITHUB_RUN_ID="99", GITHUB_RUN_ATTEMPT="5")
        self.assertFalse(self.publish())
        self.assertEqual(self.git(self.remote, "rev-parse", "main").stdout, published_head)
        self.assertEqual(marker_order(self.remote_file("conformance/SUMMARY.md")), (100, 1))

    def test_later_attempt_and_new_run_replace_report(self):
        self.assertTrue(self.publish())
        self.write_summary(100, 2)
        self.environment["GITHUB_RUN_ATTEMPT"] = "2"
        self.assertTrue(self.publish())
        self.assertEqual(marker_order(self.remote_file("conformance/SUMMARY.md")), (100, 2))
        self.write_summary(101, 1)
        self.environment.update(GITHUB_RUN_ID="101", GITHUB_RUN_ATTEMPT="1")
        self.assertTrue(self.publish())
        self.assertEqual(marker_order(self.remote_file("conformance/SUMMARY.md")), (101, 1))

    def test_retries_fast_forward_race_without_losing_remote_change(self):
        contributor = self.directory / "racing-contributor"
        self.git(self.directory, "clone", "--branch", "main", self.remote, contributor)
        self.git(contributor, "config", "user.name", "Contributor")
        self.git(contributor, "config", "user.email", "contributor@example.com")
        pushes = 0

        def race(repository, *arguments, check=True):
            nonlocal pushes
            if arguments[0] == "push":
                self.assertEqual(repository, self.checkout.resolve())
                if pushes == 0:
                    (contributor / "README.md").write_text("change while summary was committing\n")
                    self.git(contributor, "add", "README.md")
                    self.git(contributor, "commit", "-m", "concurrent push")
                    self.git(contributor, "push", "origin", "main")
                pushes += 1
            return publish_git(repository, *arguments, check=check)

        with patch("ci_commit_summary.git", side_effect=race):
            self.assertTrue(self.publish())
        self.assertEqual(pushes, 2)
        self.assertEqual(self.remote_file("README.md"), "change while summary was committing\n")
        self.assertEqual(marker_order(self.remote_file("conformance/SUMMARY.md")), (100, 1))

    def test_tag_run_is_skipped_without_needing_generated_file(self):
        self.environment.update(GITHUB_REF="refs/tags/v1", GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="v1")
        self.source.unlink()
        self.assertFalse(self.publish())
        self.assertEqual(self.git(self.remote, "rev-parse", "main").stdout.strip(), self.original_head)

    def test_report_marker_must_match_run_before_any_publication(self):
        self.write_summary(99, 1)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.publish()
        self.assertEqual(self.git(self.remote, "rev-parse", "main").stdout.strip(), self.original_head)

    def test_invalid_branch_metadata_is_rejected(self):
        self.environment["GITHUB_REF_NAME"] = "other"
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.publish()

    def test_remote_policy_rejection_is_reported_and_worktree_removed(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\necho 'summary publication denied by policy' >&2\nexit 1\n")
        hook.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "denied by policy"):
            self.publish()
        self.assertEqual(self.git(self.remote, "rev-parse", "main").stdout.strip(), self.original_head)
        self.assertEqual(len(self.git(self.checkout, "worktree", "list", "--porcelain").stdout.split("worktree ")) - 1, 1)

    def test_destination_rejects_directory_escape(self):
        outside = self.directory / "outside"
        outside.mkdir()
        fake_worktree = self.directory / "fake-worktree"
        fake_worktree.mkdir()
        try:
            (fake_worktree / "conformance").symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"Symlinks unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            summary_destination(fake_worktree)

    def test_generated_summary_symlink_is_rejected(self):
        link = self.directory / "summary-link.md"
        try:
            link.symlink_to(self.source)
        except OSError as error:
            self.skipTest(f"Symlinks unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "regular file"):
            commit_summary(link, self.checkout, self.environment)


if __name__ == "__main__":
    unittest.main()
