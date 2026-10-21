"""Commit the current CI summary to the tested branch without changing its checkout."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import tempfile


SUMMARY_PATH = Path("conformance/SUMMARY.md")
RUN_MARKER = re.compile(
    r"<!-- oidc-conformance: run_id=([1-9][0-9]*) run_attempt=([1-9][0-9]*) -->"
)


@dataclass(frozen=True)
class Run:
    branch: str
    run_id: int
    attempt: int

    @property
    def order(self):
        return self.run_id, self.attempt


def git(repository, *arguments, check=True):
    result = subprocess.run(
        ["git", *map(str, arguments)], cwd=repository,
        capture_output=True, text=True, encoding="utf-8",
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Git command failed")
    return result


def current_run(environment):
    ref = environment.get("GITHUB_REF", "")
    if environment.get("GITHUB_REF_TYPE") != "branch" or not ref.startswith("refs/heads/"):
        return None
    branch = environment.get("GITHUB_REF_NAME", "")
    if not branch or ref != "refs/heads/" + branch:
        raise ValueError("The branch name does not match GITHUB_REF")
    values = [environment.get("GITHUB_RUN_ID", ""), environment.get("GITHUB_RUN_ATTEMPT", "")]
    if any(not re.fullmatch(r"[1-9][0-9]*", value) for value in values):
        raise ValueError("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be positive integers")
    return Run(branch, *(int(value) for value in values))


def marker_order(markdown):
    markers = RUN_MARKER.findall(markdown)
    if len(markers) > 1:
        raise ValueError("The summary contains multiple CI run markers")
    return tuple(map(int, markers[0])) if markers else None


def summary_destination(worktree):
    """The remote branch must not redirect the report outside the worktree."""
    destination = worktree / SUMMARY_PATH
    for part in (destination.parent, destination):
        if part.is_symlink():
            raise ValueError("The summary destination must not contain symlinks")
    if not destination.resolve().is_relative_to(worktree.resolve()):
        raise ValueError("The summary destination escapes the temporary worktree")
    return destination


@contextmanager
def branch_worktree(repository):
    with tempfile.TemporaryDirectory(prefix="identity-conformance-summary-") as directory:
        temporary = Path(directory).resolve()
        worktree = temporary / "checkout"
        git(repository, "worktree", "add", "--detach", worktree, "FETCH_HEAD")
        try:
            yield worktree
        finally:
            # Only remove the checkout allocated immediately above, never caller paths.
            if worktree.parent.resolve() != temporary:
                raise ValueError("Refusing to remove a worktree outside its temporary directory")
            git(repository, "worktree", "remove", "--force", worktree)


def commit_summary(summary=SUMMARY_PATH, repository=Path.cwd(), environment=None):
    environment = os.environ if environment is None else environment
    run = current_run(environment)
    if run is None:
        print("Skipping repository summary publication: this is not a branch run.")
        return False
    repository = Path(repository).resolve()
    git(repository, "check-ref-format", "refs/heads/" + run.branch)
    source = Path(summary)
    if not source.is_absolute():
        source = repository / source
    if source.is_symlink() or not source.is_file():
        raise ValueError("The generated summary must be a regular file, not a symlink")
    markdown = source.read_text(encoding="utf-8")
    if marker_order(markdown) != run.order:
        raise ValueError("The generated summary does not match the current CI run and attempt")

    for attempt in range(3):
        git(repository, "fetch", "--no-tags", "origin", "refs/heads/" + run.branch)
        with branch_worktree(repository) as worktree:
            destination = summary_destination(worktree)
            if destination.exists():
                previous = marker_order(destination.read_text(encoding="utf-8"))
                if previous is not None and previous >= run.order:
                    print("Skipping repository summary publication: this run or a newer run is already published.")
                    return False
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(markdown, encoding="utf-8", newline="\n")
            git(worktree, "add", "--", SUMMARY_PATH.as_posix())
            if not git(worktree, "diff", "--cached", "--quiet", check=False).returncode:
                print("Repository summary is unchanged.")
                return False
            git(
                worktree,
                "-c", "user.name=github-actions[bot]",
                "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                "commit", "--only", "-m",
                f"docs: update OIDC conformance summary for run {run.run_id} (attempt {run.attempt})",
                "--", SUMMARY_PATH.as_posix(),
            )
            commit = git(worktree, "rev-parse", "HEAD").stdout.strip()
            # Checkout's credential configuration may be scoped to the original path.
            push = git(repository, "push", "origin", commit + ":refs/heads/" + run.branch, check=False)
            if not push.returncode:
                print(f"Published conformance/SUMMARY.md to {run.branch}.")
                return True
            # Retry only a fast-forward race; authentication and policy failures matter.
            rejected = push.stderr + push.stdout
            if attempt == 2 or not any(reason in rejected for reason in ("[rejected]", "fetch first", "non-fast-forward")):
                raise RuntimeError(rejected.strip() or "Summary push failed")
    raise RuntimeError("Summary push did not complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=SUMMARY_PATH)
    commit_summary(parser.parse_args().summary)
