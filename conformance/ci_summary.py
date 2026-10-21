"""Generate the standalone Markdown report for an OIDC conformance CI run."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from urllib.parse import quote, urlsplit

from plans import ci_cases


RESULT_COUNTS = ("PASSED", "FAILED", "WARNING", "SKIPPED", "REVIEW", "MANUAL_REVIEW_REQUIRED")


def _cell(value):
    return str(value).replace("\r", "").replace("\n", " ").replace("|", "\\|")


def _link(label, url):
    if not isinstance(url, str):
        return "—"
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return "—"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "—"
    return f"[{label}]({quote(url.strip(), safe=':/?&=%+#@-._~')})"


def _cases(environment):
    defaults = ci_cases()
    configured = environment.get("PROFILES", "")
    if not configured.strip():
        return defaults
    ids = json.loads(configured)
    if not isinstance(ids, list) or not all(isinstance(case_id, str) for case_id in ids):
        raise ValueError("PROFILES must be a JSON array of case IDs")
    by_id = {case["id"]: case for case in defaults}
    return [by_id.get(case_id, {"id": case_id, "response_type": ""}) for case_id in ids]


def _artifact_case(directory, cases, environment):
    run_id = environment.get("GITHUB_RUN_ID", "")
    for case in cases:
        base = f"oidc-conformance-{case['id']}-{run_id}"
        if directory.name == base:
            return case["id"], 1
        if directory.name.startswith(base + "-"):
            attempt = directory.name[len(base) + 1:]
            if attempt.isdecimal():
                return case["id"], int(attempt)
    return None


def _read_reports(reports_dir, cases, environment):
    latest = {}
    for directory in sorted(path for path in reports_dir.rglob("*") if path.is_dir()):
        artifact = _artifact_case(directory, cases, environment)
        if artifact:
            case_id, attempt = artifact
            if case_id not in latest or attempt >= latest[case_id][0]:
                latest[case_id] = (attempt, directory)
    reports = {}
    for case_id, (_, directory) in latest.items():
        path = directory / "results.json"
        if not path.exists():
            reports[case_id] = (None, directory, None)
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                raise ValueError("report is not an object")
            if report.get("case_id", case_id) != case_id:
                raise ValueError("report case ID does not match its artifact")
            reports[case_id] = (report, path.parent, None)
        except (OSError, UnicodeError, ValueError) as error:
            reports[case_id] = (None, path.parent, type(error).__name__)
    return reports


def _row(case, evidence):
    report, directory, error = evidence or (None, None, None)
    plan_url = report.get("plan_url") if report else None
    if directory is not None and (directory / "plan-url.txt").exists():
        try:
            plan_url = (directory / "plan-url.txt").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            pass
    response_type = (report.get("response_type") if report else None) or case.get("response_type") or "—"
    counts = None
    status = "INCOMPLETE" if error else "NO_REPORT"
    if report is not None:
        raw_counts = report.get("summary")
        declared_counts = None
        if isinstance(raw_counts, dict) and all(
            isinstance(raw_counts.get(key, 0), int)
            and not isinstance(raw_counts.get(key, 0), bool)
            and raw_counts.get(key, 0) >= 0
            for key in RESULT_COUNTS
        ):
            declared_counts = {key: raw_counts.get(key, 0) for key in RESULT_COUNTS}
        results = report.get("results")
        if isinstance(results, list) and all(isinstance(result, dict) for result in results):
            counts = dict.fromkeys(RESULT_COUNTS, 0)
            for result in results:
                outcome = result.get("result")
                if result.get("status") == "MANUAL_REVIEW_REQUIRED":
                    counts["MANUAL_REVIEW_REQUIRED"] += 1
                elif result.get("status") == "FINISHED" and outcome in RESULT_COUNTS:
                    counts[outcome] += 1
                else:
                    counts["FAILED"] += 1
        else:
            counts = declared_counts
        plan = report.get("plan")
        modules = plan.get("modules") if isinstance(plan, dict) else None
        complete = (
            counts is not None
            and counts == declared_counts
            and isinstance(results, list)
            and bool(results)
            and isinstance(modules, list)
            and len(results) == len(modules)
            and all(isinstance(result, dict) and result.get("status") == "FINISHED" for result in results)
            and sum(counts.values()) == len(results)
        )
        status = ("FAILED" if counts["FAILED"] else "COMPLETED") if complete else "INCOMPLETE"
    values = [counts[key] if counts is not None else "—" for key in RESULT_COUNTS[:4]]
    values.append(counts["REVIEW"] + counts["MANUAL_REVIEW_REQUIRED"] if counts is not None else "—")
    cells = [case["id"], response_type, status, *values, _link("Plan", plan_url)]
    return "| " + " | ".join(_cell(value) for value in cells) + " |", status, counts


def generate_summary(reports_dir=Path("reports"), environment=None):
    """Render every expected case, retaining failures and missing evidence."""
    environment = os.environ if environment is None else environment
    cases = _cases(environment)
    reports = _read_reports(Path(reports_dir), cases, environment)
    server = environment.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = environment.get("GITHUB_REPOSITORY", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "1")
    base = f"{server}/{repository}"
    run_url = f"{base}/actions/runs/{run_id}/attempts/{attempt}"
    sha = environment.get("GITHUB_SHA", "")
    rows = [_row(case, reports.get(case["id"])) for case in cases]
    states = Counter(status for _, status, _ in rows)
    totals = Counter()
    for _, _, counts in rows:
        if counts:
            totals.update(counts)
    lines = [
        "# OIDC conformance summary",
        "",
        f"<!-- oidc-conformance: run_id={run_id} run_attempt={attempt} -->",
        "",
        "This file is generated from the latest completed report publication. It records the run below, including failures and incomplete plans.",
        "",
        f"- CI run: {_link(f'Run {run_id}, attempt {attempt}', run_url)}",
        f"- Workflow: {_link('Latest CI runs', base + '/actions/workflows/oidc-conformance.yml')}",
        f"- Source commit: {_link(sha, base + '/commit/' + quote(sha, safe='')) if sha else '—'}",
        f"- Branch: `{_cell(environment.get('GITHUB_REF_NAME', 'unknown')).replace('`', chr(39))}`",
        f"- Preparation: **{_cell(environment.get('PREPARE_RESULT', 'unknown'))}**",
        f"- Plan jobs: **{_cell(environment.get('PLAN_JOBS_RESULT', 'unknown'))}**",
        "",
        f"Plans: **{len(cases)}** expected; **{states['COMPLETED']}** completed; **{states['FAILED']}** failed; **{states['INCOMPLETE']}** incomplete; **{states['NO_REPORT']}** without a report.",
        "",
        f"Recorded module results: **{totals['PASSED']}** passed, **{totals['FAILED']}** failed, **{totals['WARNING']}** warnings, **{totals['SKIPPED']}** skipped, **{totals['REVIEW'] + totals['MANUAL_REVIEW_REQUIRED']}** requiring review.",
        "",
        "## Plan results",
        "",
        "| Plan | Response type | Status | Passed | Failed | Warnings | Skipped | UI review | Official results |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        *[row for row, _, _ in rows],
        "",
        "`COMPLETED` means all expected modules finished; warnings, skips, and review outcomes still require inspection. `INCOMPLETE` includes interrupted, invalid, or internally inconsistent reports. Module counts are recomputed from individual results where available. Missing evidence is never treated as a pass.",
        "",
        "For each plan, this report uses the latest available evidence from this run. Rerunning failed jobs can reuse successful plans from earlier attempts; a newer plan attempt replaces its earlier evidence even when its report is missing or invalid.",
        "",
        "Results apply to the source commit, build features, client configuration, and deployment tested by this CI run. This report does not establish OpenID certification.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    parser.add_argument("--output", type=Path, default=Path("conformance/SUMMARY.md"))
    args = parser.parse_args()
    summary = generate_summary(args.reports_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(summary, encoding="utf-8", newline="\n")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary and Path(step_summary).resolve() != args.output.resolve():
        with Path(step_summary).open("a", encoding="utf-8", newline="\n") as output:
            output.write(summary)
    print(f"Wrote OIDC conformance summary: {args.output}")


if __name__ == "__main__":
    main()
