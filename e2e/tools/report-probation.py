#!/usr/bin/env python3
"""Reports which e2e tests on probation have passed for long enough to leave it.

A test may leave the probation list in e2e/.config/nextest.toml once it has
passed RUNS_NEEDED nightly runs of the full profile in a row on every backend
that builds it. Only runs since it went on the list count. The time it went on
is that of the commit that last added its entry, read from the file's git
history, so the clone needs that history.

Usage:
    e2e/tools/report-probation.py <runs-dir> [--ready FILE]

<runs-dir> holds a directory per run, named 0 for the newest, then 1, 2 and so
on. Each holds a `created-at` file with the time the run started in ISO 8601, a
`platforms` file naming the backends the run had, one per line, and the run's
artifacts, a directory each:

    e2e-tests-<platform>/test-list.txt  the oneline output of cargo nextest list
    e2e-junit-<platform>/junit.xml      the full profile's JUnit report

A run with no platforms tested nothing and is left out. In any other run, a
platform with no JUnit report, or one whose setup failed, counts as a failure
for the tests it builds, since its job stopped before it could report. A
platform whose job stopped before its test list too is taken to build what its
nearest run with a list says. If no run has a list for it, every test counts as
a failure there. A test a platform's report leaves out, such as one ignored
there, did not run there.

Prints a Markdown report of every test on probation, how many runs in a row it
has passed and how many of its runs failed. --ready writes the names of the
tests that may leave, one per line.
"""

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from pathlib import Path

RUNS_NEEDED = 7

E2E = Path(__file__).resolve().parent.parent
CONFIG = Path(".config/nextest.toml")
PROBATION_FILTER = E2E / "tools" / "probation-filter.sh"

# A testcase with any of these children did not pass.
NOT_PASSED = {
    "failure",
    "error",
    "skipped",
    "flakyFailure",
    "flakyError",
    "rerunFailure",
    "rerunError",
}


def probation_list(text):
    """Returns the names on the probation list in `text`, the contents of a
    nextest.toml, or `None` if its list does not parse."""
    command = [str(PROBATION_FILTER), "--names", "-"]
    output = subprocess.run(command, input=text, capture_output=True, text=True)
    if output.returncode != 0:
        return None
    return output.stdout.split()


def git(*args, check=True):
    """Returns what git prints for `args`, or `None` if it fails and `check` is
    false."""
    command = ["git", "-C", str(E2E), *args]
    output = subprocess.run(
        command, capture_output=True, text=True, check=check
    )
    return output.stdout.strip() if output.returncode == 0 else None


def added_at(name):
    """Returns when `name` last went on the probation list, or `None` while it
    is not committed."""
    # The loop walks the commits that changed the file, newest first, and stops
    # at the first one whose list lacks `name`. Other edits of the file leave
    # the time alone.
    since = None
    for line in git("log", "--format=%H %cI", "--", str(CONFIG)).splitlines():
        commit, stamp = line.split()
        text = git("show", f"{commit}:./{CONFIG}", check=False)
        if text is None or name not in (probation_list(text) or []):
            break
        since = datetime.fromisoformat(stamp)
    return since


class Run:
    """One run's backends, test lists and JUnit reports."""

    def __init__(self, directory):
        self.created_at = datetime.fromisoformat(
            (directory / "created-at").read_text().strip()
        )
        platforms = directory / "platforms"
        # The backends the run had, as its jobs name them.
        self.platforms = []
        if platforms.exists():
            self.platforms = platforms.read_text().split()
        # platform -> {(binary, name)}
        self.lists = {}
        # platform -> {(binary, name): passed}, for a report whose setup passed
        self.results = {}
        # platform -> {(binary, name)}, from the nearest run with a list, for a
        # platform this run has none for
        self.borrowed = {}
        for artifact in directory.iterdir():
            if artifact.name.startswith("e2e-tests-"):
                platform = artifact.name.removeprefix("e2e-tests-")
                self.lists[platform] = read_list(artifact / "test-list.txt")
            elif artifact.name.startswith("e2e-junit-"):
                platform = artifact.name.removeprefix("e2e-junit-")
                results = read_junit(artifact / "junit.xml")
                if results is not None:
                    self.results[platform] = results

    def passed(self, name):
        """Returns whether `name` passed on every platform that ran it."""
        ran = []
        for platform in self.platforms:
            # A platform with no list of its own, such as one whose job stopped
            # before it, goes by the nearest run's list. Its JUnit report, if it
            # has one, still says how the tests went.
            tests = self.lists.get(platform, self.borrowed.get(platform))
            if tests is None:
                return False
            built = [test for test in tests if test[1] == name]
            if not built:
                continue
            results = self.results.get(platform)
            if results is None:
                return False
            ran += [results[test] for test in built if test in results]
        return bool(ran) and all(ran)


def read_list(path):
    tests = set()
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2:
            tests.add((fields[0], fields[1]))
    return tests


def read_junit(path):
    """Returns whether each test in the JUnit report at `path` passed, or `None`
    if there is no report or its setup script failed."""
    if not path.exists():
        return None
    results = {}
    for case in ElementTree.parse(path).iter("testcase"):
        passed = not any(child.tag in NOT_PASSED for child in case)
        binary = case.get("classname", "")
        if binary.startswith("@setup-script:"):
            if not passed:
                return None
            continue
        results[(binary, case.get("name"))] = passed
    return results


def borrow_lists(runs):
    """Gives each run, for a platform it has no test list for, the list of the
    nearest run that has one."""
    for index, run in enumerate(runs):
        for platform in run.platforms:
            if platform in run.lists:
                continue
            nearest = sorted(range(len(runs)), key=lambda i: abs(i - index))
            for other in nearest:
                if platform in runs[other].lists:
                    run.borrowed[platform] = runs[other].lists[platform]
                    break


def history(runs, name, since):
    """Returns three counts over the runs since `since`: the runs in a row, from
    the newest, that `name` passed, the runs it failed, and all the runs."""
    passed = [run.passed(name) for run in runs if run.created_at >= since]
    streak = passed.index(False) if False in passed else len(passed)
    return streak, passed.count(False), len(passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("runs", type=Path, help="a directory per run, 0 newest")
    parser.add_argument("--ready", type=Path, help="write the ready names here")
    args = parser.parse_args()

    names = probation_list((E2E / CONFIG).read_text())
    if names is None:
        # Run the parser again where its message reaches stderr.
        command = [str(PROBATION_FILTER), "--names"]
        subprocess.run(command, stdout=subprocess.DEVNULL)
        sys.exit(1)
    ready = []
    if not names:
        print("No test is on probation.")
    else:
        if git("rev-parse", "--is-shallow-repository") == "true":
            sys.exit(
                "report-probation: reading when entries were added: the clone "
                "is shallow"
            )
        directories = sorted(
            (path for path in args.runs.iterdir() if path.name.isdigit()),
            key=lambda path: int(path.name),
        )
        runs = [run for run in map(Run, directories) if run.platforms]
        borrow_lists(runs)
        print(
            f"A test leaves probation once it has passed {RUNS_NEEDED} nightly "
            "runs in a row on every backend that builds it, counted from when "
            "it went on the list in `e2e/.config/nextest.toml`.\n"
        )
        print(
            "| Test | On probation since | Runs passed in a row "
            "| Runs failed since then |"
        )
        print("| --- | --- | --- | --- |")
        for name in names:
            since = added_at(name)
            if since is None:
                print(f"| `{name}` | not committed | 0 of {RUNS_NEEDED} | |")
                continue
            streak, failed, total = history(runs, name, since)
            shown = f"{min(streak, RUNS_NEEDED)} of {RUNS_NEEDED}"
            if streak >= RUNS_NEEDED:
                ready.append(name)
                shown += ", ready to leave"
            day = since.astimezone(timezone.utc).date()
            print(f"| `{name}` | {day} | {shown} | {failed} of {total} |")
        if ready:
            print(
                "\nA test that fails rarely can still pass "
                f"{RUNS_NEEDED} runs in a row, so check the runs it failed "
                "before removing it from the probation list. Once removed, it "
                "runs on pull requests."
            )
    if args.ready:
        args.ready.write_text("".join(f"{name}\n" for name in ready))


if __name__ == "__main__":
    main()
