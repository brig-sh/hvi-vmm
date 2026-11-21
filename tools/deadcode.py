#!/usr/bin/env python3
"""Reports code that no caller reaches, on every backend.

The crate is a library and a binary. rustc never reports a `pub` item of a
library as dead, so most of the tree is out of reach of the dead_code lint. This
script builds a scratch copy of the crate in which the library's top-level items
are `pub(crate)` and the binary, the examples and the integration tests are
modules of the library. rustc then sees every caller there is, and its
dead_code, unused_imports and unused_crate_dependencies lints report what none
of them reaches. `#[allow(dead_code)]` is stripped from the copy, so an item
kept alive by a waiver is reported as well.

Each target is checked twice, without and with cfg(test). An item is

  dead       when it is unused with cfg(test) on every target that compiles
             its file,
  test-only  when only cfg(test) code uses it, on every target that compiles
             its file,
  partial    when some targets that compile its file use it and others do not.

Dead and test-only items fail the run unless tools/deadcode-allow.txt lists
them. So does an entry in that file that matches nothing. Partial items are
printed and do not fail the run: an item compiled for a backend that does not
use it is often a cfg gate that could be narrower, and not dead code.

Exit status is 0 for a clean run, 1 when there are findings, and 2 on an error
(a failed build, a bad allowlist line, an unreadable raw file). The CI lane files
an issue on 1 and fails on 2.

Usage:
    tools/deadcode.py [--target T]... [--raw-out FILE] [--scan-only]
    tools/deadcode.py --from FILE... [--markdown]

Without --target it checks every target in TARGETS whose rustup target is
installed. A macOS host can check all of them. A Linux host cannot check
aarch64-apple-darwin, so its report can name items that only the macOS backend
uses. --raw-out writes the raw results, and --from reports on raw results from
several hosts, which is how the weekly CI lane combines its Linux and macOS
runs.

The scratch copy and its build live under target/deadcode/.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = ROOT / "target" / "deadcode"
ALLOW = ROOT / "tools" / "deadcode-allow.txt"

TARGETS = [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
]

LINTS = {"dead_code", "unused_imports", "unused_crate_dependencies"}

# The top-level items of src/lib.rs, which the copy makes crate-private.
LIB_PUB = re.compile(
    r"^pub (?=(mod|use|fn|const|static|struct|enum|trait|type) )", re.M
)
CFG_ATTR = re.compile(r"^\s*#\[cfg\((.*)\)\]\s*$")
ALLOW_ATTR = re.compile(
    r"#\[allow\(dead_code\)\]|#\[cfg_attr\([^\]]*allow\(dead_code\)\)\]"
)
INNER_ATTR = re.compile(r"^#!\[(.*)\]\s*$")


def fail(msg):
    """Exits with status 2, which the CI lane tells apart from findings."""
    print("deadcode: " + msg, file=sys.stderr)
    sys.exit(2)


def item_cfgs(file, line):
    """Returns the `#[cfg(...)]` predicates attached to the item at `file:line`
    of the scratch crate. Attributes and comments directly above it count."""
    try:
        lines = (SCRATCH / "crate" / file).read_text().splitlines()
    except OSError:
        return []
    cfgs = []
    i = line - 2
    while i >= 0:
        text = lines[i].strip()
        m = CFG_ATTR.match(text)
        if m:
            cfgs.append(m.group(1))
        elif not (text.startswith("#[") or text.startswith("//")):
            break
        i -= 1
    return cfgs


def target_cfg(target):
    """Returns the cfg set of `target` as a set of `key` and `key="value"`."""
    out = subprocess.run(
        ["rustc", "--print", "cfg", "--target", target],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    return set(out) | {"test"}


def cfg_true(pred, cfg):
    """Evaluates a cfg predicate against a cfg set."""
    toks = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|"[^"]*"|[(),=]', pred)
    pos = 0

    def parse():
        nonlocal pos
        name = toks[pos]
        pos += 1
        if name in ("all", "any", "not") and pos < len(toks) and toks[pos] == "(":
            pos += 1
            vals = []
            while toks[pos] != ")":
                vals.append(parse())
                if toks[pos] == ",":
                    pos += 1
            pos += 1
            if name == "all":
                return all(vals)
            if name == "any":
                return any(vals)
            return not vals[0]
        if pos < len(toks) and toks[pos] == "=":
            val = toks[pos + 1]
            pos += 2
            return (name + "=" + val) in cfg
        return name in cfg

    try:
        return parse()
    except IndexError:
        return True


def fold(src, name, lib):
    """Copies the crate root `src` into the scratch library as module `name`.

    Returns the path of the module file, relative to the scratch root. Lines
    keep their numbers, so a report points into the original file.
    """
    out = []
    mod_cfg = ""
    for line in src.read_text().splitlines():
        m = INNER_ATTR.match(line)
        if m:
            if m.group(1).startswith("cfg("):
                mod_cfg = "#[" + m.group(1) + "]\n"
            out.append("")
            continue
        line = re.sub(r"\bhvi::", "crate::", line)
        line = re.sub(r"^fn main\(\)", "pub fn main()", line)
        out.append(line)
    rel = Path("src") / ("__" + name + ".rs")
    (SCRATCH / "crate" / rel).write_text("\n".join(out) + "\n")
    lib.append(mod_cfg + "#[allow(clippy::all)]\npub mod __" + name + ";\n")
    return rel


def prepare():
    """Builds the scratch crate and returns the map from folded module files
    back to the files they came from."""
    dst = SCRATCH / "crate"
    shutil.rmtree(dst, ignore_errors=True)
    skip = {"target", ".git", ".claude", "e2e", "docs", "guest"}
    shutil.copytree(
        ROOT, dst, ignore=lambda d, names: skip if Path(d) == ROOT else ()
    )
    for path in (dst / "src").rglob("*.rs"):
        text = path.read_text()
        stripped = ALLOW_ATTR.sub("", text)
        if stripped != text:
            path.write_text(stripped)
    lib_rs = dst / "src" / "lib.rs"
    lib = [LIB_PUB.sub("pub(crate) ", lib_rs.read_text())]
    origin = {}
    origin[str(fold(dst / "src" / "main.rs", "bin", lib))] = "src/main.rs"
    for kind in ("examples", "tests"):
        for path in sorted((dst / kind).glob("*.rs")):
            name = kind[0] + "_" + path.stem
            # An integration test's helpers are reached only with cfg(test),
            # and its file is a test, so it is not reported.
            rel = fold(path, name, lib)
            origin[str(rel)] = None if kind == "tests" else kind + "/" + path.name
        shutil.rmtree(dst / kind)
    (dst / "src" / "main.rs").unlink()
    lib_rs.write_text("".join(lib))
    manifest = dst / "Cargo.toml"
    text = re.sub(r"(?ms)^\[\[bin\]\]\n.*?(?=^\[|\Z)", "", manifest.read_text())
    text = text.replace(
        "[package]\n",
        "[package]\nautobins = false\nautoexamples = false\n"
        "autotests = false\nautobenches = false\n",
        1,
    )
    manifest.write_text(text)
    return origin


def installed_targets():
    out = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    return [t for t in TARGETS if t in out]


def check(target, test):
    """Runs one `cargo check` of the scratch library and returns the files it
    compiled and the reported items, as (file, line, name, message)."""
    cmd = ["cargo", "check", "--lib", "--target", target]
    cmd += ["--message-format", "json", "--quiet"]
    if test:
        cmd += ["--profile", "test"]
    env = dict(os.environ)
    # The python3 that the macOS Command Line Tools install sets these to its
    # own SDK, and build scripts then fail to link against it.
    if sys.platform == "darwin":
        for var in ("SDKROOT", "CPATH", "LIBRARY_PATH"):
            env.pop(var, None)
    env["CARGO_TARGET_DIR"] = str(SCRATCH / "target")
    env["RUSTFLAGS"] = "-W unused_crate_dependencies"
    proc = subprocess.run(
        cmd, cwd=SCRATCH / "crate", env=env, capture_output=True, text=True
    )
    files, items, errors = set(), [], []
    crate = (SCRATCH / "crate").resolve()
    for line in proc.stdout.splitlines():
        msg = json.loads(line)
        if msg.get("target", {}).get("name") != "hvi":
            continue
        if msg.get("reason") == "compiler-artifact":
            for f in msg.get("filenames", []):
                files |= dep_info(Path(f), crate)
        if msg.get("reason") != "compiler-message":
            continue
        diag = msg["message"]
        if diag["level"] == "error":
            errors.append(diag["rendered"])
            continue
        code = (diag.get("code") or {}).get("code")
        if code not in LINTS:
            continue
        for span in diag["spans"]:
            if not span["is_primary"]:
                continue
            name = span_text(span)
            if code == "unused_crate_dependencies":
                m = re.search(r"`([^`]+)`", diag["message"])
                name = m.group(1) if m else name
            items.append([span["file_name"], span["line_start"], name,
                          diag["message"],
                          item_cfgs(span["file_name"], span["line_start"])])
    if not files and proc.returncode == 0:
        errors.append("no dep-info found for the hvi library\n")
    if proc.returncode != 0 or errors:
        sys.stderr.write(proc.stderr + "".join(errors))
        fail("cargo check failed for " + target)
    return files, items


def dep_info(artifact, crate):
    """Returns the source files of the crate that the .d file next to a
    compiled artifact lists, relative to the crate root."""
    stem = artifact.name.split(".")[0]
    if stem.startswith("lib"):
        stem = stem[3:]
    d = artifact.parent / (stem + ".d")
    if not d.exists():
        return set()
    files = set()
    # The first line is "<output>: <source> <source> ...". Paths are relative
    # to the crate root, or absolute.
    first = d.read_text().splitlines()[0]
    for dep in first.split(": ", 1)[-1].split():
        p = Path(dep)
        if not p.is_absolute():
            p = crate / p
        try:
            files.add(str(p.resolve().relative_to(crate)))
        except ValueError:
            pass
    return files


def span_text(span):
    for t in span.get("text", []):
        return t["text"][t["highlight_start"] - 1:t["highlight_end"] - 1]
    return "?"


def scan(targets):
    origin = prepare()
    raw = {"origin": origin, "targets": {}}
    for target in targets:
        print("deadcode: checking " + target, file=sys.stderr)
        files, lib = check(target, test=False)
        _, test = check(target, test=True)
        raw["targets"][target] = {"files": sorted(files), "lib": lib,
                                  "test": test,
                                  "cfg": sorted(target_cfg(target))}
    return raw


def merge(raws):
    """Classifies every reported item across the targets of `raws`."""
    origin, targets = {}, {}
    for raw in raws:
        origin.update(raw["origin"])
        targets.update(raw["targets"])
    seen = {}  # (file, name) -> {"lines", "msg", "lib": set, "test": set}
    for target, res in targets.items():
        for mode in ("lib", "test"):
            for file, line, name, msg, cfgs in res[mode]:
                if file in origin and origin[file] is None:
                    continue
                key = (origin.get(file) or file, name)
                entry = seen.setdefault(
                    key, {"lines": set(), "msg": msg, "lib": set(),
                          "test": set(), "file": file, "cfgs": cfgs})
                entry["lines"].add(line)
                entry[mode].add(target)
    out = {"dead": [], "test-only": [], "partial": []}
    for key, e in sorted(seen.items()):
        # A target compiles an item when it compiles the file and the cfg
        # attributes on the item hold for it.
        compiled = {t for t, r in targets.items()
                    if e["file"] in r["files"]
                    and all(cfg_true(c, set(r["cfg"])) for c in e["cfgs"])}
        if compiled <= e["test"]:
            cls = "dead"
        elif compiled <= e["lib"]:
            cls = "test-only"
        else:
            cls = "partial"
        out[cls].append((key, e, sorted(compiled - e["lib"])))
    return out, sorted(targets)


def read_allow():
    allow = {}
    if not ALLOW.exists():
        return allow
    for n, line in enumerate(ALLOW.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            fail("%s:%d needs <path> <item> <reason>" % (ALLOW, n))
        allow[(parts[0], parts[1])] = parts[2]
    return allow


KINDS = [
    ("unused import", "import"),
    ("extern crate", "dependency"),
    ("multiple fields", "field"),
    ("multiple methods", "method"),
    ("multiple associated", "associated item"),
    ("associated function", "associated function"),
    ("associated constant", "associated constant"),
    ("associated item", "associated item"),
    ("method", "method"),
    ("function", "function"),
    ("constant", "constant"),
    ("static", "static"),
    ("struct", "struct"),
    ("enum", "enum"),
    ("variant", "variant"),
    ("field", "field"),
    ("type alias", "type alias"),
    ("trait", "trait"),
]


def kind(msg):
    """Returns what a lint message reports, as a singular noun. A message can
    name several items, and the report shows one row per item."""
    low = msg.lower()
    for prefix, name in KINDS:
        if low.startswith(prefix):
            return name
    return "item"


def where(path, lines, markdown):
    """Returns the location of an item, as a link to the scanned commit when
    the report is Markdown and runs in GitHub Actions."""
    line = min(lines)
    text = "%s:%d" % (path, line)
    env = os.environ
    if not markdown or not all(
        env.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_SHA")
    ):
        return text if not markdown else "`%s`" % text
    url = "%s/%s/blob/%s/%s#L%d" % (
        env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"], env["GITHUB_SHA"],
        path, line,
    )
    return "[%s](%s)" % (text, url)


def report(raws, markdown):
    classes, targets = merge(raws)
    allow = read_allow()
    used = set()
    failing = 0
    lines = []
    h = "### " if markdown else "# "
    item = "- [ ] " if markdown else "- "
    missing = [t for t in TARGETS if t not in targets]
    lines.append("Targets: " + ", ".join(targets))
    if missing:
        lines.append("Not checked: " + ", ".join(missing) +
                     ". Items only those backends use can show up below.")
    titles = {
        "dead": "Dead: no target uses it",
        "test-only": "Test-only: only cfg(test) code uses it",
        "partial": "Partial: some targets compile it without using it",
    }
    for cls in ("dead", "test-only", "partial"):
        rows = []
        for (path, name), e, used_on in classes[cls]:
            if (path, name) in allow:
                used.add((path, name))
                continue
            row = "`%s` %s in %s" % (name, kind(e["msg"]), where(path, e["lines"], markdown))
            if cls == "partial":
                rows.append("- %s, used on %s" % (row, ", ".join(used_on)))
            else:
                rows.append(item + row)
        lines.append("")
        if cls == "partial":
            # Informational, and long. Markdown folds it away.
            if markdown:
                lines.append("<details><summary>%s (%d)</summary>" % (titles[cls], len(rows)))
                lines.append("")
                lines.extend(rows or ["None."])
                lines.append("")
                lines.append("</details>")
            else:
                lines.append(h + "%s (%d)" % (titles[cls], len(rows)))
                lines.extend(rows or ["None."])
            continue
        failing += len(rows)
        lines.append(h + "%s (%d)" % (titles[cls], len(rows)))
        lines.extend(rows or ["None."])
    stale = sorted(set(allow) - used)
    failing += len(stale)
    lines.append("")
    lines.append(h + "Stale allowlist entries (%d)" % len(stale))
    lines.extend(
        [item + "`%s` in `%s`, which nothing reports" % (n, p) for p, n in stale]
        or ["None."]
    )
    print("\n".join(lines))
    return 1 if failing else 0


def run():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("--raw-out")
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--from", dest="sources", nargs="+", default=[])
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    if args.sources:
        raws = [json.loads(Path(p).read_text()) for p in args.sources]
    else:
        SCRATCH.mkdir(parents=True, exist_ok=True)
        targets = args.target or installed_targets()
        raws = [scan(targets)]
        if args.raw_out:
            Path(args.raw_out).write_text(json.dumps(raws[0]))
        if args.scan_only:
            return 0
    return report(raws, args.markdown)


def main():
    try:
        return run()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
