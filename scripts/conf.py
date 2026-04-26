#!/usr/bin/env python3
"""Run and analyze conformance test results against the Rust worker.

Writes artifacts to .test-run/ so subsequent queries don't re-run tests:
  .test-run/junit.xml    — structured pytest output (parsed here)
  .test-run/pytest.log   — combined stdout/stderr from the test process
  .test-run/args.txt     — the command line used, for reproducibility

Usage:
  conf.py run [--transport {pipe,subprocess,http,unix,all}] [-k PATTERN] [--release|--debug] [-- pytest_args...]
  conf.py summary                 Show pass/fail/error/skip counts
  conf.py failures                List failing tests with 1-line summaries
  conf.py show PATTERN            Show failure/error detail for tests matching PATTERN
  conf.py names [--status STATUS] List test names, optionally filtered by status
  conf.py log                     Print tail of the pytest log
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN_DIR = ROOT / ".test-run"
JUNIT = RUN_DIR / "junit.xml"
LOG = RUN_DIR / "pytest.log"
ARGS = RUN_DIR / "args.txt"
VENV_PY = Path("/Users/rusty/Development/vgi-rpc/.venv/bin/python")
WORKER = ROOT / "conformance-worker-rust"


def _build(release: bool, skip: bool) -> None:
    profile = "release" if release else "dev"
    target = ROOT / "target" / ("release" if release else "debug") / "vgi-rpc-conformance-rust"
    if not skip:
        flags = ["--release"] if release else []
        # cargo build is a no-op when nothing changed, so always invoke it.
        # Route output to the run log so the terminal stays readable.
        RUN_DIR.mkdir(exist_ok=True)
        build_log = RUN_DIR / "build.log"
        with open(build_log, "w") as bl:
            r = subprocess.run(
                ["cargo", "build", "-p", "vgi-rpc-conformance-rust", *flags],
                cwd=ROOT, stdout=bl, stderr=subprocess.STDOUT,
            )
        if r.returncode != 0:
            print(f"[conf] cargo build failed; see {build_log}")
            raise SystemExit(r.returncode)
    if not target.exists():
        raise SystemExit(f"[conf] build missing at {target}; use --debug or rebuild")
    WORKER.parent.mkdir(parents=True, exist_ok=True)
    if WORKER.is_symlink() or WORKER.exists():
        WORKER.unlink()
    WORKER.symlink_to(target)
    print(f"[conf] worker -> {target} (profile={profile})")


def _run(args: argparse.Namespace, extras: list[str]) -> int:
    RUN_DIR.mkdir(exist_ok=True)
    _build(release=args.release, skip=args.no_build)

    env = os.environ.copy()
    transports = (
        ["pipe", "subprocess", "http", "unix", "http_externalize_always"]
        if args.transport == "all"
        else [args.transport]
    )
    env["VGI_TRANSPORTS"] = ",".join(transports)

    # Hard cap to ensure I can always run in the foreground.
    args.timeout = min(args.timeout, 59)
    cmd = [
        str(VENV_PY), "-m", "pytest",
        "test_rust_conformance.py",
        f"--junitxml={JUNIT}",
        "-rA",
        "--tb=short",
        "-v",
        "--color=no",
        "--override-ini=addopts=",
        f"--timeout={args.per_test_timeout}",
        "--timeout-method=signal",
    ]
    k_filter = args.k or args.klass
    if k_filter:
        cmd += ["-k", k_filter]
    if args.x:
        cmd += ["-x"]
    cmd += extras

    ARGS.write_text(" ".join(cmd) + "\n")
    with open(LOG, "w") as log:
        log.write(
            f"$ {' '.join(cmd)}\n"
            f"  VGI_TRANSPORTS={env['VGI_TRANSPORTS']}\n"
            f"  overall_timeout={args.timeout}s  per_test_timeout={args.per_test_timeout}s\n\n"
        )
        log.flush()
        try:
            proc = subprocess.run(
                cmd, cwd=ROOT, env=env,
                stdout=log, stderr=subprocess.STDOUT,
                timeout=args.timeout,
            )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\n[conf] OVERALL TIMEOUT after {args.timeout}s — killed\n")
            print(f"[conf] OVERALL TIMEOUT after {args.timeout}s")
            rc = 124

    summary(args)
    return rc


def _load_junit() -> ET.ElementTree | None:
    if not JUNIT.exists():
        print(f"[conf] no results at {JUNIT}; run `conf.py run` first")
        return None
    return ET.parse(JUNIT)


def _cases(tree: ET.ElementTree):
    for case in tree.iterfind(".//testcase"):
        yield case


def _status(case: ET.Element) -> str:
    if case.find("failure") is not None:
        return "failure"
    if case.find("error") is not None:
        return "error"
    if case.find("skipped") is not None:
        return "skipped"
    return "pass"


def _name(case: ET.Element) -> str:
    return f"{case.get('classname', '')}::{case.get('name', '')}"


def summary(args: argparse.Namespace) -> int:
    tree = _load_junit()
    if not tree:
        return 1
    counts = {"pass": 0, "failure": 0, "error": 0, "skipped": 0}
    for case in _cases(tree):
        counts[_status(case)] += 1
    total = sum(counts.values())
    print(f"[conf] total={total}  pass={counts['pass']}  failure={counts['failure']}  error={counts['error']}  skipped={counts['skipped']}")
    return 0 if counts["failure"] == counts["error"] == 0 else 1


def failures(args: argparse.Namespace) -> int:
    tree = _load_junit()
    if not tree:
        return 1
    any_failure = False
    for case in _cases(tree):
        st = _status(case)
        if st not in ("failure", "error"):
            continue
        any_failure = True
        node = case.find("failure")
        if node is None:
            node = case.find("error")
        assert node is not None
        msg = (node.get("message") or "").splitlines()[0][:200]
        print(f"[{st:7}] {_name(case)}")
        print(f"          {msg}")
    if not any_failure:
        print("[conf] no failures")
    return 0


def show(args: argparse.Namespace) -> int:
    tree = _load_junit()
    if not tree:
        return 1
    pat = re.compile(args.pattern)
    count = 0
    for case in _cases(tree):
        name = _name(case)
        if not pat.search(name):
            continue
        st = _status(case)
        print(f"=== [{st}] {name} ===")
        node = case.find("failure")
        if node is None:
            node = case.find("error")
        if node is None:
            node = case.find("skipped")
        if node is not None:
            msg = node.get("message") or ""
            body = (node.text or "").strip()
            print(f"  message: {msg}")
            if body:
                print("  detail:")
                for line in body.splitlines():
                    print(f"    {line}")
        count += 1
    if count == 0:
        print(f"[conf] no tests match {args.pattern!r}")
    return 0


def names(args: argparse.Namespace) -> int:
    tree = _load_junit()
    if not tree:
        return 1
    for case in _cases(tree):
        st = _status(case)
        if args.status and st != args.status:
            continue
        print(f"{st:7} {_name(case)}")
    return 0


def log_tail(args: argparse.Namespace) -> int:
    if not LOG.exists():
        print(f"[conf] no log at {LOG}")
        return 1
    lines = LOG.read_text().splitlines()
    for ln in lines[-args.n:]:
        print(ln)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run")
    pr.add_argument("--transport", default="pipe",
                    choices=["pipe", "subprocess", "http", "unix", "http_externalize_always", "all"])
    pr.add_argument("-k", help="pytest -k filter")
    pr.add_argument("-x", action="store_true", help="stop at first failure")
    pr.add_argument("--release", action="store_true", default=False,
                    help="release build (default: debug for faster iteration)")
    pr.add_argument("--debug", dest="release", action="store_false")
    pr.add_argument("--timeout", type=int, default=55,
                    help="overall wall-clock deadline in seconds (default 55, hard cap 59)")
    pr.add_argument("--per-test-timeout", type=int, default=2,
                    help="per-test timeout in seconds (default 2)")
    pr.add_argument("--no-build", action="store_true",
                    help="skip cargo build (assume binary is current)")
    pr.add_argument("--class", dest="klass",
                    help="restrict to tests in a TestClass (alias for -k TestClass)")
    pr.set_defaults(func=_run)

    ps = sub.add_parser("summary"); ps.set_defaults(func=summary)
    pf = sub.add_parser("failures"); pf.set_defaults(func=failures)
    psh = sub.add_parser("show"); psh.add_argument("pattern"); psh.set_defaults(func=show)
    pn = sub.add_parser("names"); pn.add_argument("--status"); pn.set_defaults(func=names)
    pl = sub.add_parser("log"); pl.add_argument("-n", type=int, default=60); pl.set_defaults(func=log_tail)

    args, extras = p.parse_known_args()
    if extras and extras[0] == "--":
        extras = extras[1:]
    return args.func(args, extras) if args.cmd == "run" else args.func(args)


if __name__ == "__main__":
    sys.exit(main())
