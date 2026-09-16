#!/usr/bin/env python3
"""Run and analyze conformance test results against the Rust worker.

Writes artifacts to .test-run/ so subsequent queries don't re-run tests:
  .test-run/junit.xml    — structured pytest output (parsed here)
  .test-run/pytest.log   — combined stdout/stderr from the test process
  .test-run/args.txt     — the command line used, for reproducibility

Usage:
  conf.py run [--transport {pipe,subprocess,http,unix,tcp,http_externalize_always,shm_pipe,all}]
              [-k PATTERN] [--release|--debug] [-- pytest_args...]
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
# The canonical Python reference is the `vgi-rpc-python` checkout, NOT
# `~/Development/vgi-rpc`. The latter is `main` and carries a numerically
# *higher* version (0.45.3) while containing none of the multiservice work:
# no routing key, flat routes, `__describe__` still live. A harness pinned to
# it tests against a reference that refuses every namespaced call, and reports
# the resulting failures as if they were the port's.
#
# Both defaults are overridable; a machine-specific absolute path baked into a
# committed script is how the stale pin survived unnoticed.
#   VGI_RPC_PYTHON_REPO  checkout root of vgi-rpc-python
#   VGI_RPC_PYTHON       interpreter to run the suite with (default: its .venv)
REF_REPO = Path(
    os.environ.get("VGI_RPC_PYTHON_REPO")
    or Path.home() / "Development" / "vgi-rpc-python"
)
VENV_PY = Path(os.environ.get("VGI_RPC_PYTHON") or REF_REPO / ".venv" / "bin" / "python")
VENV_BIN = VENV_PY.parent
WORKER = ROOT / "conformance-worker-rust"
GO_WORKER = Path.home() / "Development" / "vgi-rpc-go" / "vgi-rpc-conformance-go"


def _cargo_build(pkg: str, release: bool, build_log: Path) -> None:
    flags = ["--release"] if release else []
    with open(build_log, "a") as bl:
        r = subprocess.run(
            ["cargo", "build", "-p", pkg, *flags],
            cwd=ROOT, stdout=bl, stderr=subprocess.STDOUT,
        )
    if r.returncode != 0:
        print(f"[conf] cargo build of {pkg} failed; see {build_log}")
        raise SystemExit(r.returncode)


def _build_rust_worker(release: bool, skip: bool) -> Path:
    profile = "release" if release else "dev"
    target = ROOT / "target" / ("release" if release else "debug") / "vgi-rpc-conformance-rust"
    if not skip:
        RUN_DIR.mkdir(exist_ok=True)
        _cargo_build("vgi-rpc-conformance-rust", release, RUN_DIR / "build.log")
    if not target.exists():
        raise SystemExit(f"[conf] build missing at {target}; use --debug or rebuild")
    WORKER.parent.mkdir(parents=True, exist_ok=True)
    if WORKER.is_symlink() or WORKER.exists():
        WORKER.unlink()
    WORKER.symlink_to(target)
    print(f"[conf] rust worker -> {target} (profile={profile})")
    return WORKER


def _build_client_driver(release: bool, skip: bool) -> Path:
    target = ROOT / "target" / ("release" if release else "debug") / "vgi-rpc-conformance-client-driver"
    if not skip:
        RUN_DIR.mkdir(exist_ok=True)
        _cargo_build("vgi-rpc-conformance-client-driver", release, RUN_DIR / "build.log")
    if not target.exists():
        raise SystemExit(f"[conf] client driver missing at {target}; rebuild")
    print(f"[conf] client driver -> {target}")
    return target


def _resolve_worker(server: str, release: bool, skip: bool) -> Path:
    """Resolve the conformance SERVER binary for the requested language."""
    if server == "rust":
        return _build_rust_worker(release, skip)
    if server == "python":
        cli = VENV_BIN / "vgi-rpc-conformance"
        if not cli.exists():
            raise SystemExit(f"[conf] python conformance CLI not found at {cli}")
        print(f"[conf] python server -> {cli}")
        return cli
    if server == "go":
        if not GO_WORKER.exists():
            raise SystemExit(
                f"[conf] go conformance worker not found at {GO_WORKER}; "
                "build it in ~/Development/vgi-rpc-go first"
            )
        print(f"[conf] go server -> {GO_WORKER}")
        return GO_WORKER
    raise SystemExit(f"[conf] unknown server {server!r}")


def _check_reference() -> None:
    """Fail loudly when the Python reference is missing, stale, or from PyPI.

    Two ways to end up testing against the wrong reference, both silent:

      * a stale *path* -- `~/Development/vgi-rpc` is `main`, carries a
        numerically higher version, and has none of the multiservice work; and
      * a stale *version* -- an interpreter whose ``vgi_rpc`` came from PyPI
        rather than from the checkout. A version constraint is a pin too, and
        an invisible one: the run looks healthy and every namespaced call fails.

    The second is only reported, not refused: an installed-wheel layout is a
    legitimate CI shape. But it is reported on every run, because the cost of
    not noticing is a whole measurement cycle attributed to the port.
    """
    if not VENV_PY.exists():
        raise SystemExit(
            f"[conf] Python reference interpreter not found at {VENV_PY}\n"
            f"       Expected a vgi-rpc-python checkout at {REF_REPO}.\n"
            f"       Override with VGI_RPC_PYTHON_REPO=/path/to/vgi-rpc-python "
            f"(or VGI_RPC_PYTHON=/path/to/python)."
        )
    probe = subprocess.run(
        [str(VENV_PY), "-c", "import vgi_rpc, sys; print(vgi_rpc.__file__)"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        raise SystemExit(
            f"[conf] {VENV_PY} cannot import vgi_rpc:\n{probe.stderr.strip()}"
        )
    module = Path(probe.stdout.strip()).resolve()
    try:
        module.relative_to(REF_REPO.resolve())
    except ValueError:
        print(
            f"[conf] WARNING: the interpreter's vgi_rpc is NOT the checkout under test.\n"
            f"[conf]   interpreter: {VENV_PY}\n"
            f"[conf]   vgi_rpc at:  {module}\n"
            f"[conf]   expected under: {REF_REPO}\n"
            f"[conf]   An installed wheel is a pin too. If this is a PyPI release it\n"
            f"[conf]   predates the multiservice work and every namespaced call will fail."
        )
    else:
        print(f"[conf] python reference -> {module.parent} ({_reference_revision()})")


def _reference_revision() -> str:
    """The reference's git revision, so a reported number names what it measured.

    The reference moves. A failure count with no revision beside it cannot be
    compared to the next one, and two agents measuring an hour apart will report
    different numbers for the same port and both be right.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(REF_REPO), "log", "-1", "--format=%h %s"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "revision unknown"
    return r.stdout.strip() if r.returncode == 0 else "revision unknown"


def _run(args: argparse.Namespace, extras: list[str]) -> int:
    RUN_DIR.mkdir(exist_ok=True)
    _check_reference()

    worker = _resolve_worker(args.server, release=args.release, skip=args.no_build)

    env = os.environ.copy()
    # Pin the child to the same reference this script resolved, so the pytest
    # harness cannot silently fall back to a different (or stale) checkout.
    env["VGI_RPC_PYTHON_REPO"] = str(REF_REPO)
    env["VGI_RPC_PYTHON"] = str(VENV_PY)
    env.setdefault("VGI_PY_TESTS_DIR", str(REF_REPO / "tests"))
    env["RUST_CONFORMANCE_WORKER"] = str(worker)
    env["VGI_CONFORMANCE_ROLE"] = args.role
    env["VGI_CONFORMANCE_SERVER"] = args.server
    if args.role == "client":
        driver = _build_client_driver(release=args.release, skip=args.no_build)
        env["VGI_CLIENT_DRIVER"] = str(driver)

    transports = (
        ["pipe", "subprocess", "http", "unix", "tcp", "http_externalize_always", "shm_pipe"]
        if args.transport == "all"
        else [args.transport]
    )
    # shm requires both peers to support the POSIX side-channel. The Rust
    # client + rust/python servers do; the Go conformance server's shm support
    # isn't wired here, so drop shm_pipe for go.
    if args.role == "client" and args.server == "go":
        transports = [t for t in transports if t != "shm_pipe"]
    # http_externalize_always needs a storage-capable HTTP server. The rust
    # worker and the Python serve_conformance_http.py support it; the Go
    # conformance binary doesn't expose it here.
    if args.role == "client" and args.server == "go":
        transports = [t for t in transports if t != "http_externalize_always"]
    env["VGI_TRANSPORTS"] = ",".join(transports)

    # Wall-clock deadline. The fast rust-only server matrix defaults to 59s
    # (keeps default foreground runs snappy). The cross-language client matrices
    # (role=client, server=python/go) spawn a fresh, slower server per
    # pipe/subprocess test, so they default to 300s. An explicit `--timeout`
    # always wins: these were hard clamps, which meant a suite that outgrew 59s
    # could only ever report OVERALL TIMEOUT, with no way to see the real result.
    if args.timeout is not None:
        pass  # explicit --timeout always wins; the clamps below are defaults
    elif args.role == "server" and args.server == "rust":
        args.timeout = 59
    else:
        args.timeout = 300
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
                    choices=["pipe", "subprocess", "http", "unix", "tcp",
                             "http_externalize_always", "shm_pipe", "all"])
    pr.add_argument("--role", default="server", choices=["server", "client"],
                    help="server: Python client drives the worker (default); "
                         "client: the Rust vgi-rpc-client drives the server")
    pr.add_argument("--server", default="rust", choices=["rust", "python", "go"],
                    help="which conformance SERVER to drive (default rust)")
    pr.add_argument("-k", help="pytest -k filter")
    pr.add_argument("-x", action="store_true", help="stop at first failure")
    pr.add_argument("--release", action="store_true", default=False,
                    help="release build (default: debug for faster iteration)")
    pr.add_argument("--debug", dest="release", action="store_false")
    pr.add_argument("--timeout", type=int, default=None,
                    help="overall wall-clock deadline in seconds (default 59 for role=server/rust, else 300)")
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
