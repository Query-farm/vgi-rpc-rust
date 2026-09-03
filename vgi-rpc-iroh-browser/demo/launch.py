#!/usr/bin/env python3
"""Build and run the real Haybarn -> httpi:// -> identity-aware VGI demo."""

from __future__ import annotations

import argparse
import http.server
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode
import webbrowser


ENDPOINT_ID = re.compile(r"^[0-9a-f]{64}$")
WORKER_PORT = re.compile(r"^PORT:([0-9]{1,5})$")


class DemoError(RuntimeError):
    pass


class Child:
    """Child process with line readiness and bounded process-group cleanup."""

    def __init__(self, name: str, argv: list[str], cwd: Path) -> None:
        self.name = name
        self.lines: queue.Queue[str] = queue.Queue()
        self.process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=(os.name == "posix"),
        )
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self._threads = []
        for stream, readiness, suffix in (
            (self.process.stdout, True, "stdout"),
            (self.process.stderr, False, "stderr"),
        ):
            thread = threading.Thread(
                target=self._pump,
                args=(stream, readiness),
                name=f"{name}-{suffix}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()

    def _pump(self, stream, readiness: bool) -> None:
        for raw in iter(stream.readline, ""):
            line = raw.rstrip("\r\n")
            if readiness:
                self.lines.put(line)
            else:
                print(f"[{self.name}] {line}", file=sys.stderr, flush=True)

    def ready_line(self, validator, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DemoError(f"timed out waiting for {self.name} readiness")
            try:
                line = self.lines.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                status = self.process.poll()
                if status is not None:
                    raise DemoError(
                        f"{self.name} exited with status {status} before readiness"
                    )
                continue
            if validator(line):
                return line
            print(f"[{self.name}] {line}", file=sys.stderr, flush=True)

    def stop(self, timeout: float = 8.0) -> None:
        if self.process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGTERM)
                else:
                    self.process.terminate()
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(self.process.pid, signal.SIGKILL)
                else:
                    self.process.kill()
                self.process.wait(timeout=2.0)
        for thread in self._threads:
            thread.join(timeout=0.5)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()


class IsolatedAssetHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def end_headers(self) -> None:
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        print(f"[assets] {format % args}", file=sys.stderr)


class DemoServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def run_checked(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print("+ " + " ".join(argv), file=sys.stderr, flush=True)
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def build_environment() -> dict[str, str]:
    env = os.environ.copy()
    llvm = Path("/opt/homebrew/opt/llvm/bin")
    if llvm.joinpath("clang").is_file():
        env.setdefault("CC_wasm32_unknown_unknown", str(llvm / "clang"))
        env.setdefault("AR_wasm32_unknown_unknown", str(llvm / "llvm-ar"))
    return env


def build_native(repo: Path, vgi_rust: Path, release: bool) -> tuple[Path, Path]:
    profile = ["--release"] if release else []
    run_checked(
        ["cargo", "build", "--locked", *profile, "-p", "vgi-iroh-bridge", "--bin", "vgi-iroh-bridge"],
        repo,
    )
    run_checked(["cargo", "build", *profile, "-p", "vgi-example-worker"], vgi_rust)
    profile_name = "release" if release else "debug"
    return (
        repo / "target" / profile_name,
        vgi_rust / "target" / profile_name / "vgi-example-worker",
    )


def build_bindings(repo: Path, output: Path, release: bool) -> None:
    profile = ["--release"] if release else []
    run_checked(
        ["cargo", "build", "--locked", *profile, "-p", "vgi-rpc-iroh-browser", "--target", "wasm32-unknown-unknown"],
        repo,
        build_environment(),
    )
    name = "release" if release else "debug"
    wasm = repo / "target" / "wasm32-unknown-unknown" / name / "vgi_rpc_iroh_browser.wasm"
    run_checked(["wasm-bindgen", "--target", "web", "--out-dir", str(output), str(wasm)], repo)


def build_haybarn_demo(repo: Path, bindings: Path, output: Path, args) -> None:
    for filename in ("vgi_rpc_iroh_browser.js", "vgi_rpc_iroh_browser_bg.wasm"):
        if not bindings.joinpath(filename).is_file():
            raise DemoError(f"generated browser binding is missing: {bindings / filename}")
    env = os.environ.copy()
    env.update({"IROH_BINDINGS": str(bindings), "DEMO_DIST": str(output)})
    if args.haybarn:
        env["HAYBARN_WASM"] = str(args.haybarn.resolve())
    if args.engine_root:
        env["VGI_ENGINE_ROOT"] = str(args.engine_root.resolve())
    if args.vgi_extension:
        env["VGI_EXT_WASM"] = str(args.vgi_extension.resolve())
    if args.engine_version:
        env["VGI_ENGINE_VERSION_DIR"] = args.engine_version
    run_checked(["node", "build.mjs"], repo / "vgi-rpc-iroh-browser" / "demo", env)


def start_asset_server(root: Path, host: str, port: int) -> DemoServer:
    if not root.joinpath("index.html").is_file():
        raise DemoError(f"Haybarn demo is not built in {root}")

    def handler(*args, **kwargs):
        return IsolatedAssetHandler(*args, directory=str(root), **kwargs)

    return DemoServer((host, port), handler)


def browser_url(host: str, port: int, endpoint_id: str, autorun: bool = True) -> str:
    if not ENDPOINT_ID.fullmatch(endpoint_id):
        raise DemoError(f"bridge returned a non-canonical EndpointId: {endpoint_id!r}")
    browse_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    query = {"endpoint": endpoint_id}
    if autorun:
        query["autorun"] = "1"
    return f"http://{browse_host}:{port}/?{urlencode(query)}"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=0, type=int)
    parser.add_argument("--haybarn", type=Path)
    parser.add_argument("--engine-root", type=Path)
    parser.add_argument("--vgi-extension", type=Path)
    parser.add_argument("--engine-version")
    parser.add_argument("--bindings", type=Path)
    parser.add_argument("--demo-dist", type=Path)
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument(
        "--vgi-rust",
        type=Path,
        default=Path.home() / "Development" / "vgi-rust",
    )
    parser.add_argument("--worker-bin", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="run the headless Chrome identity assertion and exit",
    )
    parser.add_argument(
        "--verify-browser",
        action="append",
        choices=("chrome", "firefox", "webkit", "safari"),
        default=[],
        help=(
            "run the identity assertion in a browser engine and exit; repeat for "
            "multiple engines (Safari requires macOS with safaridriver enabled)"
        ),
    )
    parser.add_argument("--no-autorun", action="store_true")
    parser.add_argument("--no-relay", action="store_true")
    parser.add_argument("--ready-timeout", type=float, default=30.0)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    repo = repo_root()
    children: list[Child] = []
    server = None
    with tempfile.TemporaryDirectory(prefix="vgi-httpi-demo-") as temporary:
        scratch = Path(temporary)
        if args.skip_build:
            if args.bin_dir is None or args.demo_dist is None or args.worker_bin is None:
                raise DemoError(
                    "--skip-build requires --bin-dir, --demo-dist, and --worker-bin"
                )
            bin_dir = args.bin_dir.resolve()
            public_root = args.demo_dist.resolve()
            worker_binary = args.worker_bin.resolve()
        else:
            vgi_rust = args.vgi_rust.resolve()
            if not vgi_rust.joinpath("Cargo.toml").is_file():
                raise DemoError(f"vgi-rust checkout is missing: {vgi_rust}")
            bin_dir, built_worker = build_native(repo, vgi_rust, args.release)
            worker_binary = (
                args.worker_bin.resolve() if args.worker_bin else built_worker
            )
            bindings = args.bindings.resolve() if args.bindings else scratch / "bindings"
            if args.bindings is None:
                bindings.mkdir()
                build_bindings(repo, bindings, args.release)
            public_root = args.demo_dist.resolve() if args.demo_dist else scratch / "demo"
            build_haybarn_demo(repo, bindings, public_root, args)
            if args.bin_dir:
                bin_dir = args.bin_dir.resolve()

        bridge_binary = bin_dir / "vgi-iroh-bridge"
        if not worker_binary.is_file() or not bridge_binary.is_file():
            raise DemoError(f"native demo binaries are missing from {bin_dir}")
        try:
            worker = Child(
                "worker",
                [str(worker_binary), "--http-iroh-demo"],
                worker_binary.parent,
            )
            children.append(worker)
            line = worker.ready_line(lambda value: WORKER_PORT.fullmatch(value) is not None, args.ready_timeout)
            match = WORKER_PORT.fullmatch(line)
            assert match is not None
            worker_port = int(match.group(1))
            if not 1 <= worker_port <= 65535:
                raise DemoError(f"worker returned invalid port {worker_port}")

            bridge_args = [str(bridge_binary), "--ephemeral", "--http-upstream", f"http://127.0.0.1:{worker_port}"]
            if args.no_relay:
                bridge_args.append("--no-relay")
            bridge = Child("bridge", bridge_args, repo)
            children.append(bridge)
            endpoint = bridge.ready_line(lambda value: ENDPOINT_ID.fullmatch(value) is not None, args.ready_timeout)

            server = start_asset_server(public_root, args.host, args.port)
            threading.Thread(target=server.serve_forever, name="demo-assets", daemon=True).start()
            bound_host, bound_port = server.server_address[:2]
            url = browser_url(str(bound_host), int(bound_port), endpoint, not args.no_autorun)
            print(f"HTTPI_TARGET=httpi://{endpoint}", flush=True)
            print(f"BROWSER_URL={url}", flush=True)
            print("Press Ctrl-C to stop the browser server, bridge, and worker.", flush=True)
            verify_browsers = list(dict.fromkeys(args.verify_browser))
            if args.verify and "chrome" not in verify_browsers:
                verify_browsers.insert(0, "chrome")
            if verify_browsers:
                verify_env = os.environ.copy()
                if args.haybarn:
                    verify_env["HAYBARN_WASM"] = str(args.haybarn.resolve())
                for browser in verify_browsers:
                    run_checked(
                        ["node", "verify.mjs", url, browser],
                        repo / "vgi-rpc-iroh-browser" / "demo",
                        verify_env,
                    )
                return 0
            if not args.no_open:
                webbrowser.open(url)
            while True:
                for child in children:
                    status = child.process.poll()
                    if status is not None:
                        raise DemoError(f"{child.name} exited unexpectedly with status {status}")
                time.sleep(0.2)
        except KeyboardInterrupt:
            return 0
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            for child in reversed(children):
                child.stop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DemoError, OSError, subprocess.CalledProcessError) as error:
        print(f"httpi demo failed: {error}", file=sys.stderr)
        raise SystemExit(1)
