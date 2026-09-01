from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.request


MODULE_PATH = Path(__file__).with_name("launch.py")
SPEC = importlib.util.spec_from_file_location("httpi_demo_launch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
launch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch)


class LauncherTests(unittest.TestCase):
    def test_child_readiness_and_process_group_cleanup_are_bounded(self) -> None:
        child = launch.Child(
            "fixture",
            [
                sys.executable,
                "-u",
                "-c",
                (
                    "import signal,sys,time; "
                    "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                    "print('READY', flush=True); time.sleep(60)"
                ),
            ],
            Path.cwd(),
        )
        try:
            self.assertEqual(child.ready_line(lambda line: line == "READY", 2), "READY")
        finally:
            child.stop(timeout=2)
        self.assertIsNotNone(child.process.poll())

    def test_browser_url_is_canonical_and_enables_autorun(self) -> None:
        endpoint = "ab" * 32
        self.assertEqual(
            launch.browser_url("0.0.0.0", 8123, endpoint),
            f"http://127.0.0.1:8123/?endpoint={endpoint}&autorun=1",
        )
        with self.assertRaisesRegex(launch.DemoError, "non-canonical"):
            launch.browser_url("127.0.0.1", 8123, endpoint.upper())

    def test_asset_server_sets_cross_origin_isolation_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary)
            public.joinpath("index.html").write_text("ready", encoding="utf-8")
            server = launch.start_asset_server(public, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                address = f"http://127.0.0.1:{server.server_port}/"
                with urllib.request.urlopen(address) as response:
                    self.assertEqual(response.read(), b"ready")
                    self.assertEqual(response.headers["Cross-Origin-Opener-Policy"], "same-origin")
                    self.assertEqual(response.headers["Cross-Origin-Embedder-Policy"], "require-corp")
                    self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
