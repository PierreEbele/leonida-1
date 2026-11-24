"""check_device_filter_tools.py runs the cross build's PE harnesses through wine.

On Linux the Windows build's vk_descriptor_bench and vk_sandbox are PE executables: the checker used to start
them directly, so subprocess raised ``OSError: [Errno 8] Exec format error`` and the ctest entry
``vk_device_filter_tools`` failed wherever it could have said anything at all. This test drives the checker with
fake tools and a stub wine, without a Windows build or a Vulkan device.

    python -I tests/test_check_device_filter_tools.py
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "runtime" / "test" / "check_device_filter_tools.py"

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(ROOT))


def load_check():
    spec = importlib.util.spec_from_file_location("check_device_filter_tools", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckDeviceFilterToolsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.check = load_check()

    def tool(self, name, header):
        path = Path(self.directory.name) / name
        path.write_bytes(header + b"\x00" * 64)
        return str(path)

    def test_a_pe_on_a_non_windows_host_goes_through_wine(self):
        exe = self.tool("bench.exe", b"MZ")
        env = {"WINE": "stub-wine"}
        with mock.patch.object(os, "name", "posix"), mock.patch.dict(os.environ, env):
            self.assertEqual(self.check.launch_runner(exe), ["stub-wine"])

    def test_wine_comes_from_path_when_wine_is_not_set(self):
        exe = self.tool("bench.exe", b"MZ")
        with mock.patch.object(os, "name", "posix"), \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(self.check.shutil, "which", lambda name: "/usr/bin/stub-wine"):
            self.assertEqual(self.check.launch_runner(exe), ["/usr/bin/stub-wine"])

    def test_native_binaries_and_windows_hosts_run_the_tool_directly(self):
        elf = self.tool("harness", b"\x7fELF")
        exe = self.tool("bench.exe", b"MZ")
        with mock.patch.dict(os.environ, {"WINE": "stub-wine"}):
            self.assertEqual(self.check.launch_runner(elf), [])           # this host runs it as-is
            self.assertEqual(self.check.launch_runner("nonexistent"), [])
        with mock.patch.object(os, "name", "nt"), mock.patch.dict(os.environ, {"WINE": "stub-wine"}):
            self.assertEqual(self.check.launch_runner(exe), [])            # Windows runs a PE as-is

    def invoke(self, bench, sandbox, work):
        """main() through a recorder that stands in for the harnesses: the device list answers the bench, a
        filtered run names the filter and fails, as a harness that refuses the filter does."""
        seen = []

        def fake_run(cmd, env=None, **kwargs):
            seen.append(cmd)
            if "--list-devices" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="[0] stub gpu\n", stderr="")
            return subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr=f"LEONIDA_VK_DEVICE={self.check.FILTER}: no GPU matches the filter\n")

        out = io.StringIO()
        with mock.patch.object(self.check.subprocess, "run", fake_run), contextlib.redirect_stdout(out):
            code = self.check.main(["check", bench, sandbox, work])
        return code, seen, out.getvalue()

    def test_pe_tools_are_launched_through_wine(self):
        bench, sandbox = self.tool("bench.exe", b"MZ"), self.tool("sandbox.exe", b"MZ")
        work = str(Path(self.directory.name) / "work")
        with mock.patch.object(os, "name", "posix"), mock.patch.dict(os.environ, {"WINE": "stub-wine"}):
            code, seen, output = self.invoke(bench, sandbox, work)
        self.assertEqual(code, 0, output)
        for cmd in seen:
            self.assertEqual(cmd[0], "stub-wine", f"the tool was not started through wine: {cmd}")

    def test_no_wine_for_pe_tools_is_a_skip_not_a_crash(self):
        bench, sandbox = self.tool("bench.exe", b"MZ"), self.tool("sandbox.exe", b"MZ")
        work = str(Path(self.directory.name) / "work")
        with mock.patch.object(os, "name", "posix"), \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(self.check.shutil, "which", lambda name: None):
            code, seen, output = self.invoke(bench, sandbox, work)
        self.assertEqual(code, 77, output)
        self.assertEqual(seen, [])
        self.assertIn("no wine", output)


if __name__ == "__main__":
    unittest.main()
