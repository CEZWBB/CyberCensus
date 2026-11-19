#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_updater 的离线测试（不联网）。"""

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tool_updater as up  # noqa: E402


class TestVersion(unittest.TestCase):
    def test_parse_versions(self):
        self.assertEqual(up.parse_version("[INF] Current Version: v2.17.0"), "2.17.0")
        self.assertEqual(up.parse_version("[INF] Nuclei Engine Version: v3.11.1\n"), "3.11.1")
        self.assertEqual(up.parse_version("WAFW00F : v2.4.2"), "2.4.2")
        self.assertEqual(up.parse_version("no version here"), "")

    def test_is_newer(self):
        self.assertTrue(up.is_newer("2.18.0", "2.17.0"))
        self.assertTrue(up.is_newer("3.0.0", "2.99.99"))
        self.assertFalse(up.is_newer("2.17.0", "2.17.0"))
        self.assertFalse(up.is_newer("", "2.17.0"))
        self.assertTrue(up.is_newer("2.17.1", ""))


class TestSelectAsset(unittest.TestCase):
    def _release(self):
        return {"assets": [
            {"name": "subfinder_2.18.0_linux_amd64.zip",
             "browser_download_url": "https://x/linux.zip", "size": 1},
            {"name": "subfinder_2.18.0_windows_amd64.zip",
             "browser_download_url": "https://x/win.zip", "size": 42},
            {"name": "subfinder_2.18.0_checksums.txt",
             "browser_download_url": "https://x/sums.txt", "size": 3},
        ]}

    def test_picks_windows_amd64_zip(self):
        name, url, size = up.select_asset(self._release(), "subfinder")
        self.assertEqual(name, "subfinder_2.18.0_windows_amd64.zip")
        self.assertEqual(url, "https://x/win.zip")
        self.assertEqual(size, 42)

    def test_missing_returns_empty(self):
        self.assertEqual(up.select_asset({"assets": []}, "httpx"),
                         ("", "", 0))
        self.assertEqual(up.select_asset({}, "nuclei"), ("", "", 0))


class TestCheckUpdates(unittest.TestCase):
    def test_check_reports_newer_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            tools = os.path.join(d, "tools")
            os.makedirs(tools)

            def fake_local(path):
                if path.endswith("subfinder.exe"):
                    return "2.17.0"
                return ""

            orig_local = up.local_version
            orig_gh = up.github_latest
            orig_pypi = up.pypi_latest
            up.local_version = fake_local
            up.github_latest = lambda name, timeout=25: {
                "version": {"subfinder": "2.18.0", "httpx": "1.12.0",
                            "nuclei": "3.11.1"}.get(name, ""),
                "url": "https://x/win.zip", "asset": "a.zip"}
            up.pypi_latest = lambda pkg, timeout=20: "2.5.0"
            self.addCleanup(up.__setattr__, "local_version", orig_local)
            self.addCleanup(up.__setattr__, "github_latest", orig_gh)
            self.addCleanup(up.__setattr__, "pypi_latest", orig_pypi)

            rows = {r["name"]: r for r in up.check_updates(d)}
            self.assertTrue(rows["subfinder"]["updatable"])
            self.assertTrue(rows["httpx"]["updatable"])   # 未安装 → 可安装
            self.assertEqual(rows["nuclei"]["latest"], "3.11.1")
            self.assertFalse(rows["wafw00f"]["updatable"])
            self.assertIn("PyPI", rows["wafw00f"]["note"])


class TestInstallTool(unittest.TestCase):
    def test_install_replaces_binary(self):
        with tempfile.TemporaryDirectory() as d:
            tools = os.path.join(d, "tools")
            os.makedirs(tools)
            cur = os.path.join(tools, "subfinder.exe")
            with open(cur, "wb") as f:
                f.write(b"OLD")

            def fake_download(url, timeout, dest):
                with zipfile.ZipFile(dest, "w") as zf:
                    zf.writestr("subfinder_9.9.9_windows_amd64/subfinder.exe",
                                b"NEW")
                return dest

            orig_gh = up.github_latest
            orig_dl = up._open_url
            orig_ver = up.local_version
            up.github_latest = lambda name, timeout=25: {
                "version": "9.9.9", "asset": "x.zip", "url": "https://x/x.zip"}
            up._open_url = fake_download
            up.local_version = (
                lambda p, timeout=20: "9.9.9" if os.path.isfile(p) else "")
            self.addCleanup(up.__setattr__, "github_latest", orig_gh)
            self.addCleanup(up.__setattr__, "_open_url", orig_dl)
            self.addCleanup(up.__setattr__, "local_version", orig_ver)

            ok, msg = up.install_tool(d, "subfinder")
            self.assertTrue(ok, msg)
            with open(cur, "rb") as f:
                self.assertEqual(f.read(), b"NEW")
            self.assertFalse(os.path.exists(cur + ".old"))


class TestTemplates(unittest.TestCase):
    def test_update_templates_uses_bundled_dir(self):
        with tempfile.TemporaryDirectory() as d:
            tools = os.path.join(d, "tools")
            os.makedirs(tools)
            nuclei = os.path.join(tools, "nuclei.exe")
            with open(nuclei, "wb") as f:
                f.write(b"MZ")
            tpl = os.path.join(d, "nuclei-templates")
            os.makedirs(tpl)
            seen = {}

            class R(object):
                returncode = 0
                stdout = "Templates updated"
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = cmd
                return R()

            orig_run = up.subprocess.run
            up.subprocess.run = fake_run
            self.addCleanup(setattr, up.subprocess, "run", orig_run)
            ok, msg = up.update_templates(d)
            self.assertTrue(ok, msg)
            self.assertIn("-update-templates", seen["cmd"])
            self.assertIn("-ud", seen["cmd"])
            self.assertIn(tpl, seen["cmd"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
