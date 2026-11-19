#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_updater.py —— 增强引擎检查更新 / 一键升级（subfinder / httpx / nuclei）。

- 版本来源：直接运行本地 exe 的 `-version`
- 最新版本：GitHub Releases API（ProjectDiscovery 官方）
- 下载：官方 release 的 `*_windows_amd64.zip`，直连失败自动走 gh-proxy 镜像
- 安装：先下载到 .new.exe → 运行校验版本 → 备份旧版 → 原子替换 → 失败回滚
- wafw00f：官方没有 Windows 单文件发行版，随 CyberCensus 发布包更新
- 模板：nuclei `-update-templates`（有包内 nuclei-templates 时用 `-ud` 指向它）

本模块不依赖 cybercensus，方便单独测试；GUI / CLI 都可调用。
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

UA = "CyberCensus-Updater/1.0"
REPOS = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "nuclei": "projectdiscovery/nuclei",
}
# wafw00f 当前随发布包冻结的版本；PyPI 有新版本时只提示，不自动替换
WAFW00F_BUNDLED_VERSION = "2.4.2"
MIRROR_PREFIXES = ("", "https://gh-proxy.com/", "https://ghproxy.net/")


def _no_window():
    return 0x08000000 if os.name == "nt" else 0


def _exe_name(name):
    return name + (".exe" if os.name == "nt" else "")


def tool_path(base_dir, name):
    return os.path.join(base_dir, "tools", _exe_name(name))


def parse_version(text):
    """从工具输出里抓 x.y.z；抓不到返回空串。"""
    for m in re.finditer(r"\bv?(\d+\.\d+\.\d+)\b", text or ""):
        return m.group(1)
    return ""


def _version_tuple(v):
    nums = [int(x) for x in re.findall(r"\d+", v or "")[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def is_newer(latest, current):
    return _version_tuple(latest) > _version_tuple(current)


def local_version(exe, timeout=20):
    """运行 exe -version 读取版本；文件不存在/执行失败返回空串。"""
    if not exe or not os.path.isfile(exe):
        return ""
    try:
        r = subprocess.run([exe, "-version"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           creationflags=_no_window())
        return parse_version((r.stdout or "") + "\n" + (r.stderr or ""))
    except Exception:
        return ""


def _get_json(url, timeout=25, mirrors=False):
    last = None
    prefixes = MIRROR_PREFIXES if mirrors else ("",)
    for prefix in prefixes:
        try:
            req = urllib.request.Request(prefix + url, headers={
                "User-Agent": UA, "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            last = e
    raise last or IOError("请求失败")


def select_asset(release, name):
    """从 GitHub release JSON 里挑 Windows amd64 压缩包，返回 (文件名, 下载地址, 大小)。"""
    for a in (release or {}).get("assets", []) or []:
        n = str(a.get("name") or "").lower()
        if not n.endswith(".zip"):
            continue
        if "windows" not in n or ("amd64" not in n and "x86_64" not in n):
            continue
        if "checksum" in n or name.lower() not in n:
            continue
        return (a.get("name") or "", a.get("browser_download_url") or "",
                int(a.get("size") or 0))
    return ("", "", 0)


def github_latest(name, timeout=25):
    """查询某工具的最新 release：{tag, version, asset, url, size}。"""
    repo = REPOS.get(name)
    if not repo:
        return {}
    data = _get_json("https://api.github.com/repos/%s/releases/latest" % repo,
                     timeout=timeout, mirrors=True)
    tag = str(data.get("tag_name") or "").lstrip("v")
    asset, url, size = select_asset(data, name)
    return {"tag": tag, "version": parse_version(tag), "asset": asset,
            "url": url, "size": size}


def pypi_latest(package, timeout=20):
    try:
        data = _get_json("https://pypi.org/pypi/%s/json" % package, timeout=timeout)
        return str((data.get("info") or {}).get("version") or "")
    except Exception:
        return ""


def check_updates(base_dir, include_wafw00f=True, timeout=25):
    """检查全部引擎。返回 [{name, current, latest, updatable, note, ...}]。"""
    out = []
    for name in ("subfinder", "httpx", "nuclei"):
        cur = local_version(tool_path(base_dir, name))
        row = {"name": name, "current": cur, "latest": "", "updatable": False,
               "note": ""}
        try:
            info = github_latest(name, timeout=timeout)
            row.update({"latest": info.get("version", ""),
                        "url": info.get("url", ""),
                        "asset": info.get("asset", "")})
            row["updatable"] = bool(row["latest"] and is_newer(
                row["latest"], row["current"]))
            if not cur:
                row["note"] = "未安装，可一键安装"
        except Exception as e:
            row["note"] = "检查失败: %s" % str(e)[:80]
        out.append(row)
    if include_wafw00f:
        latest = pypi_latest("wafw00f")
        cur = WAFW00F_BUNDLED_VERSION
        out.append({"name": "wafw00f", "current": cur, "latest": latest or cur,
                    "updatable": False,
                    "note": ("随 CyberCensus 发布包更新（官方无 Windows 单文件）"
                             if not latest or not is_newer(latest, cur)
                             else "PyPI 有 %s，需重新打包发布包" % latest)})
    return out


def _open_url(url, timeout, dest):
    last = None
    for prefix in MIRROR_PREFIXES:
        try:
            req = urllib.request.Request(prefix + url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                got = 0
                while True:
                    chunk = r.read(1024 * 128)
                    if not chunk:
                        break
                    f.write(chunk)
                    got += len(chunk)
                if total and got != total:
                    raise IOError("下载不完整 %d/%d" % (got, total))
            return dest
        except Exception as e:
            last = e
            try:
                if os.path.isfile(dest):
                    os.remove(dest)
            except Exception:
                pass
    raise last or IOError("下载失败")


def _extract_exe(zip_path, name, out_dir):
    with zipfile.ZipFile(zip_path) as zf:
        target = _exe_name(name)
        cand = next((i for i in zf.infolist()
                     if not i.is_dir()
                     and i.filename.lower().endswith(target.lower())),
                    None)
        if not cand:
            raise IOError("压缩包内没有 %s" % target)
        dst = os.path.join(out_dir, target)
        with zf.open(cand) as src, open(dst, "wb") as f:
            shutil.copyfileobj(src, f)
        return dst


def _replace_with_retry(src, dst, tries=4):
    """Windows 下刚下载的 exe 常被杀软短暂占用，重试替换。"""
    last = None
    for i in range(tries):
        try:
            os.replace(src, dst)
            return True
        except Exception as e:
            last = e
            time.sleep(0.8 * (i + 1))
    raise last


def install_tool(base_dir, name, log=None, timeout=180):
    """下载并安装/升级一个工具。返回 (ok, message)。"""
    def say(msg):
        if log:
            try:
                log(msg)
            except Exception:
                pass

    if name not in REPOS:
        return False, "不支持自动更新: %s" % name
    try:
        info = github_latest(name)
    except Exception as e:
        return False, "查询 %s 最新版失败: %s" % (name, str(e)[:100])
    if not info.get("url"):
        return False, "没有找到 %s 的 Windows 发布包" % name

    tools = os.path.join(base_dir, "tools")
    os.makedirs(tools, exist_ok=True)
    cur = tool_path(base_dir, name)
    old_ver = local_version(cur)
    say("%s: 当前 %s → 最新 %s，下载 %s"
        % (name, old_ver or "未安装", info.get("version", "?"),
           info.get("asset", "")))

    tmpdir = tempfile.mkdtemp(prefix="cc_upd_")
    try:
        zpath = os.path.join(tmpdir, "pkg.zip")
        _open_url(info["url"], timeout, zpath)
        new_exe = _extract_exe(zpath, name, tmpdir)
        # 临时目录可能在 C:，目标在 E:/其他盘：先复制到目标同盘，才能原子替换
        staged = cur + ".new"
        try:
            if os.path.isfile(staged):
                os.remove(staged)
        except Exception:
            pass
        shutil.copy2(new_exe, staged)
        ver = local_version(staged)
        if not ver:
            return False, "下载的 %s 无法运行（版本校验失败）" % name
        say("%s: 下载完成 v%s，正在替换…" % (name, ver))

        backup = cur + ".old"
        if os.path.isfile(backup):
            try:
                os.remove(backup)
            except Exception:
                pass
        if os.path.isfile(cur):
            try:
                os.replace(cur, backup)
            except Exception:
                shutil.copy2(cur, backup)
        try:
            _replace_with_retry(staged, cur)
        except Exception:
            if os.path.isfile(backup):
                try:
                    _replace_with_retry(backup, cur)
                except Exception:
                    pass
            raise
        final_ver = local_version(cur)
        if not final_ver:
            if os.path.isfile(backup):
                try:
                    _replace_with_retry(backup, cur)
                except Exception:
                    pass
            return False, "%s 替换后无法运行，已回滚" % name
        try:
            if os.path.isfile(backup):
                os.remove(backup)
        except Exception:
            pass
        return True, "%s 已更新到 v%s" % (name, final_ver)
    except Exception as e:
        return False, "%s 更新失败: %s" % (name, str(e)[:120])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        try:
            staged = tool_path(base_dir, name) + ".new"
            if os.path.isfile(staged):
                os.remove(staged)
        except Exception:
            pass


def update_templates(base_dir, log=None, timeout=600):
    """更新 nuclei 官方模板；有包内 nuclei-templates 时更新那一份。"""
    nuclei = tool_path(base_dir, "nuclei")
    if not os.path.isfile(nuclei):
        return False, "未找到 nuclei，无法更新模板"
    cmd = [nuclei, "-update-templates", "-duc"]
    tpl = os.path.join(base_dir, "nuclei-templates")
    if os.path.isdir(tpl):
        cmd += ["-ud", tpl]
    try:
        if log:
            log("模板: 执行 nuclei -update-templates …")
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout,
                           creationflags=_no_window())
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        tail = out.splitlines()[-1] if out else ""
        if r.returncode != 0:
            return False, "模板更新失败: %s" % tail[:160]
        return True, "模板已更新: %s" % tail[:160]
    except Exception as e:
        return False, "模板更新失败: %s" % str(e)[:120]


def update_all(base_dir, log=None, progress=None):
    """检查并升级所有可更新工具 + 模板。返回结果列表 [(name, ok, msg)]。"""
    results = []
    rows = check_updates(base_dir)
    for i, row in enumerate(rows):
        name = row["name"]
        if progress:
            try:
                progress(int(100 * i / max(1, len(rows))), name)
            except Exception:
                pass
        if name == "wafw00f":
            results.append((name, True, "跳过：%s" % row.get("note", "")))
            continue
        if not row.get("updatable") and row.get("current"):
            results.append((name, True, "已是最新 v%s" % row["current"]))
            continue
        ok, msg = install_tool(base_dir, name, log=log)
        results.append((name, ok, msg))
    ok, msg = update_templates(base_dir, log=log)
    results.append(("nuclei-templates", ok, msg))
    if progress:
        try:
            progress(100, "完成")
        except Exception:
            pass
    return results
