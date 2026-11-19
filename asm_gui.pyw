#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_gui.pyw —— 互联网暴露面测绘工具 图形界面（现代深色主题）

依赖：customtkinter（双击 启动界面.bat 会自动安装，或手动 pip install customtkinter）

启动方式（任选其一）：
  1. 双击 启动界面.bat
  2. 双击本文件（.pyw 由 pythonw 运行，无黑窗口）
  3. 命令行： pyw -3.11 asm_gui.pyw

自检（构建界面后立即销毁，验证无异常）：
  py -3.11 asm_gui.pyw --smoke

打包成单个 exe（可选）：
  pyinstaller --onefile --windowed --collect-all customtkinter asm_gui.pyw
"""

import argparse
import json
import os
import queue
import re
import sys
import threading
import traceback

# PyInstaller 单文件模式下 __file__ 指向临时解压目录（_MEIPASS），
# config.json / 输出目录必须定位到 exe 所在目录
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import cybercensus                # noqa: E402
import providers as prov_layer  # noqa: E402

try:
    import customtkinter as ctk
except ImportError:
    import tkinter as tk
    from tkinter import messagebox
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "缺少界面依赖",
        "未安装 customtkinter。\n\n请先运行：\n    pip install customtkinter\n\n"
        "或直接双击 启动界面.bat（会自动安装）。")
    raise SystemExit(1)

from tkinter import messagebox, filedialog  # noqa: E402

APP_TITLE = "CyberCensus · 互联网暴露面测绘工具"
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# 界面模式选项 -> 流水线模式
MODE_MAP = {"被动": "passive", "标准": "standard", "复核": "verify", "主动": "active"}
MODE_ORDER = ["被动", "标准", "复核", "主动"]
MODE_HINTS = {
    "被动": "不向目标发送任何请求；仅 subfinder 属于纯被动外部工具",
    "标准": "只探测主域名建立锚点，httpx / wafw00f 参与",
    "复核": "对疑似资产补一次 HTTP 复核（会触碰目标）",
    "主动": "端口扫描 + Web 指纹 + 敏感路径 + nuclei（需授权）",
}
# 模式视觉标识：(英文代号, 主色, 悬停色, 一句话说明, 卡片能力标签)
MODE_META = {
    "被动": ("PASSIVE", "#22d3ee", "#67e8f9", "零触碰 · 纯第三方数据",
             ["零触碰", "subfinder", "8 被动源"]),
    "标准": ("STANDARD", "#38bdf8", "#7dd3fc", "锚点探测 · 默认模式",
             ["锚点探测", "httpx", "wafw00f"]),
    "复核": ("VERIFY", "#fbbf24", "#fcd34d", "疑似资产存活复核",
             ["存活复核", "httpx", "WAF"]),
    "主动": ("ACTIVE", "#f87171", "#fca5a5", "端口扫描 + 敏感路径 + nuclei",
             ["端口扫描", "敏感路径", "nuclei"]),
}
# 能力矩阵：模式 -> [(能力, 是否启用), ...]
MODE_CAPS = {
    "被动": [("被动源", True), ("subfinder", True), ("httpx", False),
             ("wafw00f", False), ("端口扫描", False), ("nuclei", False)],
    "标准": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", False), ("nuclei", False)],
    "复核": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", False), ("nuclei", False)],
    "主动": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", True), ("nuclei", True)],
}

PLATFORM_LABELS = [
    ("fofa", "FOFA"),
    ("zerozone", "0.zone 零零信安"),
    ("hunter", "鹰图 Hunter"),
    ("daydaymap", "DayDayMap"),
]

# ---- 视觉系统：深空黑 + 青色霓虹（科技感） ----
ACCENT = "#22d3ee"        # 品牌青
ACCENT_HOVER = "#67e8f9"
ACCENT_DIM = "#0e7490"
RED = "#f87171"
RED_HOVER = "#fca5a5"
GREEN = "#34d399"
ORANGE = "#fbbf24"
GRAY = "#71859a"          # 次要文字
TEXT = "#dbe7f3"          # 主文字
BG = "#05070d"            # 窗口底色（深空黑）
PANEL = "#090f18"         # 侧栏
CARD = "#0d1520"          # 卡片
CARD_HI = "#101b2a"       # 选中卡片
STROKE = "#1b2b3d"        # 描边
STROKE_HI = "#2b4359"     # 悬停描边
HEADER_BG = "#070c13"     # 头栏
MONO = "Consolas"         # 科技感等宽字体（Windows 自带）

LOG_PALETTE = {
    "dark": {"hdr": "#67e8f9", "good": "#34d399", "warn": "#fbbf24", "norm": "#a8bccf"},
}


# ---------------------------------------------------------------------------
# 纯辅助函数（不依赖窗口，便于单元测试）
# ---------------------------------------------------------------------------
def parse_targets(text):
    """把用户输入拆成 (names, domains, ips, errors)。

    支持逗号/分号/空白分隔多个目标，逐个自动识别 名称 / 域名 / IP / CIDR。
    """
    names, domains, ips, errors = [], set(), set(), []
    tokens = [t for t in re.split(r"[,，;；\s]+", (text or "").strip()) if t]
    for t in tokens:
        kind = cybercensus.classify_target(t)
        if kind == "ip":
            ips.add(t)
        elif kind == "cidr":
            err = cybercensus._add_ip_target(ips, t)
            if err:
                errors.append(err)
        elif kind == "domain":
            domains.add(t.lower())
        else:
            names.append(t)
    return names, domains, ips, errors


def build_args(mode, platforms, threads=20, provider_pages=1,
               cscan=False, top=0, ports="", full_ports=False,
               out="cybercensus_out", config=CONFIG_PATH, debug_provider=False,
               formats=None, sensitive=None, probe_interval=0.0, webhook="",
               ext=True, packages=None, intel="", fast=False, paths=True):
    """由界面选择构造 argparse.Namespace（与 CLI 参数一一对应）。

    mode: passive / standard / verify / active
    formats: 输出格式列表（"md"/"csv"/"json" 的子集），空=全部
    sensitive: 敏感路径探测（None=跟随模式：active 开，其它关）
    ext: 调用本机已安装的外部工具（subfinder/httpx/wafw00f/nuclei）
    """
    active = (mode == "active")
    if sensitive is None:
        sensitive = active
    args = argparse.Namespace(
        beian="",
        threads=max(1, int(threads)),
        timeout=10.0,
        scan_timeout=2.5,
        out=out,
        output_formats=(",".join(formats) if formats else "md,csv,html"),
        no_probe=(mode == "passive"),
        no_discover=False,   # 名称模式默认启用搜索引擎官网自举（被动模式自动跳过）
        probe_found=False,
        probe_limit=100,
        probe_interval=float(probe_interval or 0),
        sensitive=bool(sensitive),
        no_sensitive=not sensitive,
        sensitive_limit=200,
        verify=(mode == "verify"),
        verify_limit=0,
        active=active,
        cscan=bool(cscan and active),
        full_ports=bool(full_ports),
        top=int(top),
        ports=ports,
        quiet=False,
        providers=(list(platforms) if platforms else None),
        provider_pages=max(1, int(provider_pages)),
        provider_limit=0,
        no_providers=(not platforms),
        config=config,
        debug_provider=bool(debug_provider),
        webhook=webhook or "",
        ext_tools=None,
        no_ext=not bool(ext),
        ext_sub_limit=3000,
        app_packages=list(packages or []),
        intel=intel or "",
        fast=bool(fast),
        no_paths=not bool(paths),
        path_limit=30,
        yes=True,   # 授权确认由界面勾选框承担，不再走 input()
    )
    # 端口列表（与 CLI main 相同的优先级：自定义 > top > 内置全表）
    if ports:
        args.ports_list = cybercensus.parse_ports(ports)
    elif args.top > 0:
        args.ports_list = list(cybercensus.DEFAULT_PORTS[:args.top])
    else:
        args.ports_list = list(cybercensus.DEFAULT_PORTS)
    if not args.ports_list:
        args.ports_list = list(cybercensus.DEFAULT_PORTS)
    return args


def _to_int(s, default):
    try:
        return int(str(s).strip())
    except Exception:
        return default


def asset_rows(eng, max_evidence=2):
    """从引擎结果提取表格行：[(分类, 主机, IP, 端口, 标题, 敏感发现, 归属说明, tag), ...]。

    按 确认 → 疑似 → 存疑 排序；归属说明用白话证据（截断到 max_evidence 条）。
    纯函数，供界面表格与单元测试共用。
    """
    order = {"确认": 0, "疑似": 1, "存疑": 2}
    tag_map = {"确认": "confirmed", "疑似": "suspect", "存疑": "unknown"}
    rows = []
    for a in eng.assets.values():
        plain = cybercensus.plain_evidence(a.evidence, max_items=max_evidence) or "—"
        findings = "、".join(sorted(f.split("|", 1)[-1] for f in a.findings))
        rows.append((
            a.confidence, a.host or a.ip or "", a.ip or "", str(a.port or ""),
            a.title or "", findings, plain, tag_map.get(a.confidence, "unknown"),
        ))
    rows.sort(key=lambda r: (order.get(r[0], 3), r[1], r[3]))
    return rows


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(APP_TITLE)
        w, h = 1180, 860
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("%dx%d+%d+%d" % (w, h, max(0, (sw - w) // 2),
                                       max(0, (sh - h) // 2 - 24)))
        self.minsize(1040, 700)
        self.configure(fg_color=BG)

        # 字体阶梯（等宽字体营造终端/仪表盘观感）
        self.f_brand = ctk.CTkFont(family=MONO, size=21, weight="bold")
        self.f_mono = ctk.CTkFont(family=MONO, size=12)
        self.f_mono_sm = ctk.CTkFont(family=MONO, size=10)
        self.f_title = ctk.CTkFont(size=13, weight="bold")
        self.f_body = ctk.CTkFont(size=12)
        self._mode = "标准"

        self._queue = queue.Queue()
        self._worker = None
        self._stop_flag = threading.Event()
        self._last_out_dir = None
        self._last_md_path = None
        self._last_html_path = None
        self._last_engine = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._build_advanced_dialog()
        self._refresh_platforms()
        self._select_mode("标准", initial=True)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-Return>", lambda e: self._on_start())
        self.after(100, self._poll)

    # ------------------------------------------------------------------
    # 品牌头栏（横贯顶部）
    # ------------------------------------------------------------------
    def _build_header(self):
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color=HEADER_BG)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bar, text="◈", font=ctk.CTkFont(family=MONO, size=28, weight="bold"),
                     text_color=ACCENT).grid(row=0, column=0, rowspan=2, padx=(24, 12),
                                             pady=(10, 8))
        ctk.CTkLabel(bar, text="CYBERCENSUS", font=self.f_brand, text_color=TEXT
                     ).grid(row=0, column=1, sticky="sw", pady=(12, 0))
        ctk.CTkLabel(bar, text="互联网暴露面测绘  //  ATTACK SURFACE INTELLIGENCE",
                     text_color=GRAY, font=self.f_mono_sm
                     ).grid(row=1, column=1, sticky="nw", pady=(0, 12))

        ctk.CTkLabel(bar, text=" V1.0 ", font=self.f_mono_sm, text_color=ACCENT,
                     fg_color="#0a2230", corner_radius=4, height=20, padx=6
                     ).grid(row=0, column=2, rowspan=2, padx=(0, 12))

        self.lbl_mode_tag = ctk.CTkLabel(
            bar, text="STANDARD", font=ctk.CTkFont(family=MONO, size=11, weight="bold"),
            text_color=ACCENT, fg_color=CARD, corner_radius=6, height=24, padx=12,
            border_width=1, border_color=STROKE)
        self.lbl_mode_tag.grid(row=0, column=3, rowspan=2, padx=(0, 10))

        # 状态胶囊
        self.var_status = ctk.StringVar(value="● 就绪")
        self.lbl_status = ctk.CTkLabel(
            bar, textvariable=self.var_status, font=ctk.CTkFont(size=12, weight="bold"),
            text_color=GRAY, fg_color=CARD, corner_radius=12, padx=14, height=26,
            border_width=1, border_color=STROKE)
        self.lbl_status.grid(row=0, column=4, rowspan=2, padx=(0, 24))

        # 底部品牌色细线
        ctk.CTkFrame(bar, height=1, fg_color="#123b4a"
                     ).grid(row=2, column=0, columnspan=5, sticky="ew")

    def _set_status(self, text, color):
        self.var_status.set(text)
        self.lbl_status.configure(text_color=color)

    # ------------------------------------------------------------------
    # 侧边栏（卡片化）
    # ------------------------------------------------------------------
    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=self.f_mono_sm, text_color=GRAY,
                     anchor="w").pack(fill="x", padx=18, pady=(10, 4))

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=268, corner_radius=0, fg_color=PANEL)
        sb.grid(row=1, column=0, sticky="nsw")
        sb.grid_propagate(False)
        self._sidebar = sb

        # ---- 平台卡片 ----
        self._section(sb, "// 01  PLATFORMS  ·  测绘平台")
        card = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                            border_width=1, border_color=STROKE)
        card.pack(fill="x", padx=14)
        self.sw_platforms = {}
        self.var_platforms = {}
        for name, label in PLATFORM_LABELS:
            var = ctk.BooleanVar(value=True)
            sw = ctk.CTkSwitch(card, text=label, variable=var, onvalue=True,
                               offvalue=False, font=self.f_body,
                               progress_color=ACCENT, button_color=ACCENT)
            sw.pack(anchor="w", padx=14, pady=5)
            self.sw_platforms[name] = sw
            self.var_platforms[name] = var
        ctk.CTkLabel(card, text="● 未配 Key 也可运行：8 个本地被动源",
                     text_color=GREEN, font=self.f_mono_sm
                     ).pack(anchor="w", padx=14, pady=(6, 12))

        # ---- 本机外部引擎（状态面板）----
        self._section(sb, "// 02  ENGINES  ·  本机外部引擎")
        card3 = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                             border_width=1, border_color=STROKE)
        card3.pack(fill="x", padx=14)
        try:
            avail = set(cybercensus.ext_available())
        except Exception:
            avail = set()
        for name in ("subfinder", "httpx", "wafw00f", "nuclei"):
            row = ctk.CTkFrame(card3, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            on = name in avail
            ctk.CTkLabel(row, text="●" if on else "○", font=self.f_mono_sm,
                         text_color=GREEN if on else "#3d5064"
                         ).pack(side="left")
            ctk.CTkLabel(row, text=name, font=self.f_mono,
                         text_color=TEXT if on else GRAY).pack(side="left", padx=(7, 0))
            ctk.CTkLabel(row, text="READY" if on else "MISSING", font=self.f_mono_sm,
                         text_color=GREEN if on else "#3d5064").pack(side="right")
        ctk.CTkLabel(card3, text="未安装的引擎自动跳过（纯被动仅 subfinder）",
                     text_color=GRAY, font=self.f_mono_sm, wraplength=220,
                     justify="left").pack(anchor="w", padx=14, pady=(6, 12))

        # ---- 操作 ----
        self._section(sb, "// 03  CONFIG  ·  配置")
        card2 = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                             border_width=1, border_color=STROKE)
        card2.pack(fill="x", padx=14)
        ctk.CTkButton(card2, text="⚙  配置平台 Key…", command=self._open_key_dialog,
                      height=34, corner_radius=8, fg_color="transparent",
                      border_width=1, border_color=STROKE, hover_color=CARD_HI,
                      text_color=TEXT, font=self.f_body
                      ).pack(fill="x", padx=12, pady=12)

        # ---- 底部图例 ----
        legend = ctk.CTkFrame(sb, fg_color="transparent")
        legend.pack(side="bottom", fill="x", padx=18, pady=14)
        ctk.CTkLabel(legend, text="// EVIDENCE GRADE", font=self.f_mono_sm,
                     text_color=GRAY, anchor="w").pack(fill="x")
        for color, label in ((GREEN, "确认 · 强证据 ≥1"),
                             (ORANGE, "疑似 · 较强证据 ≥2"),
                             (GRAY, "剔除 · 证据不足")):
            ctk.CTkLabel(legend, text="● " + label, font=self.f_mono_sm,
                         text_color=color, anchor="w").pack(fill="x", pady=1)
        ctk.CTkLabel(legend, text="PASSIVE-FIRST · A/B/C GRADING",
                     font=self.f_mono_sm, text_color="#3d5064",
                     anchor="w").pack(fill="x", pady=(8, 0))

    # ------------------------------------------------------------------
    # 主工作区
    # ------------------------------------------------------------------
    def _build_main(self):
        m = ctk.CTkFrame(self, fg_color="transparent")
        m.grid(row=1, column=1, sticky="nsew", padx=20, pady=16)
        self._main = m

        # ---- 目标卡片 ----
        card_t = ctk.CTkFrame(m, corner_radius=10, fg_color=CARD,
                              border_width=1, border_color=STROKE)
        card_t.pack(fill="x")
        head = ctk.CTkFrame(card_t, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(9, 2))
        ctk.CTkLabel(head, text="// TARGET  ·  测绘目标", font=self.f_mono_sm,
                     text_color=ACCENT).pack(side="left")
        ctk.CTkLabel(head, text="名称 / 域名 / IP / 网段 · 支持多个", font=self.f_mono_sm,
                     text_color=GRAY).pack(side="right")
        self.var_target = ctk.StringVar()
        self.ent_target = ctk.CTkEntry(
            card_t, textvariable=self.var_target, height=42,
            font=ctk.CTkFont(size=14), corner_radius=8, border_color=STROKE,
            fg_color="#080e16",
            placeholder_text="单位名称 / 域名 / IP / 网段 —— 空格或逗号分隔")
        self.ent_target.pack(fill="x", padx=16, pady=(2, 2))
        self.ent_target.bind("<KeyRelease>", lambda e: self._preview_target())
        self.lbl_preview = ctk.CTkLabel(card_t, text="AUTO-DETECT · 自动识别输入类型…",
                                        text_color=GRAY, font=self.f_mono_sm,
                                        anchor="w")
        self.lbl_preview.pack(anchor="w", padx=16, pady=(0, 7))

        # ---- 模式卡片（点击切换，视觉差异明显） ----
        self._section(m, "// MODE  ·  扫描模式（点击卡片切换）")
        frm_modes = ctk.CTkFrame(m, fg_color="transparent")
        frm_modes.pack(fill="x")
        for c in range(len(MODE_ORDER)):
            frm_modes.grid_columnconfigure(c, weight=1, uniform="modes")
        self.mode_cards = {}
        for i, name in enumerate(MODE_ORDER):
            code, color, hover, desc, chips = MODE_META[name]
            card = ctk.CTkFrame(frm_modes, corner_radius=10, fg_color=CARD,
                                border_width=1, border_color=STROKE, cursor="hand2")
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            card.grid_columnconfigure(0, weight=1)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, sticky="ew", padx=12, pady=(7, 0))
            idx = ctk.CTkLabel(top, text="0%d" % (i + 1), font=self.f_mono_sm,
                               text_color=GRAY)
            idx.pack(side="left")
            dot = ctk.CTkLabel(top, text="●", font=self.f_mono_sm, text_color="#3d5064")
            dot.pack(side="right")
            title = ctk.CTkLabel(card, text=name, font=ctk.CTkFont(size=14, weight="bold"),
                                 text_color=TEXT, anchor="w")
            title.grid(row=1, column=0, sticky="w", padx=12)
            code_lbl = ctk.CTkLabel(card, text=code, font=self.f_mono_sm,
                                    text_color=GRAY, anchor="w")
            code_lbl.grid(row=2, column=0, sticky="w", padx=12)
            chip = ctk.CTkLabel(card, text=" · ".join(chips), font=self.f_mono_sm,
                                text_color=GRAY, anchor="w", justify="left",
                                wraplength=170)
            chip.grid(row=3, column=0, sticky="w", padx=12, pady=(4, 8))
            for w in (card, top, idx, dot, title, code_lbl, chip):
                w.bind("<Button-1>", lambda e, k=name: self._select_mode(k))
            card.bind("<Enter>", lambda e, c=card, k=name: self._mode_hover(c, k, True))
            card.bind("<Leave>", lambda e, c=card, k=name: self._mode_hover(c, k, False))
            self.mode_cards[name] = {"frame": card, "title": title, "code": code_lbl,
                                     "dot": dot, "chip": chip, "index": idx,
                                     "color": color, "hover": hover}

        # ---- 能力矩阵（随模式实时变化） ----
        box = ctk.CTkFrame(m, corner_radius=8, fg_color="#0a1220",
                           border_width=1, border_color=STROKE)
        box.pack(fill="x", pady=(6, 0))
        self.cap_row = ctk.CTkFrame(box, fg_color="transparent")
        self.cap_row.pack(fill="x", padx=14, pady=(6, 1))
        self.cap_labels = {}
        for key in ("被动源", "subfinder", "httpx", "wafw00f", "端口扫描", "nuclei"):
            lbl = ctk.CTkLabel(self.cap_row, text=key, font=self.f_mono_sm,
                               text_color=GRAY)
            lbl.pack(side="left", padx=(0, 16))
            self.cap_labels[key] = lbl
        self.lbl_matrix_note = ctk.CTkLabel(box, text="", font=self.f_mono_sm,
                                            text_color=GRAY, anchor="w")
        self.lbl_matrix_note.pack(fill="x", padx=14, pady=(0, 6))

        self.var_auth = ctk.BooleanVar(value=False)
        self.sw_auth = ctk.CTkSwitch(
            box, text="我已获得书面授权（主动模式必勾）", variable=self.var_auth,
            text_color=RED, progress_color=RED, button_color=RED, font=self.f_mono_sm)

        # ---- 运行行 ----
        frm_run = ctk.CTkFrame(m, fg_color="transparent")
        frm_run.pack(fill="x", pady=(8, 0))
        self.btn_start = ctk.CTkButton(
            frm_run, text="▶  开始测绘 · 标准", width=200, height=42, corner_radius=9,
            font=ctk.CTkFont(size=15, weight="bold"), fg_color=ACCENT,
            hover_color=ACCENT_HOVER, text_color="#04141a", command=self._on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ctk.CTkButton(
            frm_run, text="⏹ 停止并输出", width=128, height=42, corner_radius=9,
            fg_color="transparent", border_width=1, border_color=RED,
            text_color=RED, hover_color="#2a1416", state="disabled",
            command=self._on_stop)
        self.btn_stop.pack(side="left", padx=(10, 0))
        self.bar = ctk.CTkProgressBar(frm_run, height=8, corner_radius=4,
                                      progress_color=ACCENT, fg_color=CARD)
        self.bar.set(0)
        self.bar.pack(side="left", fill="x", expand=True, padx=(18, 0))

        # ---- 高级参数（独立窗口，不挤占结果区） ----
        self.btn_adv = ctk.CTkButton(
            m, text="⚙  高级参数 // ADVANCED", width=190, height=26, corner_radius=6,
            fg_color="transparent", hover_color=CARD_HI,
            font=self.f_mono_sm, text_color=GRAY, anchor="w", command=self._open_adv)
        self.btn_adv.pack(anchor="w", pady=(5, 0))

        # ---- 结果卡片 ----
        frm_cards = ctk.CTkFrame(m, fg_color="transparent", height=1)
        frm_cards.pack(fill="x", pady=(8, 4))
        for c in range(3):
            frm_cards.grid_columnconfigure(c, weight=1)
        self.card_confirmed = self._card(frm_cards, 0, "确认资产", GREEN, "A ≥ 1 或 B ≥ 2")
        self.card_suspect = self._card(frm_cards, 1, "疑似资产", ORANGE, "B = 1 或 C ≥ 1")
        self.card_rejected = self._card(frm_cards, 2, "剔除（存疑）", GRAY, "无关联证据")

        # ---- 结果区：资产列表 / 运行日志 ----
        self.tabview = ctk.CTkTabview(
            m, height=190, corner_radius=10, command=self._on_tab_change,
            fg_color=CARD, segmented_button_fg_color=PANEL,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HOVER)
        self.tabview.pack(fill="both", expand=True, pady=(4, 0))
        tab_assets = self.tabview.add("资产列表")
        tab_apps = self.tabview.add("APP 应用")
        tab_log = self.tabview.add("运行日志")

        import tkinter.ttk as ttk
        cols = ("分类", "主机", "IP", "端口", "标题", "敏感发现", "归属说明")
        widths = (64, 190, 115, 55, 190, 150, 330)
        self.tree = ttk.Treeview(tab_assets, columns=cols, show="headings",
                                 selectmode="browse")
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tab_assets, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("confirmed", foreground=GREEN)
        self.tree.tag_configure("suspect", foreground=ORANGE)
        self.tree.tag_configure("unknown", foreground=GRAY)

        # APP 应用标签页（App Store 发现的移动端资产）
        acols = ("应用名", "开发者", "包名", "归属依据")
        awidths = (240, 320, 260, 260)
        self.tree_apps = ttk.Treeview(tab_apps, columns=acols, show="headings",
                                      selectmode="browse")
        for c, w in zip(acols, awidths):
            self.tree_apps.heading(c, text=c)
            self.tree_apps.column(c, width=w, anchor="w")
        avsb = ttk.Scrollbar(tab_apps, orient="vertical", command=self.tree_apps.yview)
        self.tree_apps.configure(yscrollcommand=avsb.set)
        self.tree_apps.pack(side="left", fill="both", expand=True)
        avsb.pack(side="right", fill="y")

        self._style_treeview()

        self.txt_log = ctk.CTkTextbox(tab_log, font=ctk.CTkFont(family=MONO, size=12),
                                      wrap="word", corner_radius=8,
                                      fg_color="#060b11", border_width=0)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.configure(state="disabled")
        self._apply_log_palette("dark")
        self.tabview.set("运行日志")

        # ---- 底部操作（先 pack 到底部，保证标签页不会把它挤掉） ----
        frm_done = ctk.CTkFrame(m, fg_color="transparent")
        frm_done.pack(side="bottom", fill="x", pady=(8, 0), before=self.tabview)
        self.btn_report = ctk.CTkButton(
            frm_done, text="⬇  生成报告…", width=150, height=38, corner_radius=8,
            fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color="#04141a",
            text_color_disabled="#0b3b45",
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled", command=self._open_report_dialog)
        self.btn_report.pack(side="left")
        self.btn_open_out = ctk.CTkButton(
            frm_done, text="📁 打开输出文件夹", width=150, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_out)
        self.btn_open_out.pack(side="left", padx=8)
        self.btn_open_html = ctk.CTkButton(
            frm_done, text="🌐 查看网页报告", width=140, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_html)
        self.btn_open_html.pack(side="left")
        self.btn_open_report = ctk.CTkButton(
            frm_done, text="📄 查看MD报告", width=130, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_report)
        self.btn_open_report.pack(side="left", padx=8)

    def _card(self, parent, col, caption, color, hint=""):
        f = ctk.CTkFrame(parent, corner_radius=10, fg_color=CARD, height=74,
                         border_width=1, border_color=STROKE)
        f.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 6, 0))
        ctk.CTkFrame(f, width=3, height=1, fg_color=color, corner_radius=2
                     ).pack(side="left", fill="y")
        num = ctk.CTkLabel(f, text="0",
                           font=ctk.CTkFont(family=MONO, size=26, weight="bold"),
                           text_color=color, width=52, anchor="w")
        num.pack(side="left", padx=(12, 2), pady=6)
        txt = ctk.CTkFrame(f, fg_color="transparent")
        txt.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=6)
        ctk.CTkLabel(txt, text=caption, text_color=TEXT, anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
        if hint:
            ctk.CTkLabel(txt, text=hint, text_color=GRAY, anchor="w",
                         font=self.f_mono_sm).pack(anchor="w")
        return num

    def _build_advanced_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("高级参数 · CyberCensus")
        win.geometry("800x540")
        win.configure(fg_color=BG)
        win.withdraw()
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        self.adv_win = win

        ctk.CTkLabel(win, text="// ADVANCED  ·  高级参数（修改后立即生效）",
                     font=self.f_mono_sm, text_color=ACCENT
                     ).pack(anchor="w", padx=20, pady=(14, 0))

        f = ctk.CTkFrame(win, corner_radius=10, fg_color=CARD,
                         border_width=1, border_color=STROKE)
        f.pack(fill="both", expand=True, padx=16, pady=10)
        ctk.CTkLabel(f, text="并发线程").grid(row=0, column=0, sticky="e", padx=(14, 4), pady=6)
        self.cmb_threads = ctk.CTkComboBox(f, values=["10", "20", "50", "100"],
                                           width=90)
        self.cmb_threads.set("20")
        self.cmb_threads.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(f, text="平台翻页").grid(row=0, column=2, sticky="e", padx=(16, 4))
        self.cmb_pages = ctk.CTkComboBox(f, values=["1", "2", "3", "5"], width=90)
        self.cmb_pages.set("1")
        self.cmb_pages.grid(row=0, column=3, sticky="w")
        self.var_debug = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="打印平台查询语句（排障）", variable=self.var_debug,
                      progress_color=ACCENT
                      ).grid(row=0, column=4, sticky="w", padx=16)

        ctk.CTkLabel(f, text="常用端口前N").grid(row=1, column=0, sticky="e", padx=(14, 4), pady=6)
        self.cmb_top = ctk.CTkComboBox(f, values=["0", "50", "100", "200"], width=90)
        self.cmb_top.set("0")
        self.cmb_top.grid(row=1, column=1, sticky="w")
        ctk.CTkLabel(f, text="自定义端口").grid(row=1, column=2, sticky="e", padx=(16, 4))
        self.var_ports = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_ports, width=150,
                     placeholder_text="80,443,8000-8100").grid(row=1, column=3, sticky="w")
        self.var_fullports = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="全端口(慢)", variable=self.var_fullports,
                      progress_color=ACCENT
                      ).grid(row=1, column=4, sticky="w", padx=16)
        self.var_cscan = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="C段扩展(仅主动)", variable=self.var_cscan,
                      progress_color=ACCENT
                      ).grid(row=1, column=5, sticky="w", padx=(8, 14))

        ctk.CTkLabel(f, text="输出目录").grid(row=2, column=0, sticky="e", padx=(14, 4), pady=6)
        self.var_out = ctk.StringVar(value="cybercensus_out")
        ctk.CTkEntry(f, textvariable=self.var_out).grid(row=2, column=1, columnspan=3,
                                                        sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="浏览…", width=70, command=self._browse_out
                      ).grid(row=2, column=4, sticky="w")

        self.var_sensitive = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="敏感路径探测(.git/.env等，主动模式必查)",
                      variable=self.var_sensitive, progress_color=ACCENT
                      ).grid(row=3, column=0, columnspan=3, sticky="w", padx=(14, 0), pady=2)

        self.var_ext = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="调用本机外部工具(subfinder/httpx/wafw00f/nuclei)",
                      variable=self.var_ext, progress_color=ACCENT
                      ).grid(row=3, column=3, columnspan=3, sticky="w", padx=(14, 0), pady=2)

        ctk.CTkLabel(f, text="告警Webhook").grid(row=4, column=0, sticky="e",
                                                 padx=(14, 4), pady=6)
        self.var_webhook = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_webhook, placeholder_text="钉钉/企业微信/飞书机器人 URL（可选）"
                     ).grid(row=4, column=1, columnspan=4, sticky="we", padx=(0, 14))

        ctk.CTkLabel(f, text="APP/小程序包").grid(row=5, column=0, sticky="e",
                                                 padx=(14, 4), pady=6)
        self.var_packages = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_packages,
                     placeholder_text="APK / .wxapkg 文件或目录，多个用 ; 分隔（本地静态扫描）"
                     ).grid(row=5, column=1, columnspan=3, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_packages
                      ).grid(row=5, column=4, sticky="w")
        ctk.CTkButton(f, text="目录…", width=64, command=self._pick_package_dir
                      ).grid(row=5, column=5, sticky="w", padx=(6, 14))

        ctk.CTkLabel(f, text="理解结果JSON").grid(row=6, column=0, sticky="e",
                                                  padx=(14, 4), pady=6)
        self.var_intel = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_intel,
                     placeholder_text="外部模型/子 agent 产出的 intel.json（别名/查询词/候选域）"
                     ).grid(row=6, column=1, columnspan=4, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_intel
                      ).grid(row=6, column=5, sticky="w", padx=(6, 14))

        self.var_fast = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="极速模式：跳过慢速阶段、缩短超时、提高并发（覆盖会下降）",
                      variable=self.var_fast, progress_color=ORANGE
                      ).grid(row=7, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(8, 4))

        self.var_paths = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="采集路径线索：robots.txt / sitemap.xml / 前端 JS API（主动 GET）",
                      variable=self.var_paths, progress_color=ACCENT
                      ).grid(row=8, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(0, 10))

        ctk.CTkLabel(win, text="提示：平台翻页越多越慢、越费配额；全端口扫描建议仅在授权窗口期使用。",
                     font=self.f_mono_sm, text_color=GRAY
                     ).pack(anchor="w", padx=22, pady=(2, 0))
        frm = ctk.CTkFrame(win, fg_color="transparent")
        frm.pack(fill="x", padx=20, pady=(6, 12))
        ctk.CTkButton(frm, text="完成", width=110, height=32, corner_radius=8,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color="#04141a",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=win.withdraw).pack(side="right")

    def _open_adv(self):
        self.adv_win.deiconify()
        self.adv_win.lift()
        self.adv_win.focus_force()

    # ---- 模式切换（视觉联动：卡片 / 能力矩阵 / 主按钮 / 进度条 / 标签页）----
    def _mode_hover(self, card, name, on):
        if name == self._mode:
            return
        card.configure(border_color=STROKE_HI if on else STROKE)

    def _select_mode(self, name, initial=False):
        meta = MODE_META.get(name)
        if not meta:
            return
        code, color, hover, desc, chips = meta
        self._mode = name
        for n, w in self.mode_cards.items():
            sel = (n == name)
            w["frame"].configure(fg_color=CARD_HI if sel else CARD,
                                 border_color=w["color"] if sel else STROKE,
                                 border_width=2 if sel else 1)
            w["title"].configure(text_color=w["color"] if sel else TEXT)
            w["code"].configure(text_color=w["color"] if sel else GRAY)
            w["index"].configure(text_color=w["color"] if sel else GRAY)
            w["dot"].configure(text_color=w["color"] if sel else "#3d5064")
            w["chip"].configure(text_color=TEXT if sel else GRAY)
        caps = dict(MODE_CAPS.get(name, ()))
        for key, lbl in self.cap_labels.items():
            on = caps.get(key, False)
            lbl.configure(text=("● " if on else "○ ") + key,
                          text_color=color if on else "#3d5064")
        self.lbl_matrix_note.configure(text="//  " + MODE_HINTS.get(name, ""),
                                       text_color=GRAY)
        self.btn_start.configure(text="▶  开始测绘 · %s" % name,
                                 fg_color=color, hover_color=hover)
        self.btn_report.configure(fg_color=color, hover_color=hover)
        self.bar.configure(progress_color=color)
        self.tabview.configure(segmented_button_selected_color=color,
                               segmented_button_selected_hover_color=hover)
        self.lbl_mode_tag.configure(text=code, text_color=color)
        if name == "主动":
            self.sw_auth.pack(side="right", padx=(0, 6))
        else:
            self.sw_auth.pack_forget()

    # ---- 表格样式 ----
    def _style_treeview(self):
        """给 ttk.Treeview 套深色样式（CTk 不带表格控件，嵌入原生 Treeview）。"""
        import tkinter.ttk as ttk
        bg, fg, head, sel = "#080e16", "#c6d6e4", "#101b28", "#0e7490"
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg,
                        rowheight=30, borderwidth=0, font=("", 12))
        style.configure("Treeview.Heading", background=head, foreground=fg,
                        relief="flat", font=("", 12, "bold"))
        style.map("Treeview", background=[("selected", sel)])
        style.map("Treeview.Heading", background=[("active", head)])

    def _on_tab_change(self):
        pass   # 预留：点击标签页时的钩子

    def _populate_table(self, eng):
        """把引擎结果填进资产表格（完成扫描后调用）。"""
        self.tree.delete(*self.tree.get_children())
        for r in asset_rows(eng):
            tag = r[6]
            self.tree.insert("", "end", values=r[:7], tags=(tag,))

    def _populate_apps(self, eng):
        """把 App Store 发现的应用填进 APP 标签页。"""
        self.tree_apps.delete(*self.tree_apps.get_children())
        for track, seller, bundle, reason in getattr(eng, "apps", []) or []:
            self.tree_apps.insert("", "end",
                                  values=(track, seller, bundle, reason))

    def _apply_log_palette(self, mode):
        for tag, color in LOG_PALETTE[mode].items():
            try:
                self.txt_log.tag_config(tag, foreground=color)
            except Exception:
                pass    # 旧版 CTkTextbox 无 tag 支持，纯色输出

    # ---- 目标解析预览 ----
    def _preview_target(self):
        text = self.ent_target.get()
        if not text.strip():
            self.lbl_preview.configure(text="AUTO-DETECT · 自动识别输入类型…",
                                       text_color=GRAY)
            return
        names, domains, ips, errors = parse_targets(text)
        if errors:
            self.lbl_preview.configure(text=errors[0], text_color=RED)
            return
        parts = []
        if names:
            parts.append("名称×%d" % len(names))
        if domains:
            parts.append("域名×%d" % len(domains))
        if ips:
            parts.append("IP×%d" % len(ips))
        self.lbl_preview.configure(text="识别：" + "、".join(parts), text_color=GREEN)

    # ---- 平台可用性 ----
    def _refresh_platforms(self):
        cfg = prov_layer.load_config(CONFIG_PATH)
        enabled = set(prov_layer.available_providers(cfg))
        for name, label in PLATFORM_LABELS:
            sw = self.sw_platforms[name]
            if name in enabled:
                sw.configure(text=label, state="normal")
                self.var_platforms[name].set(True)
            else:
                sw.configure(text=label + "（未配Key）", state="disabled")
                self.var_platforms[name].set(False)

    # ---- 输出目录浏览 ----
    def _browse_out(self):
        d = filedialog.askdirectory(initialdir=BASE_DIR, title="选择输出目录")
        if d:
            self.var_out.set(d)

    # ---- APP / 小程序包选择（本地静态分析）----
    def _pick_packages(self):
        paths = filedialog.askopenfilenames(
            title="选择 APK / 小程序包（可多选）",
            filetypes=[("APP 包", "*.apk *.wxapkg *.ap"), ("所有文件", "*.*")])
        if paths:
            self.var_packages.set(";".join(paths))

    def _pick_package_dir(self):
        d = filedialog.askdirectory(title="选择包含 APK / .wxapkg 的目录")
        if d:
            cur = self.var_packages.get().strip()
            self.var_packages.set((cur + ";" if cur else "") + d)

    def _pick_intel(self):
        p = filedialog.askopenfilename(
            title="选择外部模型/子 agent 产出的理解结果 JSON",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")])
        if p:
            self.var_intel.set(p)

    # ---- Key 配置对话框 ----
    def _open_key_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("平台 API Key 配置（写入 config.json；环境变量优先于本文件）")
        win.geometry("580x330")
        win.resizable(False, False)
        win.after(300, lambda: win.grab_set())   # CTkToplevel 需等窗口显示后再 grab

        data = {}
        if os.path.isfile(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                data = {}
        for k in ("fofa", "zerozone", "hunter", "daydaymap"):
            data.setdefault(k, {})

        fields = [
            ("FOFA 邮箱", "fofa", "email", False),
            ("FOFA Key", "fofa", "key", True),
            ("0.zone Key", "zerozone", "key", True),
            ("鹰图 Hunter Key", "hunter", "key", True),
            ("DayDayMap Key", "daydaymap", "key", True),
        ]
        entries = []
        for i, (label, sec, key, secret) in enumerate(fields):
            ctk.CTkLabel(win, text=label).grid(row=i, column=0, sticky="e",
                                               padx=(14, 6), pady=7)
            var = ctk.StringVar(value=str(data.get(sec, {}).get(key, "") or ""))
            ent = ctk.CTkEntry(win, textvariable=var, width=340, show="*" if secret else "")
            ent.grid(row=i, column=1, sticky="w", padx=(0, 10))
            entries.append((sec, key, var, ent))

        var_show = ctk.BooleanVar(value=False)

        def _toggle_show():
            show = "" if var_show.get() else "*"
            for sec, key, var, ent in entries:
                if ent.cget("show"):
                    ent.configure(show=show)

        ctk.CTkSwitch(win, text="显示明文", variable=var_show, command=_toggle_show
                      ).grid(row=len(fields), column=1, sticky="w")

        def _save():
            for sec, key, var, ent in entries:
                data.setdefault(sec, {})[key] = var.get().strip()
            try:
                with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=2)
            except Exception as e:
                messagebox.showerror("保存失败", str(e), parent=win)
                return
            self._refresh_platforms()
            messagebox.showinfo("已保存", "config.json 已更新。", parent=win)
            win.destroy()

        frm = ctk.CTkFrame(win, fg_color="transparent")
        frm.grid(row=len(fields) + 1, column=0, columnspan=2, pady=(10, 4))
        ctk.CTkButton(frm, text="保存", width=100, command=_save).pack(side="left", padx=8)
        ctk.CTkButton(frm, text="取消", width=100, fg_color="gray40",
                      command=win.destroy).pack(side="left", padx=8)

    # ---- 开始/停止 ----
    def _on_start(self):
        if self._worker and self._worker.is_alive():
            return
        names, domains, ips, errors = parse_targets(self.ent_target.get())
        if errors:
            messagebox.showerror("目标解析失败", "\n".join(errors))
            return
        if not names and not domains and not ips:
            messagebox.showwarning("缺少目标",
                                   "请输入单位名称 / 域名 / IP / 网段（可多个，空格或逗号分隔）")
            return
        mode = MODE_MAP.get(self._mode, "standard")
        if mode == "active" and not self.var_auth.get():
            messagebox.showwarning("需要授权确认",
                                   "主动扫描会真实访问并扫描目标，请先勾选书面授权确认。")
            return
        if self.var_fullports.get():
            if not messagebox.askyesno("全端口确认", "全端口 1-65535 非常慢，确定继续？"):
                return
        platforms = [n for n, v in self.var_platforms.items() if v.get()]
        packages = [p.strip() for p in re.split(r"[;\n]+", self.var_packages.get())
                    if p.strip()]
        outdir = os.path.abspath(self.var_out.get().strip() or "cybercensus_out")
        args = build_args(
            mode, platforms,
            threads=_to_int(self.cmb_threads.get(), 20),
            provider_pages=_to_int(self.cmb_pages.get(), 1),
            cscan=self.var_cscan.get(),
            top=_to_int(self.cmb_top.get(), 0),
            ports=self.var_ports.get().strip(),
            full_ports=self.var_fullports.get(),
            out=outdir,
            debug_provider=self.var_debug.get(),
            sensitive=self.var_sensitive.get(),
            probe_interval=0.0,
            webhook=self.var_webhook.get().strip(),
            ext=self.var_ext.get(),
            packages=packages,
            intel=self.var_intel.get().strip(),
            fast=self.var_fast.get(),
            paths=self.var_paths.get(),
        )
        self._last_out_dir = args.out

        # 重置界面状态
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.tree_apps.delete(*self.tree_apps.get_children())
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="…")
        self.btn_report.configure(state="disabled")
        self.btn_open_out.configure(state="disabled")
        self.btn_open_report.configure(state="disabled")
        self.btn_open_html.configure(state="disabled")
        self._last_md_path = None
        self._last_html_path = None
        self.tabview.set("运行日志")

        self._set_running(True)
        self._stop_flag.clear()
        if not platforms:
            self._append_log("未选择任何平台（或未配 Key）：只跑本地被动采集。", "!")
        self._append_log("目标已提交，开始测绘…", "#")
        self.bar.start()

        cybercensus.LOG_HOOK = lambda msg, level: self._queue.put(("log", msg, level))
        self._worker = threading.Thread(target=self._run,
                                        args=(args, names, domains, ips),
                                        daemon=True)
        self._worker.start()

    def _run(self, args, names, domains, ips):
        try:
            # 界面模式：只采集+分级，结果先展示在"资产列表"，
            # 报告由用户点"生成报告"时按所选格式再写文件
            eng, _files, _jp, _mp = cybercensus.run_pipeline(
                args, names, domains, ips,
                should_stop=self._stop_flag.is_set, do_output=False)
            self._queue.put(("done", (eng,)))
        except Exception:
            self._queue.put(("error", traceback.format_exc()))

    def _on_stop(self):
        if not (self._worker and self._worker.is_alive()):
            return
        self._stop_flag.set()
        self.btn_stop.configure(state="disabled")
        self._append_log("已请求停止：当前阶段结束后对已收集数据做分级输出。", "!")

    def _set_running(self, running):
        self.btn_start.configure(state="disabled" if running else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        if running:
            self._set_status("● 运行中", ORANGE)
        else:
            self.bar.stop()

    # ---- 队列轮询（工作线程 → 界面线程）----
    def _poll(self):
        try:
            while True:
                item = self._queue.get_nowait()
                if item[0] == "log":
                    self._append_log(item[1], item[2])
                elif item[0] == "done":
                    self._on_done(*item[1])
                elif item[0] == "report_done":
                    self._on_report_done(*item[1])
                elif item[0] == "error":
                    self._on_error(item[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _on_done(self, eng):
        self._set_running(False)
        self.bar.set(1)
        self._last_engine = eng
        counts = {"确认": 0, "疑似": 0, "存疑": 0}
        for a in eng.assets.values():
            counts[a.confidence] = counts.get(a.confidence, 0) + 1
        self.card_confirmed.configure(text=str(counts["确认"]))
        self.card_suspect.configure(text=str(counts["疑似"]))
        self.card_rejected.configure(text=str(counts["存疑"]))
        self._populate_table(eng)
        self._populate_apps(eng)
        self._append_log("=" * 60, "#")
        self._append_log("完成：确认 %d | 疑似 %d | 剔除 %d | 合计 %d"
                         % (counts["确认"], counts["疑似"], counts["存疑"], len(eng.assets)), "#")
        extra = []
        if getattr(eng, "apps", None):
            extra.append("APP %d 个" % len(eng.apps))
        if getattr(eng, "packages", None):
            extra.append("APP/小程序包 %d 个" % len(eng.packages))
        if getattr(eng, "js_secrets", None):
            extra.append("JS 密钥线索 %d 处" % len(eng.js_secrets))
        if getattr(eng, "ext_hits", None):
            extra.append("外部工具命中 %d 条" % len(eng.ext_hits))
        if extra:
            self._append_log("其他发现：" + " / ".join(extra) + "（报告中有单独章节）", "+")
        # 即使资产为 0，只要 APP / 包 / 密钥等有结果，也允许生成报告
        has_results = bool(eng.assets or extra)
        if has_results:
            self.btn_report.configure(state="normal")   # 结果就绪，可按需生成报告
            if eng.assets:
                self.tabview.set("资产列表")
            elif getattr(eng, "apps", None):
                self.tabview.set("APP 应用")
            self._set_status("● 扫描完成", GREEN)
        else:
            self._append_log("未发现任何资产或线索，无需生成报告。", "!")
            self._set_status("● 未发现资产", ORANGE)

    def _on_error(self, tb_text):
        self._set_running(False)
        self.bar.set(0)
        self._set_status("● 出错", RED)
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="0")
        if getattr(self, "_last_engine", None) is not None:
            self.btn_report.configure(state="normal")
        self._append_log("运行出错：", "!")
        for line in tb_text.strip().splitlines()[-8:]:
            self._append_log("  " + line, "!")

    # ---- 生成报告（按需导出，用户选格式）----
    def _open_report_dialog(self):
        eng = getattr(self, "_last_engine", None)
        if eng is None:
            return
        win = ctk.CTkToplevel(self)
        win.title("生成报告")
        win.geometry("460x370")
        win.resizable(False, False)
        win.after(300, lambda: win.grab_set())

        ctk.CTkLabel(win, text="选择要导出的报告格式",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w",
                                                                    padx=18, pady=(16, 8))
        var_md = ctk.BooleanVar(value=True)
        var_html = ctk.BooleanVar(value=True)
        var_csv = ctk.BooleanVar(value=True)
        var_json = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(win, text="网页报告（HTML，带资产关系图，适合交付）",
                      variable=var_html).pack(anchor="w", padx=22, pady=3)
        ctk.CTkSwitch(win, text="可读报告（MD，纯文本版）",
                      variable=var_md).pack(anchor="w", padx=22, pady=3)
        ctk.CTkSwitch(win, text="资产台账（CSV，适合 Excel 管理）",
                      variable=var_csv).pack(anchor="w", padx=22, pady=3)
        ctk.CTkSwitch(win, text="原始数据（JSON，适合程序处理）",
                      variable=var_json).pack(anchor="w", padx=22, pady=3)

        frm_dir = ctk.CTkFrame(win, fg_color="transparent")
        frm_dir.pack(fill="x", padx=18, pady=(10, 4))
        ctk.CTkLabel(frm_dir, text="保存到").pack(side="left", padx=(0, 6))
        var_out = ctk.StringVar(value=self.var_out.get().strip() or "cybercensus_out")
        ctk.CTkEntry(frm_dir, textvariable=var_out).pack(side="left", fill="x",
                                                         expand=True, padx=(0, 6))
        ctk.CTkButton(frm_dir, text="浏览…", width=70,
                      command=lambda: var_out.set(
                          filedialog.askdirectory(initialdir=BASE_DIR) or var_out.get())
                      ).pack(side="left")

        def _generate():
            fmts = [k for k, v in (("html", var_html.get()), ("md", var_md.get()),
                                   ("csv", var_csv.get()), ("json", var_json.get())) if v]
            if not fmts:
                messagebox.showwarning("未选择格式", "请至少选择一种报告格式。", parent=win)
                return
            win.destroy()
            self._generate_report(eng, fmts, var_out.get().strip() or "cybercensus_out")

        ctk.CTkButton(win, text="生成", width=110, command=_generate
                      ).pack(pady=(12, 16))

    def _generate_report(self, eng, fmts, outdir):
        outdir = os.path.abspath(outdir)
        eng.args.output_formats = ",".join(fmts)
        eng.args.out = outdir
        self._last_out_dir = outdir

        def _job():
            try:
                cybercensus.LOG_HOOK = lambda msg, level: self._queue.put(("log", msg, level))
                files, json_path, md_path = eng.output()
                self._queue.put(("report_done", (files, json_path, md_path)))
            except Exception:
                self._queue.put(("error", traceback.format_exc()))

        self.btn_report.configure(state="disabled")
        self._append_log("== 生成报告（%s）==" % "+".join(fmts), "#")
        threading.Thread(target=_job, daemon=True).start()

    def _on_report_done(self, files, json_path, md_path):
        n = len(files) + (1 if json_path else 0) + (1 if md_path else 0)
        self._append_log("报告已生成：%d 个文件" % n, "+")
        if files.get("confirmed"):
            self._append_log("确认台账：%s" % files["confirmed"], "+")
        if md_path:
            self._last_md_path = md_path
            self._append_log("可读报告：%s" % md_path, "+")
        self.btn_report.configure(state="normal")
        if files or json_path or md_path:
            self.btn_open_out.configure(state="normal")
        if md_path:
            self.btn_open_report.configure(state="normal")
        if files.get("html"):
            self._last_html_path = files["html"]
            self.btn_open_html.configure(state="normal")
            self._append_log("网页报告：%s" % files["html"], "+")
        self._set_status("● 报告已生成", GREEN)
        messagebox.showinfo("完成", "报告已生成（%d 个文件），见「打开输出文件夹」。" % n)

    # ---- 打开产物 ----
    def _open_out(self):
        if self._last_out_dir and os.path.isdir(self._last_out_dir):
            os.startfile(self._last_out_dir)   # noqa: S606 (Windows only)

    def _open_report(self):
        if self._last_md_path and os.path.isfile(self._last_md_path):
            os.startfile(self._last_md_path)   # noqa: S606

    def _open_html(self):
        if self._last_html_path and os.path.isfile(self._last_html_path):
            os.startfile(self._last_html_path)   # noqa: S606

    # ---- 日志输出 ----
    def _append_log(self, msg, level="*"):
        tag = {"#": "hdr", "+": "good", "!": "warn"}.get(level, "norm")
        self.txt_log.configure(state="normal")
        try:
            self.txt_log.insert("end", "[%s] %s\n" % (level, msg), tag)
        except Exception:
            self.txt_log.insert("end", "[%s] %s\n" % (level, msg))
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    # ---- 关闭 ----
    def _on_close(self):
        if self._worker and self._worker.is_alive():
            if not messagebox.askyesno(APP_TITLE, "测绘仍在运行，确定退出吗？"):
                return
        cybercensus.LOG_HOOK = None
        self._stop_flag.set()
        self.destroy()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--smoke" in argv:
        # 自检：构建界面后立即销毁（验证控件/布局无异常）
        app = App()
        app.update_idletasks()
        app.update()
        app.destroy()
        print("GUI smoke OK")
        return 0
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
