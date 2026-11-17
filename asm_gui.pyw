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
MODE_HINTS = {
    "被动": "完全不触碰目标，纯第三方数据",
    "标准": "仅探测主域名建立锚点",
    "复核": "对疑似资产做一次 HTTP 复核",
    "主动": "端口扫描 + Web 指纹（需授权）",
}

PLATFORM_LABELS = [
    ("fofa", "FOFA"),
    ("zerozone", "0.zone 零零信安"),
    ("hunter", "鹰图 Hunter"),
    ("daydaymap", "DayDayMap"),
]

ACCENT = "#2f81f7"
RED = "#e5534b"
GREEN = "#3fb950"
ORANGE = "#d29922"
GRAY = "#8b949e"

LOG_PALETTE = {
    "dark": {"hdr": "#58a6ff", "good": "#3fb950", "warn": "#d29922", "norm": "#c9d1d9"},
    "light": {"hdr": "#0969da", "good": "#1a7f37", "warn": "#9a6700", "norm": "#24292f"},
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
               formats=None):
    """由界面选择构造 argparse.Namespace（与 CLI 参数一一对应）。

    mode: passive / standard / verify / active
    formats: 输出格式列表（"md"/"csv"/"json" 的子集），空=全部
    """
    active = (mode == "active")
    args = argparse.Namespace(
        beian="",
        threads=max(1, int(threads)),
        timeout=10.0,
        scan_timeout=2.5,
        out=out,
        output_formats=(",".join(formats) if formats else "md,csv,json"),
        no_probe=(mode == "passive"),
        no_discover=False,   # 名称模式默认启用搜索引擎官网自举（被动模式自动跳过）
        probe_found=False,
        probe_limit=100,
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
    """从引擎结果提取表格行：[(分类, 主机, IP, 端口, 标题, 归属说明, tag), ...]。

    按 确认 → 疑似 → 存疑 排序；归属说明用白话证据（截断到 max_evidence 条）。
    纯函数，供界面表格与单元测试共用。
    """
    order = {"确认": 0, "疑似": 1, "存疑": 2}
    tag_map = {"确认": "confirmed", "疑似": "suspect", "存疑": "unknown"}
    rows = []
    for a in eng.assets.values():
        plain = cybercensus.plain_evidence(a.evidence, max_items=max_evidence) or "—"
        rows.append((
            a.confidence, a.host or a.ip or "", a.ip or "", str(a.port or ""),
            a.title or "", plain, tag_map.get(a.confidence, "unknown"),
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
        self.geometry("1060x700")
        self.minsize(920, 640)

        self._queue = queue.Queue()
        self._worker = None
        self._stop_flag = threading.Event()
        self._last_out_dir = None
        self._last_md_path = None
        self._last_engine = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._refresh_platforms()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll)

    # ------------------------------------------------------------------
    # 侧边栏
    # ------------------------------------------------------------------
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=240, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsw")
        sb.grid_propagate(False)
        sb.grid_rowconfigure(10, weight=1)   # 弹性空隙
        self._sidebar = sb

        ctk.CTkLabel(sb, text="CyberCensus", font=ctk.CTkFont(size=24, weight="bold")
                     ).grid(row=0, column=0, sticky="w", padx=22, pady=(24, 0))
        ctk.CTkLabel(sb, text="互联网暴露面测绘 · 低误报",
                     text_color=GRAY).grid(row=1, column=0, sticky="w", padx=22)

        self._hline(sb, 2)

        ctk.CTkLabel(sb, text="测绘平台", font=ctk.CTkFont(size=13, weight="bold")
                     ).grid(row=3, column=0, sticky="w", padx=22, pady=(6, 2))
        self.sw_platforms = {}
        self.var_platforms = {}
        for i, (name, label) in enumerate(PLATFORM_LABELS):
            var = ctk.BooleanVar(value=True)
            sw = ctk.CTkSwitch(sb, text=label, variable=var, onvalue=True, offvalue=False)
            sw.grid(row=4 + i, column=0, sticky="w", padx=22, pady=3)
            self.sw_platforms[name] = sw
            self.var_platforms[name] = var
        ctk.CTkLabel(sb, text="未配 Key 也能跑：本地被动源 + 官网自举",
                     text_color=GREEN, font=ctk.CTkFont(size=11)
                     ).grid(row=8, column=0, sticky="w", padx=22, pady=(2, 4))

        self._hline(sb, 9)

        ctk.CTkButton(sb, text="配置平台 Key…", command=self._open_key_dialog
                      ).grid(row=11, column=0, sticky="ew", padx=18, pady=(4, 2))

        self.var_dark = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(sb, text="深色模式", variable=self.var_dark,
                      command=self._toggle_theme
                      ).grid(row=12, column=0, sticky="w", padx=22, pady=6)

        ctk.CTkLabel(sb, text="被动优先 · 证据分级 A/B/C", text_color=GRAY,
                     font=ctk.CTkFont(size=11)
                     ).grid(row=13, column=0, sticky="w", padx=22, pady=(2, 12))

    @staticmethod
    def _hline(parent, row):
        ctk.CTkFrame(parent, height=1, fg_color="gray25", corner_radius=0
                     ).grid(row=row, column=0, sticky="ew", padx=18, pady=8)

    # ------------------------------------------------------------------
    # 主工作区
    # ------------------------------------------------------------------
    def _build_main(self):
        m = ctk.CTkFrame(self, fg_color="transparent")
        m.grid(row=0, column=1, sticky="nsew", padx=18, pady=14)
        self._main = m

        # ---- 目标输入 ----
        ctk.CTkLabel(m, text="测绘目标", font=ctk.CTkFont(size=13, weight="bold")
                     ).pack(anchor="w")
        self.var_target = ctk.StringVar()
        self.ent_target = ctk.CTkEntry(
            m, textvariable=self.var_target, height=42,
            font=ctk.CTkFont(size=14), corner_radius=8,
            placeholder_text="单位名称 / 域名 / IP / 网段 —— 可多个，空格或逗号分隔")
        self.ent_target.pack(fill="x", pady=(4, 2))
        self.ent_target.bind("<KeyRelease>", lambda e: self._preview_target())
        self.lbl_preview = ctk.CTkLabel(m, text="自动识别输入类型…", text_color=GRAY,
                                        font=ctk.CTkFont(size=12))
        self.lbl_preview.pack(anchor="w")

        # ---- 模式 ----
        frm_mode = ctk.CTkFrame(m, fg_color="transparent")
        frm_mode.pack(fill="x", pady=(8, 2))
        self.seg_mode = ctk.CTkSegmentedButton(
            frm_mode, values=list(MODE_MAP.keys()), command=self._on_mode_change,
            font=ctk.CTkFont(size=13), height=32)
        self.seg_mode.set("标准")
        self.seg_mode.pack(side="left")
        self.lbl_mode_hint = ctk.CTkLabel(frm_mode, text=MODE_HINTS["标准"],
                                          text_color=GRAY, font=ctk.CTkFont(size=12))
        self.lbl_mode_hint.pack(side="left", padx=12)
        # 授权开关（选"主动"时才显示）
        self.var_auth = ctk.BooleanVar(value=False)
        self.sw_auth = ctk.CTkSwitch(
            frm_mode, text="我已获得书面授权", variable=self.var_auth,
            text_color=RED, progress_color=RED)

        # ---- 运行按钮 ----
        frm_run = ctk.CTkFrame(m, fg_color="transparent")
        frm_run.pack(fill="x", pady=(8, 0))
        self.btn_start = ctk.CTkButton(
            frm_run, text="▶  开始测绘", width=150, height=38, corner_radius=8,
            font=ctk.CTkFont(size=14, weight="bold"), fg_color=ACCENT,
            hover_color="#1f6feb", command=self._on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ctk.CTkButton(
            frm_run, text="⏹ 停止并输出", width=120, height=38, corner_radius=8,
            fg_color=RED, hover_color="#c93c37", state="disabled",
            command=self._on_stop)
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.bar = ctk.CTkProgressBar(frm_run, height=8, corner_radius=4)
        self.bar.set(0)
        self.bar.pack(side="left", fill="x", expand=True, padx=(14, 0))

        # ---- 高级选项（收起） ----
        self.btn_adv = ctk.CTkButton(
            m, text="▸  高级选项", width=110, height=26, corner_radius=6,
            fg_color="transparent", hover_color=("gray80", "gray25"),
            text_color=GRAY, anchor="w", command=self._toggle_adv)
        self.btn_adv.pack(anchor="w", pady=(6, 0))
        self._build_advanced()

        # ---- 结果卡片 ----
        frm_cards = ctk.CTkFrame(m, fg_color="transparent")
        frm_cards.pack(fill="x", pady=(10, 4))
        for c in range(3):
            frm_cards.grid_columnconfigure(c, weight=1)
        self.card_confirmed = self._card(frm_cards, 0, "确认资产", GREEN)
        self.card_suspect = self._card(frm_cards, 1, "疑似资产", ORANGE)
        self.card_rejected = self._card(frm_cards, 2, "剔除（存疑）", GRAY)

        # ---- 结果区：资产列表 / 运行日志 双标签页 ----
        self.tabview = ctk.CTkTabview(m, corner_radius=8, command=self._on_tab_change)
        self.tabview.pack(fill="both", expand=True, pady=(8, 0))
        tab_assets = self.tabview.add("资产列表")
        tab_log = self.tabview.add("运行日志")

        # 资产表格（ttk.Treeview，深色样式）
        import tkinter.ttk as ttk
        cols = ("分类", "主机", "IP", "端口", "标题", "归属说明")
        widths = (70, 200, 120, 60, 220, 380)
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
        self._style_treeview("dark")

        # 运行日志
        self.txt_log = ctk.CTkTextbox(tab_log, font=ctk.CTkFont(family="Consolas", size=12),
                                      wrap="word", corner_radius=8)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.configure(state="disabled")
        self._apply_log_palette("dark")
        self.tabview.set("运行日志")   # 扫描过程默认看日志，完成后自动切到资产列表

        # ---- 底部按钮 ----
        frm_done = ctk.CTkFrame(m, fg_color="transparent")
        frm_done.pack(fill="x", pady=(8, 0))
        self.btn_report = ctk.CTkButton(frm_done, text="⬇ 生成报告…", width=130,
                                        state="disabled", command=self._open_report_dialog)
        self.btn_report.pack(side="left")
        self.btn_open_out = ctk.CTkButton(frm_done, text="打开输出文件夹",
                                          width=140, state="disabled",
                                          command=self._open_out)
        self.btn_open_out.pack(side="left", padx=8)
        self.btn_open_report = ctk.CTkButton(frm_done, text="查看报告 (MD)",
                                             width=140, state="disabled",
                                             command=self._open_report)
        self.btn_open_report.pack(side="left")

    def _card(self, parent, col, caption, color):
        f = ctk.CTkFrame(parent, corner_radius=10)
        f.grid(row=0, column=col, sticky="ew", padx=6)
        num = ctk.CTkLabel(f, text="—", font=ctk.CTkFont(size=30, weight="bold"),
                           text_color=color)
        num.pack(pady=(12, 0))
        ctk.CTkLabel(f, text=caption, text_color=GRAY,
                     font=ctk.CTkFont(size=12)).pack(pady=(0, 12))
        return num

    def _build_advanced(self):
        f = ctk.CTkFrame(self._main, corner_radius=8)
        self.frm_adv = f   # 不 pack，展开时显示
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
        ctk.CTkSwitch(f, text="打印平台查询语句（排障）", variable=self.var_debug
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
        ctk.CTkSwitch(f, text="全端口(慢)", variable=self.var_fullports
                      ).grid(row=1, column=4, sticky="w", padx=16)
        self.var_cscan = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="C段扩展(仅主动)", variable=self.var_cscan
                      ).grid(row=1, column=5, sticky="w", padx=(8, 14))

        ctk.CTkLabel(f, text="输出目录").grid(row=2, column=0, sticky="e", padx=(14, 4), pady=6)
        self.var_out = ctk.StringVar(value="cybercensus_out")
        ctk.CTkEntry(f, textvariable=self.var_out).grid(row=2, column=1, columnspan=3,
                                                        sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="浏览…", width=70, command=self._browse_out
                      ).grid(row=2, column=4, sticky="w")

    # ---- 主题 / 选项面板 ----
    def _toggle_theme(self):
        mode = "dark" if self.var_dark.get() else "light"
        ctk.set_appearance_mode(mode)
        self._apply_log_palette(mode)
        self._style_treeview(mode)

    def _style_treeview(self, mode):
        """给 ttk.Treeview 套深/浅色样式（CTk 不带表格控件，嵌入原生 Treeview）。"""
        import tkinter.ttk as ttk
        if mode == "dark":
            bg, fg, head, sel = "#161b22", "#c9d1d9", "#21262d", "#2f81f7"
        else:
            bg, fg, head, sel = "#ffffff", "#24292f", "#eaeef2", "#0969da"
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg,
                        rowheight=26, borderwidth=0, font=("", 12))
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
            self.tree.insert("", "end", values=r[:6], tags=(tag,))

    def _apply_log_palette(self, mode):
        for tag, color in LOG_PALETTE[mode].items():
            try:
                self.txt_log.tag_config(tag, foreground=color)
            except Exception:
                pass    # 旧版 CTkTextbox 无 tag 支持，纯色输出

    def _toggle_adv(self):
        if self.frm_adv.winfo_ismapped():
            self.frm_adv.pack_forget()
            self.btn_adv.configure(text="▸  高级选项")
        else:
            self.frm_adv.pack(fill="x", pady=(4, 0), after=self.btn_adv)
            self.btn_adv.configure(text="▾  高级选项")

    def _on_mode_change(self, value):
        self.lbl_mode_hint.configure(text=MODE_HINTS.get(value, ""))
        if value == "主动":
            self.sw_auth.pack(side="right")
        else:
            self.sw_auth.pack_forget()

    # ---- 目标解析预览 ----
    def _preview_target(self):
        text = self.ent_target.get()
        if not text.strip():
            self.lbl_preview.configure(text="自动识别输入类型…", text_color=GRAY)
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
        mode = MODE_MAP.get(self.seg_mode.get(), "standard")
        if mode == "active" and not self.var_auth.get():
            messagebox.showwarning("需要授权确认",
                                   "主动扫描会真实访问并扫描目标，请先勾选书面授权确认。")
            return
        if self.var_fullports.get():
            if not messagebox.askyesno("全端口确认", "全端口 1-65535 非常慢，确定继续？"):
                return
        platforms = [n for n, v in self.var_platforms.items() if v.get()]
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
        )
        self._last_out_dir = args.out

        # 重置界面状态
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="…")
        self.btn_report.configure(state="disabled")
        self.btn_open_out.configure(state="disabled")
        self.btn_open_report.configure(state="disabled")
        self._last_md_path = None
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
        if not running:
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
        self._append_log("=" * 60, "#")
        self._append_log("完成：确认 %d | 疑似 %d | 剔除 %d | 合计 %d"
                         % (counts["确认"], counts["疑似"], counts["存疑"], len(eng.assets)), "#")
        if eng.assets:
            self.btn_report.configure(state="normal")   # 结果就绪，可按需生成报告
            self.tabview.set("资产列表")
        else:
            self._append_log("未发现任何资产，无需生成报告。", "!")

    def _on_error(self, tb_text):
        self._set_running(False)
        self.bar.set(0)
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="—")
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
        win.geometry("460x300")
        win.resizable(False, False)
        win.after(300, lambda: win.grab_set())

        ctk.CTkLabel(win, text="选择要导出的报告格式",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w",
                                                                    padx=18, pady=(16, 8))
        var_md = ctk.BooleanVar(value=True)
        var_csv = ctk.BooleanVar(value=True)
        var_json = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(win, text="可读报告（MD，适合阅读和交付）",
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
            fmts = [k for k, v in (("md", var_md.get()), ("csv", var_csv.get()),
                                   ("json", var_json.get())) if v]
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
        messagebox.showinfo("完成", "报告已生成（%d 个文件），见「打开输出文件夹」。" % n)

    # ---- 打开产物 ----
    def _open_out(self):
        if self._last_out_dir and os.path.isdir(self._last_out_dir):
            os.startfile(self._last_out_dir)   # noqa: S606 (Windows only)

    def _open_report(self):
        if self._last_md_path and os.path.isfile(self._last_md_path):
            os.startfile(self._last_md_path)   # noqa: S606

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
