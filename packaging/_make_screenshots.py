"""生成 CSDN 宣传稿用的界面演示截图（全部为虚构演示数据）。"""
import argparse
import importlib.util
import os
import sys
import tempfile
import time

from PIL import ImageGrab

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)

sys.argv = ["asm_gui.pyw"]
spec = importlib.util.spec_from_file_location("asm_gui", os.path.join(ROOT, "asm_gui.pyw"))
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
import cybercensus  # noqa: E402


def fake_engine():
    e = cybercensus.Engine(argparse.Namespace(
        beian="", threads=10, timeout=5,
        out=tempfile.mkdtemp(prefix="cc_demo_"),
        output_formats="html"))
    rows = [
        ("www.yunchi.example", 443, "https", "确认",
         "云驰出行 - 官方网站", "203.0.113.20",
         ["A|主域名子域:yunchi.example", "A|证书O=一致:云驰出行科技有限公司",
          "B|页面备案号一致:京ICP备2024000000号"],
         {"beian": "京ICP备2024000000号-1", "cert_org": "云驰出行科技有限公司",
          "rdap_org": "云驰出行科技有限公司", "asn": "AS64500",
          "asn_org": "YUNCHI-MOBILITY-AS",
          "emails": {"security@yunchi.example"},
          "phones": {"010-00000000"},
          "authorities": {"云驰出行科技有限公司"},
          "trackings": {"ga4:G-YUNCHI2024"},
          "verify_tokens": {"google:yunchi-demo-token"},
          "credit_code": "91110108MA0000000X",
          "site_code": "11010800000000000000",
          "police_beian": "京公网安备 11010800000000号",
          "registry_ids": {"LEI:YUNCHI000000000000000"},
          "refs": {"src.yunchi.example", "open.yunchi.example"},
          "server": "nginx/1.24.0",
          "tech": "nginx / Vue / jQuery",
          "source": "crt.sh",
          "title": "云驰出行 - 官方网站"}),
        ("src.yunchi.example", 443, "https", "确认",
         "云驰安全应急响应中心", "203.0.113.21",
         ["A|主域名子域:yunchi.example", "A|证书O=一致:云驰出行科技有限公司",
          "B|统计/像素ID一致:ga4:G-YUNCHI2024"],
         {"cert_org": "云驰出行科技有限公司", "trackings": {"ga4:G-YUNCHI2024"},
          "source": "crt.sh", "title": "云驰安全应急响应中心"}),
        ("open.yunchi.example", 443, "https", "确认",
         "云驰开放平台 - 开发者中心", "203.0.113.22",
         ["A|主域名子域:yunchi.example", "B|页脚主办/版权单位一致:云驰出行科技有限公司"],
         {"authorities": {"云驰出行科技有限公司"}, "source": "搜索引擎",
          "title": "云驰开放平台 - 开发者中心"}),
        ("api.yunchi.example", 443, "https", "确认",
         "云驰开放 API 网关", "203.0.113.23",
         ["A|证书O=一致:云驰出行科技有限公司", "B|联系邮箱一致:security@yunchi.example"],
         {"cert_org": "云驰出行科技有限公司",
          "emails": {"security@yunchi.example"}, "source": "httpx",
          "title": "云驰开放 API 网关"}),
        ("sso.yunchi.example", 443, "https", "疑似",
         "统一身份认证 - 登录", "203.0.113.24",
         ["B|平台domain命中(待核)", "C|同锚点IP:203.0.113.24"],
         {"source": "FOFA", "title": "统一身份认证 - 登录"}),
        ("jenkins.yunchi.example", 8080, "http", "疑似",
         "Jenkins", "203.0.113.25",
         ["B|统计/像素ID一致:ga4:G-YUNCHI2024", "C|平台IP命中:203.0.113.25"],
         {"trackings": {"ga4:G-YUNCHI2024"}, "source": "FOFA",
          "title": "Jenkins"}),
        ("gitlab.yunchi.example", 443, "https", "疑似",
         "GitLab", "203.0.113.26",
         ["C|平台IP命中:203.0.113.26"],
         {"source": "Hunter", "title": "GitLab"}),
        ("test.yunchi.example", 443, "https", "疑似",
         "预发布环境", "203.0.113.27",
         ["B|平台domain命中(待核)"],
         {"source": "DayDayMap", "title": "预发布环境"}),
        ("vpn.yunchi.example", 443, "https", "存疑",
         "SSL VPN", "203.0.113.28",
         [],
         {"reject_reason": "无任何关联证据"}),
        ("cdn.yunchi.example", 443, "https", "存疑",
         "CDN 节点", "203.0.113.29",
         [],
         {"reject_reason": "第三方云/CDN资源，且无强关联证据"}),
        ("mail.yunchi.example", 443, "https", "存疑",
         "企业邮箱", "203.0.113.30",
         [],
         {"reject_reason": "无任何关联证据"}),
        ("old.yunchi.example", 80, "http", "存疑",
         "站点已迁移", "203.0.113.31",
         [],
         {"reject_reason": "无任何关联证据"}),
    ]
    for host, port, scheme, conf, title, ip, ev, extra in rows:
        a = e.add_asset(host, port, scheme, source="demo")
        a.source = {extra.get("source", "crt.sh")}
        a.confidence = conf
        a.title = title
        a.ip = ip
        a.evidence = ev
        a.cert_org = extra.get("cert_org", "")
        a.beian = extra.get("beian", "")
        a.rdap_org = extra.get("rdap_org", "")
        a.asn = extra.get("asn", "")
        a.asn_org = extra.get("asn_org", "")
        a.reject_reason = extra.get("reject_reason", "")
        a.status = "200 OK" if conf != "存疑" else "404 Not Found"
        a.server = extra.get("server", "nginx")
        a.tech = extra.get("tech", "nginx / Vue")
        a.credit_code = extra.get("credit_code", "")
        a.site_code = extra.get("site_code", "")
        a.police_beian = extra.get("police_beian", "")
        a.registry_ids.update(extra.get("registry_ids") or set())
        a.refs.update(extra.get("refs") or set())
        a.emails.update(extra.get("emails") or set())
        a.phones.update(extra.get("phones") or set())
        a.authorities.update(extra.get("authorities") or set())
        a.trackings.update(extra.get("trackings") or set())
        a.findings.update({".git 目录可访问|敏感路径", "Swagger 接口文档|敏感路径"}
                          if host.startswith("jenkins.") else set())
    # 让图谱有足够的连线：非存疑资产都带 ASN，确认资产带证书 O=
    for a in e.assets.values():
        if a.confidence == "存疑":
            continue
        if not a.asn:
            a.asn, a.asn_org = "AS64500", "YUNCHI-MOBILITY-AS"
        if a.confidence == "确认" and not a.cert_org:
            a.cert_org = "云驰出行科技有限公司"
    e.anchor["orgs"].add("云驰出行科技有限公司")
    e.anchor["domains"].add("yunchi.example")
    return e


def grab(widget, path, topmost=False):
    if topmost:
        try:
            widget.attributes("-topmost", True)
        except Exception:
            pass
    widget.update_idletasks()
    widget.update()
    time.sleep(0.8)
    x = widget.winfo_rootx()
    y = widget.winfo_rooty()
    w = widget.winfo_width()
    h = widget.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(path)
    print("saved", path, img.size)


def main():
    app = gui.App()
    app.geometry("1180x1000+40+20")
    try:
        app.tabview.configure(height=360)
    except Exception:
        pass
    app.deiconify()
    e = fake_engine()
    app.ent_target.insert(0, "云驰出行科技有限公司")
    app._preview_target()
    app._populate_table(e)
    app.tabview.set("资产列表")
    grab(app, os.path.join(OUT, "01-main.png"), topmost=True)

    # 只看疑似 + 全选，展示筛选与多选
    app._toggle_filter("疑似")
    app._toggle_select_all()
    grab(app, os.path.join(OUT, "02-list.png"), topmost=True)

    # 详情 / 人工复核
    target = next(a for a in e.assets.values() if a.confidence == "确认")
    app._show_asset_detail(target)
    app.update()
    time.sleep(0.5)
    dialogs = [w for w in app.winfo_children()
               if isinstance(w, gui.ctk.CTkToplevel)]
    if dialogs:
        dialogs[-1].geometry("820x470")
        dialogs[-1].update_idletasks()
        dialogs[-1].update()
        time.sleep(0.4)
        grab(dialogs[-1], os.path.join(OUT, "03-detail.png"), topmost=True)
    app.destroy()

    make_graph_screenshot(e)


def make_graph_screenshot(eng):
    """从真实 HTML 报告里取出图谱区块，用 Chrome 无头截一张图。"""
    import re
    import subprocess
    eng.args.output_formats = "html"
    eng.output()
    html_path = next((os.path.join(eng.args.out, f)
                      for f in os.listdir(eng.args.out) if f.endswith(".html")), "")
    if not html_path:
        print("no html report, skip graph")
        return
    with open(html_path, "r", encoding="utf-8") as fh:
        html = fh.read()
    m = re.search(r"<div id='graph'.*?</script>", html, re.S)
    if not m:
        print("no graph block, skip")
        return
    page = ("<!doctype html><meta charset='utf-8'><style>"
            "body{margin:0;background:#070d16;color:#dfe9f5;"
            "font-family:'Microsoft YaHei',sans-serif;padding:22px}"
            "h2{font-size:18px;font-weight:600;margin:0 0 4px}"
            ".muted{color:#8aa0b6;font-size:12px;margin:0 0 14px}"
            "</style><h2>🕸 资产关系图谱（可交互）</h2>"
            "<p class='muted'>节点：主机 / IP / ASN / 证书组织 / 统计 ID / 验证令牌。"
            "鼠标悬停查看节点详情。</p>" + m.group(0))
    page_path = os.path.join(eng.args.out, "graph_demo.html")
    with open(page_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    if not os.path.isfile(chrome):
        print("chrome not found, skip graph")
        return
    out = os.path.join(OUT, "04-graph.png")
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    "--force-device-scale-factor=2",
                    "--window-size=1280,700", "--virtual-time-budget=4000",
                    "--screenshot=" + out, "file:///" + page_path.replace("\\", "/")],
                   check=False)
    print("saved", out)


if __name__ == "__main__":
    main()
