#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
providers.py —— 多平台网络空间测绘聚合适配层

支持平台：
  - FOFA            (fofa.info)
  - 0.zone 零零信安  (0.zone)
  - Hunter 奇安信鹰图 (api.hunter.how)
  - DayDayMap       (www.daydaymap.com)

设计：
  1. 统一把"目标信息"翻译成各平台的**高精度查询**（cert / domain / icp / org / ip），
     尽量不用 title/body 这类宽泛关键词，从源头降低误报。
  2. 每条结果都带上 match_kind（命中类型），供上层做证据分级。
  3. 任一平台失败不影响其它平台。
  4. 只做"取数 + 归一化"，去重/评分/剔除由上层 cybercensus.py 完成。

配置（优先级：环境变量 > config.json）：
  FOFA_EMAIL / FOFA_KEY
  ZONE_KEY  (0.zone)
  HUNTER_KEY (hunter.how)
  DAYDAYMAP_KEY

自检（不联网，只打印翻译后的查询语句）：
  python providers.py --selftest
"""

import base64
import ipaddress
import json
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timedelta

# 平台 API 走正规证书，默认开启校验（请求携带 api-key，不能裸奔）。
# 企业内网 MITM 代理场景可设 ASM_INSECURE=1 跳过校验。
if os.environ.get("ASM_INSECURE"):
    _SSL = ssl.create_default_context()
    _SSL.check_hostname = False
    _SSL.verify_mode = ssl.CERT_NONE
else:
    _SSL = ssl.create_default_context()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
def _http(url, method="GET", body=None, headers=None, timeout=25, retries=1):
    h = {"User-Agent": UA, "Accept": "application/json, */*"}
    if headers:
        h.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h.setdefault("Content-Type", "application/json")
    last = None
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
                raw = r.read(8 * 1024 * 1024)
            return raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                txt = e.read().decode("utf-8", "replace")
            except Exception:
                txt = ""
            last = RuntimeError("HTTP %s %s" % (e.code, txt[:200]))
            # key 无效 / 权限不足 / 查询非法：重试无意义，立即失败
            if e.code in (400, 401, 403, 404, 405, 422):
                raise last
            # 限速 / 服务端故障：退避重试，尊重 Retry-After
            if e.code in (429, 500, 502, 503, 504) and i < retries:
                ra = e.headers.get("Retry-After") if e.headers else None
                try:
                    wait = min(float(ra), 60.0)
                except (TypeError, ValueError):
                    wait = 1.0 * (i + 1)
                time.sleep(wait)
                continue
            raise last
        except Exception as e:  # noqa
            last = e
        if i < retries:
            time.sleep(1.0 * (i + 1))
    raise last


# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
def load_config(path=None):
    env_map = {
        ("fofa", "email"): "FOFA_EMAIL",
        ("fofa", "key"): "FOFA_KEY",
        ("zerozone", "key"): "ZONE_KEY",
        ("hunter", "key"): "HUNTER_KEY",
        ("daydaymap", "key"): "DAYDAYMAP_KEY",
    }
    cfg = {
        "fofa": {"email": os.environ.get("FOFA_EMAIL", ""),
                 "key": os.environ.get("FOFA_KEY", "")},
        "zerozone": {"key": os.environ.get("ZONE_KEY", "") or os.environ.get("OZONE_KEY", "")},
        "hunter": {"key": os.environ.get("HUNTER_KEY", "")},
        "daydaymap": {"key": os.environ.get("DAYDAYMAP_KEY", "") or os.environ.get("DDM_KEY", "")},
    }
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                ext = json.load(f)
            for name in list(cfg.keys()):
                if name in ext and isinstance(ext[name], dict):
                    for k, v in ext[name].items():
                        if not v:
                            continue
                        # 环境变量优先：已由环境变量提供的不被配置文件覆盖
                        ev = env_map.get((name, k))
                        if ev and os.environ.get(ev):
                            continue
                        cfg[name][k] = str(v)
        except Exception as e:
            print("[!] 读取配置文件失败: %s" % e)
    return cfg


ALIASES = {
    "fofa": "fofa",
    "0zone": "zerozone", "zerozone": "zerozone", "0.zone": "zerozone",
    "零零信安": "zerozone", "zone": "zerozone",
    "hunter": "hunter", "鹰图": "hunter", "奇安信": "hunter",
    "daydaymap": "daydaymap", "ddm": "daydaymap",
}


def available_providers(cfg, wanted=None):
    """返回 {name: Provider 实例}，只包含已配置 key 的平台。"""
    want = None
    if wanted:
        want = set()
        for w in wanted:
            w = w.strip().lower()
            if w in ALIASES:
                want.add(ALIASES[w])
    out = {}
    # FOFA 认证需要 email + key 双参数，只配 key 时直接不启用，避免运行时每个查询都失败
    if (not want or "fofa" in want) and cfg["fofa"].get("key") and cfg["fofa"].get("email"):
        out["fofa"] = Fofa(cfg["fofa"])
    if (not want or "zerozone" in want) and cfg["zerozone"].get("key"):
        out["zerozone"] = ZeroZone(cfg["zerozone"])
    if (not want or "hunter" in want) and cfg["hunter"].get("key"):
        out["hunter"] = Hunter(cfg["hunter"])
    if (not want or "daydaymap" in want) and cfg["daydaymap"].get("key"):
        out["daydaymap"] = DayDayMap(cfg["daydaymap"])
    return out


# ----------------------------------------------------------------------------
# 统一查询对象
# ----------------------------------------------------------------------------
class Query(object):
    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind = kind      # domain / cert / icp / org / ip / cidr / keyword
        self.value = value

    def __repr__(self):
        return "%s=%s" % (self.kind, self.value)


def build_queries(domains, beians, orgs, ips, cidrs=None):
    """生成高精度查询计划。顺序：强证据优先。"""
    qs = []
    seen = set()

    def add(kind, value):
        value = (value or "").strip()
        if not value:
            return
        k = (kind, value.lower())
        if k in seen:
            return
        seen.add(k)
        qs.append(Query(kind, value))

    for d in sorted(set(x.lower() for x in domains if x)):
        add("domain", d)
        add("cert", d)
    for b in sorted(set(x for x in beians if x)):
        add("icp", b)
    for o in sorted(set(x for x in orgs if x and len(x) >= 4)):
        add("org", o)
    for ip in sorted(set(ips)):
        add("ip", ip)
    for c in sorted(set(cidrs or [])):
        add("cidr", c)
    return qs


# ----------------------------------------------------------------------------
# 归一化
# ----------------------------------------------------------------------------
def _clean_host(u):
    if not u:
        return ""
    u = str(u).strip().lower()
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split("?", 1)[0]
    if u.startswith("["):  # ipv6
        return u.split("]")[0].lstrip("[")
    if u.count(":") == 1:
        return u.split(":")[0]
    return u


def _norm_port(p):
    try:
        return int(p)
    except Exception:
        return 0


# 备案号形如 "京ICP备12345678号-3"。beian/icp 是平台语义字段可直接信任；
# icp_reg_name/number 可能是无关编号（序号、端口字符串），必须能提取出 ICP 片段才采信，
# 否则垃圾值会流进上层的 A 级证据。
_ICP_RE = re.compile(r"[一-龥]{1,15}ICP备\d{4,}号(?:-\d+)?")


def make_record(provider, match_kind, raw):
    """把各平台原始行统一成标准 dict。"""
    ip = str(raw.get("ip") or "").strip()
    host = _clean_host(raw.get("host") or raw.get("domain") or raw.get("url") or "")
    if not host and ip:
        host = ip
    port = _norm_port(raw.get("port"))
    title = str(raw.get("title") or raw.get("web_title") or "").strip()
    server = str(raw.get("server") or raw.get("header_server") or "").strip()
    beian = str(raw.get("beian") or raw.get("icp") or "").strip()
    if not _ICP_RE.search(beian):
        cand = str(raw.get("icp_reg_name") or raw.get("number") or "").strip()
        m = _ICP_RE.search(cand)
        beian = m.group(0) if m else ""
    cert = raw.get("cert") or ""
    if isinstance(cert, dict):
        cert = cert.get("subject") or cert.get("subject_cn") or json.dumps(cert, ensure_ascii=False)
    cert = str(cert or "")
    org = str(raw.get("company") or raw.get("org") or raw.get("org_name") or "").strip()
    url = str(raw.get("url") or "")
    if not host and not ip:
        return None
    return {
        "provider": provider,
        "match_kind": match_kind,
        "host": host,
        "ip": ip,
        "port": port,
        "title": title[:200],
        "server": server[:120],
        "beian": beian,
        "cert": cert[:400],
        "org": org[:120],
        "url": url,
    }


# ----------------------------------------------------------------------------
# 平台基类
# ----------------------------------------------------------------------------
class BaseProvider(object):
    name = "base"
    min_interval = 1.0
    page_size = 100
    max_pages = 1
    max_queries = 40
    supports = ()

    def __init__(self, conf):
        self.conf = conf or {}
        self.key = self.conf.get("key", "")
        self._last = 0.0

    def _throttle(self):
        dt = time.time() - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.time()

    def translate(self, q):
        """把统一 Query 翻译成本平台语法。返回 None 表示不支持。"""
        raise NotImplementedError

    def search(self, native_query, page=1, size=None):
        """执行一次查询，返回 list[dict]（原始行）。"""
        raise NotImplementedError

    def run(self, queries, pages=1, limit=0, debug=False, log=print):
        recs = []
        stats = {"provider": self.name, "queries": 0, "records": 0, "errors": 0}
        pages = max(1, min(pages, self.max_pages if self.max_pages else pages))
        for q in queries:
            if q.kind not in self.supports:
                continue
            if self.max_queries and stats["queries"] >= self.max_queries:
                log("  [%s] 已达单次查询上限 %d，停止追加查询" % (self.name, self.max_queries))
                break
            native = self.translate(q)
            if not native:
                if debug:
                    log("  [%s] 跳过 %s（不支持或非法查询）" % (self.name, q))
                continue
            if debug:
                log("  [%s] Q%d %s -> %s" % (self.name, stats["queries"] + 1, q, native))
            stats["queries"] += 1
            for page in range(1, pages + 1):
                try:
                    self._throttle()
                    rows = self.search(native, page=page, size=self.page_size)
                except Exception as e:
                    stats["errors"] += 1
                    if debug:
                        log("  [%s] 查询失败 %s: %s" % (self.name, q, e), "!")
                    else:
                        log("  [%s] 查询失败 %s: %s" % (self.name, q, str(e)[:160]), "!")
                    break
                if not rows:
                    break
                for raw in rows:
                    r = make_record(self.name, q.kind, raw)
                    if r:
                        recs.append(r)
                if limit and len(recs) >= limit:
                    break
                if len(rows) < self.page_size:
                    break
            if limit and len(recs) >= limit:
                break
        stats["records"] = len(recs)
        return recs, stats


# ----------------------------------------------------------------------------
# FOFA
# ----------------------------------------------------------------------------
class Fofa(BaseProvider):
    name = "fofa"
    min_interval = 0.6
    page_size = 100
    max_pages = 10
    supports = ("domain", "cert", "icp", "org", "ip", "cidr", "keyword")

    def translate(self, q):
        v = q.value.replace('"', '\\"')
        if q.kind == "domain":
            return 'domain="%s"' % v
        if q.kind == "cert":
            return 'cert="%s"' % v
        if q.kind == "icp":
            return 'icp="%s"' % v
        if q.kind == "org":
            return 'org="%s"' % v
        if q.kind in ("ip", "cidr"):
            return 'ip="%s"' % v
        if q.kind == "keyword":
            return 'body="%s"' % v
        return None

    def search(self, native_query, page=1, size=None):
        size = size or self.page_size
        qb = base64.urlsafe_b64encode(native_query.encode("utf-8")).decode("ascii")
        fields = "host,ip,port,title,server,domain,protocol,cert,icp"
        url = ("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s"
               "&page=%d&size=%d&fields=%s"
               % (urllib.parse.quote(self.conf.get("email", "")),
                  urllib.parse.quote(self.key),
                  urllib.parse.quote(qb), page, min(size, 1000),
                  urllib.parse.quote(fields)))
        data = json.loads(_http(url, timeout=30))
        if data.get("error"):
            raise RuntimeError("FOFA: %s" % data.get("errmsg", "error"))
        rows = data.get("results") or []
        flds = data.get("fields") or fields.split(",")
        out = []
        for row in rows:
            if isinstance(row, dict):
                out.append(row)
            elif isinstance(row, list):
                out.append(dict(zip(flds, row)))
        return out


# ----------------------------------------------------------------------------
# 0.zone 零零信安
# ----------------------------------------------------------------------------
class ZeroZone(BaseProvider):
    name = "zerozone"
    min_interval = 0.6
    page_size = 100
    max_pages = 10
    max_queries = 30
    supports = ("domain", "cert", "icp", "org", "ip", "cidr", "keyword")
    ENDPOINT = "https://0.zone/api/data/"

    def translate(self, q):
        # 0.zone 语法：= 精确、== 包含、=== 逐字符；括号用于分组
        # 值统一加双引号，否则含空格的英文组织名会产生畸形查询且静默失败
        v = q.value.replace("\\", "\\\\").replace('"', '\\"')
        if q.kind == "domain":
            return 'url=="%s"' % v
        if q.kind == "cert":
            # 证书详情（含域名/组织名）模糊匹配，命中面比 subject_cn 更全
            return 'ssl_info.detail=="%s"' % v
        if q.kind == "icp":
            return 'icp=="%s"' % v
        if q.kind == "org":
            return 'company=="%s"' % v
        if q.kind == "ip":
            return 'ip="%s"' % v
        if q.kind == "cidr":
            try:
                net = ipaddress.ip_network(q.value, strict=False)
                return 'ip="%s-%s"' % (net.network_address, net.broadcast_address)
            except Exception:
                # 解析失败：返回 None 让 run() 跳过，不发起注定非法的查询
                return None
        if q.kind == "keyword":
            return 'title=="%s"' % v
        return None

    def search(self, native_query, page=1, size=None):
        size = size or self.page_size
        body = {
            "query": native_query,
            "query_type": "site",
            "page": page,
            "pagesize": max(1, min(size, 100)),
            "zone_key_id": self.key,
        }
        txt = _http(self.ENDPOINT, method="POST", body=body, timeout=30)
        data = json.loads(txt)
        if str(data.get("code", "-1")) != "0":
            raise RuntimeError("0.zone: %s" % data.get("message", "error"))
        rows = data.get("data") or []
        for r in rows:
            if isinstance(r, dict):
                if not r.get("icp") and r.get("beian"):
                    r["icp"] = r.get("beian")
                si = r.get("ssl_info")
                if isinstance(si, dict) and not r.get("cert"):
                    r["cert"] = si.get("subject_cn") or si.get("subject_org") or ""
        return rows


# ----------------------------------------------------------------------------
# Hunter 奇安信鹰图
# ----------------------------------------------------------------------------
class Hunter(BaseProvider):
    name = "hunter"
    min_interval = 2.05     # 官方限制：1 次 / 2 秒
    page_size = 100         # API 单页上限 100；2 秒/次的限速下大页明显更快
    max_pages = 10
    supports = ("domain", "cert", "icp", "org", "ip", "cidr", "keyword")
    ENDPOINT = "https://api.hunter.how/search"

    def translate(self, q):
        v = q.value.replace('"', '\\"')
        if q.kind == "domain":
            return 'domain="%s"' % v
        if q.kind == "cert":
            return 'cert="%s"' % v
        if q.kind == "icp":
            return 'icp.number="%s"' % v
        if q.kind == "org":
            return 'company="%s"' % v
        if q.kind in ("ip", "cidr"):
            return 'ip="%s"' % v
        if q.kind == "keyword":
            return 'web.body="%s"' % v
        return None

    def search(self, native_query, page=1, size=None):
        size = size or self.page_size
        q = base64.urlsafe_b64encode(native_query.encode("utf-8")).decode("ascii")
        start = (datetime.now() - timedelta(days=3650)).strftime("%Y-%m-%d")
        end = datetime.now().strftime("%Y-%m-%d")
        fields = "ip,port,domain,web_title,url,status_code,header_server,product,cert"
        url = ("%s?api-key=%s&query=%s&page=%d&page_size=%d"
               "&start_time=%s&end_time=%s&fields=%s"
               % (self.ENDPOINT, urllib.parse.quote(self.key), urllib.parse.quote(q),
                  page, min(size, 100), start, end, urllib.parse.quote(fields)))
        txt = _http(url, timeout=35)
        data = json.loads(txt)
        code = data.get("code")
        if str(code) not in ("200", "0"):
            raise RuntimeError("Hunter: code=%s msg=%s" % (code, data.get("message") or data.get("msg")))
        d = data.get("data") or {}
        arr = d.get("arr") or d.get("list") or []
        out = []
        for r in arr:
            if isinstance(r, dict):
                if not r.get("title") and r.get("web_title"):
                    r["title"] = r["web_title"]
                if not r.get("server") and r.get("header_server"):
                    r["server"] = r["header_server"]
                if not r.get("icp") and r.get("number"):
                    r["icp"] = r["number"]
                out.append(r)
        return out


# ----------------------------------------------------------------------------
# DayDayMap
# ----------------------------------------------------------------------------
class DayDayMap(BaseProvider):
    name = "daydaymap"
    min_interval = 1.0
    page_size = 100
    max_pages = 10
    supports = ("domain", "cert", "icp", "org", "ip", "cidr", "keyword")
    ENDPOINT = "https://www.daydaymap.com/api/v1/raymap/search/all"

    def translate(self, q):
        v = q.value.replace('"', '\\"')
        if q.kind == "domain":
            return 'domain="%s"' % v
        if q.kind == "cert":
            return 'cert="%s"' % v
        if q.kind == "icp":
            return 'icp.number="%s"' % v
        if q.kind == "org":
            return 'org.name="%s"' % v
        if q.kind in ("ip", "cidr"):
            return 'ip="%s"' % v
        if q.kind == "keyword":
            return 'web.body="%s"' % v
        return None

    def search(self, native_query, page=1, size=None):
        size = size or self.page_size
        kw = base64.b64encode(native_query.encode("utf-8")).decode("ascii")
        body = {"page": page, "page_size": max(1, min(size, 1000)), "keyword": kw}
        headers = {"api-key": self.key, "Content-Type": "application/json"}
        txt = _http(self.ENDPOINT, method="POST", body=body, headers=headers, timeout=35)
        data = json.loads(txt)
        if str(data.get("code")) not in ("200", "0"):
            raise RuntimeError("DayDayMap: %s" % (data.get("msg") or data.get("message") or "error"))
        d = data.get("data") or {}
        rows = d.get("list") or d.get("arr") or []
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            if not r.get("title") and r.get("web_title"):
                r["title"] = r["web_title"]
            if not r.get("icp") and r.get("icp_reg_name"):
                r["icp"] = r["icp_reg_name"]
            out.append(r)
        return out


# ----------------------------------------------------------------------------
# 聚合入口
# ----------------------------------------------------------------------------
def run(providers, queries, pages=1, limit=0, debug=False, log=print):
    """并发跑多个平台（平台之间并行，平台内部串行以遵守频率限制）。"""
    if not providers:
        return [], {}
    import threading
    records = []
    stats = {}
    lock = threading.Lock()

    def _worker(name, p):
        try:
            recs, st = p.run(queries, pages=pages, limit=limit, debug=debug, log=log)
        except Exception as e:  # noqa
            recs, st = [], {"provider": name, "queries": 0, "records": 0, "errors": 1}
            log("  [%s] 异常: %s" % (name, str(e)[:160]), "!")
        with lock:
            records.extend(recs)
            stats[name] = st

    threads = []
    for name, p in providers.items():
        t = threading.Thread(target=_worker, args=(name, p))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return records, stats


# ----------------------------------------------------------------------------
# 自检
# ----------------------------------------------------------------------------
def _selftest():
    qs = build_queries(["example.com"], ["京ICP备12345678号"],
                       ["某某市人民政府"], ["1.2.3.4"], ["1.2.3.0/24"])
    print("统一查询计划:")
    for q in qs:
        print("  -", q)
    print("")
    dummy = {
        "fofa": {"key": "x", "email": "a@b.c"},
        "zerozone": {"key": "x"},
        "hunter": {"key": "x"},
        "daydaymap": {"key": "x"},
    }
    provs = available_providers(dummy)
    for name, p in provs.items():
        print("== %s ==" % name)
        for q in qs:
            if q.kind in p.supports:
                print("  %-8s -> %s" % (q.kind, p.translate(q)))
        print("")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print("用法: python providers.py --selftest")
