#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shadowmap.py —— ShadowMap：单位名称 / 域名 / IP 的互联网暴露面测绘工具（低误报版）

设计原则（对应《单位名称暴露面全量测绘方法》）：
  1. 名称/域名/IP 只是入口，真正的"证据锚点"是：
       ICP备案号、SSL证书 O=组织名、Whois注册人、统计代码ID、favicon哈希
  2. 默认只做【被动收集】+ 对用户提供的域名做一次锚点探测，不主动扫目标。
  3. 主动扫描（端口/批量探测/C段）必须显式 --active / --cscan。
  4. 结果按 A/B/C 证据分级自动给出 确认 / 疑似 / 存疑。

用法示例：
  python shadowmap.py -n "某某市人民政府" -d xx.gov.cn
  python shadowmap.py -d example.com
  python shadowmap.py --ip 1.2.3.4
  python shadowmap.py -d example.com --active --top 200
  python shadowmap.py -d example.com --active --cscan

依赖（可选，缺失会自动降级）：
  pip install dnspython cryptography
"""

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ----------------------------------------------------------------------------
# 可选依赖
# ----------------------------------------------------------------------------
try:
    import dns.resolver  # type: ignore
    HAVE_DNS = True
except Exception:
    HAVE_DNS = False

try:
    from cryptography import x509  # type: ignore
    from cryptography.x509.oid import NameOID  # type: ignore
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

try:
    import providers as prov_layer  # 多平台聚合适配层
    HAVE_PROVIDERS = True
except Exception:
    prov_layer = None
    HAVE_PROVIDERS = False


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
IPHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 "
             "Mobile/15E148 MicroMessenger/8.0.40")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_PORTS = [
    80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 9443,
    22, 21, 23, 25, 110, 143, 445, 3389,
    3306, 5432, 6379, 9200, 27017, 11211, 1433, 1521,
    2375, 2379, 5000, 7001, 7002, 8081, 8082, 8088, 8090, 888, 10000, 18080,
]

# 公共后缀简化表：避免把 xx.gov.cn 误判成 gov.cn
SLD = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "com.tw", "com.mo", "co.uk", "co.jp", "com.au", "com.sg",
    "com.br", "co.kr", "co.in",
}


def root_domain(host):
    host = (host or "").strip().strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in SLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# 第三方云 / CDN / 托管平台后缀：无强证据时应剔除
THIRD_PARTY_SUFFIXES = (
    "aliyuncs.com", "myqcloud.com", "cloudfront.net", "azurewebsites.net",
    "amazonaws.com", "googleusercontent.com", "github.io", "vercel.app",
    "netlify.app", "herokuapp.com", "pages.dev", "workers.dev", "r2.dev",
    "oss-cn-", "cos.ap-", "obs.cn-", "bcebos.com", "qiniudn.com", "qbox.me",
    "cloudflare.net", "akamaiedge.net", "edgekey.net", "fastly.net",
)


def is_third_party_infra(host):
    h = (host or "").lower()
    return any(s in h for s in THIRD_PARTY_SUFFIXES)


BEIAN_RE = re.compile(r"([\u4e00-\u9fa5]{1,15}ICP备\d{4,}号(?:-\d+)?)")

# 备案号主号（省简称+ICP备+主序号）：同一主体的判定依据，-N 只是网站序号。
# 比较主号而不是做子串匹配，避免不同主体的短号误命中（如 "京ICP备1234号" vs "京ICP备12345号"）。
BEIAN_MAIN_RE = re.compile(r"([\u4e00-\u9fa5]{1,15}ICP备\d{4,})号(?:-\d+)?")


def _beian_key(s):
    """提取备案号主号作为比较键；非法/垃圾值返回空串。"""
    s = unicodedata.normalize("NFKC", s or "").replace(" ", "")
    m = BEIAN_MAIN_RE.search(s.upper().replace("ＩＣＰ", "ICP"))
    return m.group(1) if m else ""


# whois 隐私保护占位组织名：不是真实注册主体，不能进证据锚点
PRIVACY_ORG_MARKERS = (
    "REDACTED FOR PRIVACY", "WhoisGuard", "Registration Private",
    "Data Protected", "Privacy Protect", "Domains By Proxy",
)


def _norm_org(s):
    """组织名归一化：NFKC（全角→半角）+ 去空白/中点/常见标点 + 小写。"""
    s = unicodedata.normalize("NFKC", s or "")
    return re.sub(r"[\s·．.，,（()）]", "", s).lower()


def _org_match(a, b, min_sub=6):
    """组织名匹配：归一后相等必中；包含仅当短边长度达标。

    短边门槛挡住 "某某市" 这类过短名的裸包含（误报源），
    同时保留 "某某市数据局" vs "某某市数据局信息中心"（真实下属机构）的命中。
    """
    na, nb = _norm_org(a), _norm_org(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    short, long_ = (na, nb) if len(na) <= len(nb) else (nb, na)
    return len(short) >= min_sub and short in long_


def _org_related(a, b):
    """宽松版组织名关联（双向包含即可）：用于 IP 归属 org 与用户主体名称的相互印证。

    两侧都是用户域知识（用户给的名称 + 待印证的归属），不设最短长度门槛；
    印证通过才允许归属 org 进证据锚点，否则它只是 ISP/云厂商名。
    """
    na, nb = _norm_org(a), _norm_org(b)
    if not na or not nb:
        return False
    return na in nb or nb in na


ANALYTICS_PATTERNS = [
    ("baidu", re.compile(r"hm\.baidu\.com/hm\.js\?([0-9a-f]{32})")),
    ("ga4", re.compile(r"gtag/js\?id=(G-[A-Z0-9]{6,})")),
    ("ga-ua", re.compile(r"ga\('create',\s*'(UA-\d{4,}-\d+)'")),
    ("cnzz", re.compile(r"cnzz\.com/(?:stat\.php\?id=|.*?[?&]id=)(\d{6,})")),
]

TECH_MARKERS = [
    ("ThinkPHP", ["thinkphp", "ThinkPHP"]),
    ("Spring", ["Whitelabel Error Page", "spring"]),
    ("WordPress", ["wp-content", "wp-includes"]),
    ("Shiro", ["rememberMe=deleteMe", "shiro"]),
    ("Nginx", []),
    ("IIS", []),
    ("Tomcat", ["Apache Tomcat", "tomcat"]),
    ("Weblogic", ["weblogic"]),
    ("Jenkins", ["Jenkins"]),
    ("Swagger", ["swagger-ui", "swagger"]),
    ("Vue", ["__VUE__", "/static/js/app."]),
    ("React", ["__NEXT_DATA__", "react"]),
]

QUIET = False
LOG_HOOK = None   # GUI 注入的日志回调 hook(msg, level)；设置后日志只走钩子不打印


def log(msg, level="*"):
    if LOG_HOOK is not None:
        # 界面模式：日志流进窗口（pythonw 下也没有控制台可打印）
        try:
            LOG_HOOK(msg, level)
        except Exception:
            pass
        return
    if QUIET:
        return
    print("[%s] %s" % (level, msg))
    try:
        sys.stdout.flush()
    except Exception:
        pass


# ----------------------------------------------------------------------------
# HTTP 基础
# ----------------------------------------------------------------------------
def http_get(url, timeout=15, retries=2, headers=None, binary=False,
             max_bytes=4 * 1024 * 1024):
    hdrs = {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    last_err = None
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                data = r.read(max_bytes)
                enc = (r.headers.get("Content-Encoding") or "").lower()
                if enc == "gzip":
                    try:
                        data = gzip.decompress(data)
                    except Exception:
                        pass
                elif enc == "deflate":
                    try:
                        data = zlib.decompress(data)
                    except Exception:
                        pass
                if binary:
                    return data
                return data.decode("utf-8", "replace")
        except Exception as e:  # noqa
            last_err = e
            if i < retries:
                time.sleep(0.8 * (i + 1))
    raise last_err


def http_probe(host, port, scheme, timeout=8):
    """返回 dict：status/title/server/powered/beian/analytics/favicon/tech/body_len"""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = "%s://%s/" % (scheme, host)
    else:
        url = "%s://%s:%d/" % (scheme, host, port)

    out = {"url": url, "status": "", "title": "", "server": "",
           "powered": "", "beian": "", "analytics": "", "favicon": "",
           "tech": "", "body_len": 0}
    body = ""
    status = ""
    hdrs = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
                status = r.status
                hdrs = dict(r.headers)
                body = r.read(500000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = dict(e.headers or {})
            try:
                body = e.read(500000).decode("utf-8", "replace")
            except Exception:
                body = ""
    except Exception as e:  # noqa
        out["error"] = str(e)[:120]
        return out

    out["status"] = status
    out["body_len"] = len(body)
    out["server"] = hdrs.get("Server", "")
    out["powered"] = hdrs.get("X-Powered-By", "")

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    if m:
        out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    mb = BEIAN_RE.search(body)
    if mb:
        out["beian"] = mb.group(1)

    for name, pat in ANALYTICS_PATTERNS:
        ma = pat.search(body)
        if ma:
            out["analytics"] = "%s:%s" % (name, ma.group(1))
            break

    techs = []
    hay = (body[:60000] + " " + out["server"] + " " + out["powered"])
    for tname, marks in TECH_MARKERS:
        if not marks:
            continue
        for mk in marks:
            if mk and mk.lower() in hay.lower():
                techs.append(tname)
                break
    out["tech"] = ",".join(sorted(set(techs)))

    # favicon 哈希（Shodan 风格，mmh3 of base64）
    try:
        fav = _fetch_favicon(host, port, scheme, timeout)
        if fav:
            out["favicon"] = str(murmur3_favicon(fav))
    except Exception:
        pass

    return out


def _fetch_favicon(host, port, scheme, timeout=6):
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = "%s://%s/favicon.ico" % (scheme, host)
    else:
        url = "%s://%s:%d/favicon.ico" % (scheme, host, port)
    try:
        data = http_get(url, timeout=timeout, retries=0, binary=True, max_bytes=200000)
        if data and len(data) >= 4:
            return data
    except Exception:
        return None
    return None


# ----------------------------------------------------------------------------
# MurmurHash3 x86_32（纯 Python，用于 favicon 哈希）
# ----------------------------------------------------------------------------
def murmur3_32(data, seed=0):
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    if h1 & 0x80000000:
        h1 -= 0x100000000
    return h1


def murmur3_favicon(data):
    b64 = base64.encodebytes(data)  # 每 76 字符换行 + 结尾换行，Shodan 风格
    return murmur3_32(b64)


# ----------------------------------------------------------------------------
# 证书信息
# ----------------------------------------------------------------------------
def tls_cert_info(host, port=443, timeout=8):
    if not HAVE_CRYPTO:
        return {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        if not der:
            return {}
        cert = x509.load_der_x509_certificate(der)

        def attr(name, oid):
            for n in name:
                if n.oid == oid:
                    return n.value
            return ""

        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [v for v in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass
        not_after = ""
        try:
            not_after = str(getattr(cert, "not_valid_after_utc", cert.not_valid_after))[:19]
        except Exception:
            pass
        return {
            "org": attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "cn": attr(cert.subject, NameOID.COMMON_NAME),
            "issuer": attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "sans": sans,
            "not_after": not_after,
        }
    except Exception:
        return {}


# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------
def resolve_a(host):
    ips = set()
    try:
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except Exception:
        pass
    return ips


def dns_records(domain):
    out = {"MX": [], "NS": [], "TXT": [], "A": [], "CNAME": []}
    if HAVE_DNS:
        for rt in ("MX", "NS", "TXT", "A", "CNAME"):
            try:
                ans = dns.resolver.resolve(domain, rt, lifetime=8)
                for r in ans:
                    if rt == "MX":
                        out["MX"].append(str(getattr(r, "exchange", r)).rstrip("."))
                    elif rt == "TXT":
                        try:
                            out["TXT"].append(b"".join(r.strings).decode("utf-8", "replace"))
                        except Exception:
                            out["TXT"].append(str(r))
                    elif rt == "CNAME":
                        out["CNAME"].append(str(getattr(r, "target", r)).rstrip("."))
                    else:
                        out[rt].append(str(r).rstrip("."))
            except Exception:
                pass
    else:
        out["A"] = sorted(resolve_a(domain))
        # nslookup 兜底（Windows/Linux 通用）
        for rt in ("MX", "NS", "TXT"):
            try:
                import subprocess
                p = subprocess.run(["nslookup", "-type=" + rt, domain],
                                   capture_output=True, timeout=10)
                txt = (p.stdout or b"").decode("utf-8", "replace")
                if rt == "MX":
                    for m in re.findall(r"mail exchanger\s*=\s*(\S+)", txt, re.I):
                        out["MX"].append(m.rstrip("."))
                elif rt == "NS":
                    for m in re.findall(r"(?:nameserver|nameservers?)\s*=\s*(\S+)", txt, re.I):
                        out["NS"].append(m.rstrip("."))
                else:
                    for m in re.findall(r'text\s*=\s*"([^"]+)"', txt, re.I):
                        out["TXT"].append(m)
            except Exception:
                pass
    return out


# ----------------------------------------------------------------------------
# Whois（port 43）
# ----------------------------------------------------------------------------
def whois_query(domain, timeout=10):
    def _q(server, query):
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                c = s.recv(4096)
                if not c:
                    break
                chunks.append(c)
        return b"".join(chunks).decode("utf-8", "replace")

    try:
        txt = _q("whois.iana.org", domain)
        m = re.search(r"(?im)^refer:\s*(\S+)", txt)
        if m:
            try:
                txt = _q(m.group(1).strip(), domain)
            except Exception:
                pass
        return txt
    except Exception:
        return ""


def parse_whois(txt):
    out = {"registrar": "", "org": "", "email": "", "created": ""}
    if not txt:
        return out
    def _g(keys):
        for k in keys:
            m = re.search(r"(?im)^\s*%s\s*:\s*(.+)$" % re.escape(k), txt)
            if m:
                return m.group(1).strip()
        return ""
    out["registrar"] = _g(["Registrar", "Sponsoring Registrar", "registrar"])
    out["org"] = _g(["Registrant Organization", "Registrant Organisation",
                     "Registrant", "Organization", "org", "Registrant Name"])
    out["email"] = _g(["Registrant Email", "Email", "e-mail"])
    out["created"] = _g(["Creation Date", "Registration Time", "created",
                         "Registration Date", "Domain Registration Date"])
    return out


# ----------------------------------------------------------------------------
# 第三方数据源
# ----------------------------------------------------------------------------
def crt_subdomains(domain, timeout=25):
    names = set()
    try:
        url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
        txt = http_get(url, timeout=timeout, retries=2)
        data = json.loads(txt)
        for e in data:
            for n in str(e.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith("." + domain.lower()) or n == domain.lower():
                    names.add(n)
    except Exception as e:
        log("crt.sh(%s) 失败: %s" % (domain, str(e)[:80]), "!")
    return names


def crt_by_org(org, timeout=25):
    names = set()
    try:
        url = "https://crt.sh/?O=" + urllib.parse.quote(org) + "&output=json"
        txt = http_get(url, timeout=timeout, retries=1)
        data = json.loads(txt)
        for e in data:
            for n in str(e.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and "." in n:
                    names.add(n)
    except Exception as e:
        log("crt.sh(O=%s) 失败或为空: %s" % (org, str(e)[:80]), "!")
    return names


# ----------------------------------------------------------------------------
# 名称 -> 官网域名自举（无平台 Key 的第一跳）
#
# 只给单位名称时（无域名无IP无Key），旧的唯一本地源是 crt.sh 精确 O= 反查——
# 用户给"莞城人民医院"、证书里是"东莞市莞城医院"，第一跳即断。
# 这里用搜索引擎（cn.bing.com，无需 Key）找候选域名，再逐个探测首页，
# 用 标题/证书O= 与主体名互证过滤，验证通过的域名进入正式锚点流，
# 后续 crt.sh 子域枚举 / DNS / whois / IP 反查整条本地被动链即被激活。
# ----------------------------------------------------------------------------
SEARCH_JUNK_ROOTS = frozenset((
    # 搜索引擎 / 门户 / 百科 / 问答 / 文库 / 社区
    "baidu.com", "bing.com", "microsoft.com", "qq.com", "weibo.com", "zhihu.com",
    "toutiao.com", "sohu.com", "163.com", "sina.com.cn", "sogou.com", "so.com",
    "360.cn", "douyin.com", "xiaohongshu.com", "csdn.net", "jianshu.com",
    "bing.net", "clarity.ms", "cnblogs.com", "gushici.net", "zdic.net",
    "hanyuguoxue.com", "zhuanlan.zhihu.com", "wenku.baidu.com", "baike.baidu.com",
    "youdao.com", "sogou.cn", "sm.cn", "chinaso.com", "cnctravel.com",
    # 医疗目录 / 挂号聚合 / 问答（医院类目标的高发干扰源）
    "qiuyi.cn", "bohe.cn", "kq36.com", "haodf.com", "guahao.com", "39.net",
    "xywy.com", "a-hospital.com", "fh21.com", "youlai.cn", "120ask.com",
    "dxy.com", "cnkang.com", "myzx.cn", "mip.cn", "jjkk.cn", "ypk39.net",
    "51daifu.com", "vodjk.com", "qqyy.com", "fx120.net", "qyiypf.com",
    # 招聘 / 企查 / SEO 信息站
    "zhipin.com", "51job.com", "liepin.com", "zhaopin.com", "qcc.com",
    "tianyancha.com", "qixin.com", "aiqicha.baidu.com", "cnzzla.com",
    "chinaz.com", "aizhan.com", "17ce.com", "boce.com", "ping.pe",
    "whois.com", "whois.net", "alexa.com", "similarweb.com", "wjtcs.cn",
    # 视频/电商/工具站
    "bilibili.com", "iqiyi.com", "taobao.com", "jd.com", "pinduoduo.com",
    "alipay.com", "amap.com", "bdimg.com", "bdstatic.com", "bdcdn.network",
))

_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?<![\w.\-/])((?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+"
    r"(?:com|net|org|cn|gov|edu|info|xyz|top|vip|cc|hk|mo|tw)(?:\.cn)?)"
    r"(?![\w.\-])")


def _strip_tags(html):
    return re.sub(r"<[^>]+>", " ", html or "")


def search_engine_lookup(name, timeout=15):
    """cn.bing.com 搜索（无 Key），返回 (去标签全文, 有机结果 host 列表)。

    失败/被拦截返回 ("", [])。单次、不重试翻页，控制对搜索引擎的触碰。
    """
    try:
        url = ("https://cn.bing.com/search?q=" + urllib.parse.quote(name)
               + "&count=20&mkt=zh-CN")
        html = http_get(url, timeout=timeout, retries=1,
                        headers={"Accept": "text/html, */*"})
        hosts = [h.lower() for h in
                 re.findall(r'<h2><a[^>]+href="https?://([^/\"]+)', html)]
        return _strip_tags(html), hosts
    except Exception as e:
        log("搜索引擎查询失败(%s): %s" % (name, str(e)[:80]), "!")
        return "", []


def discover_domains_from_search(name, max_candidates=5):
    """从搜索引擎结果提取候选官网域名，返回 [(host, score), ...] 按分排序。

    - 有机链接 host 记 3 分（结果标题直接链接的目标）
    - 正文/摘要中出现的域名记 1 分/次（目录站摘要常含官网链接）
    - 搜索引擎自身与聚合目录站（SEARCH_JUNK_ROOTS）直接排除
    - gov.cn 门户等误留候选交给上层探测验证过滤
    """
    text, hosts = search_engine_lookup(name)
    if not text and not hosts:
        return []
    scores = {}

    def _add(host, w):
        host = (host or "").strip().lower().strip(".")
        if not host or "_" in host:
            return
        root = root_domain(host)
        if not root or root in SEARCH_JUNK_ROOTS or host in SEARCH_JUNK_ROOTS:
            return
        # 排除纯数字/版本号样式的伪域名（如 3.1.4.com 类噪音由 TLD 白名单兜住）
        scores[host] = scores.get(host, 0) + w

    for h in hosts:
        _add(h, 3)
    for m in _DOMAIN_IN_TEXT_RE.finditer(text):
        _add(m.group(1), 1)
    out = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return out[:max_candidates]


def hackertarget_hostsearch(domain, timeout=20):
    res = {}
    try:
        url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
        txt = http_get(url, timeout=timeout, retries=1)
        low = txt.lower()
        if "api count" in low or "error" in low or "quota" in low:
            return res
        for line in txt.splitlines():
            if "," in line:
                h, ip = line.split(",", 1)
                h = h.strip().lower()
                if h.endswith("." + domain.lower()) or h == domain.lower():
                    res[h] = ip.strip()
    except Exception as e:
        log("hackertarget(%s) 失败: %s" % (domain, str(e)[:60]), "!")
    return res


def rapiddns_subdomains(domain, timeout=20):
    names = set()
    try:
        url = "https://rapiddns.io/subdomain/%s?full=1" % urllib.parse.quote(domain)
        html = http_get(url, timeout=timeout, retries=1)
        for m in re.findall(r"<td>([A-Za-z0-9_.\-]+\." + re.escape(domain) + r")</td>", html):
            names.add(m.strip().lower())
    except Exception:
        pass
    return names


def reverse_ip(ip, timeout=20):
    names = set()
    # hackertarget
    try:
        url = "https://api.hackertarget.com/reverseiplookup/?q=" + urllib.parse.quote(ip)
        txt = http_get(url, timeout=timeout, retries=1)
        low = txt.lower()
        if "error" not in low and "api count" not in low:
            for line in txt.splitlines():
                line = line.strip().lower()
                if line and "." in line and " " not in line:
                    names.add(line)
    except Exception:
        pass
    # rapiddns sameip
    try:
        url = "https://rapiddns.io/sameip/%s?full=1" % urllib.parse.quote(ip)
        html = http_get(url, timeout=timeout, retries=1)
        for m in re.findall(r"<td>([A-Za-z0-9_.\-]+\.[A-Za-z]{2,})</td>", html):
            if m.strip() and not m.strip().replace(".", "").isdigit():
                names.add(m.strip().lower())
    except Exception:
        pass
    return names


def ip_info(ip, timeout=12):
    out = {}
    try:
        url = ("http://ip-api.com/json/%s?fields=status,message,country,regionName,"
               "city,isp,org,as,asname,query" % urllib.parse.quote(ip))
        data = json.loads(http_get(url, timeout=timeout, retries=1))
        if data.get("status") == "success":
            out = data
    except Exception:
        pass
    return out


def bgp_prefixes(ip, timeout=15):
    out = []
    try:
        url = "https://api.bgpview.io/ip/" + urllib.parse.quote(ip)
        data = json.loads(http_get(url, timeout=timeout, retries=1))
        for p in (data.get("data", {}) or {}).get("prefixes", []) or []:
            if p.get("prefix"):
                out.append(p["prefix"])
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------
# 资产对象
# ----------------------------------------------------------------------------
class Asset(object):
    __slots__ = ("host", "ip", "port", "scheme", "status", "title", "server",
                 "powered", "tech", "cert_org", "cert_san", "beian",
                 "analytics", "favicon", "source", "evidence", "confidence",
                 "error", "prov_kinds", "providers", "prov_beian", "prov_cert",
                 "prov_org", "reject_reason", "urls")

    def __init__(self, host, port=None, scheme=None):
        self.host = host
        self.ip = ""
        self.port = port
        self.scheme = scheme
        self.status = ""
        self.title = ""
        self.server = ""
        self.powered = ""
        self.tech = ""
        self.cert_org = ""
        self.cert_san = ""
        self.beian = ""
        self.analytics = ""
        self.favicon = ""
        self.source = set()
        self.evidence = []
        self.confidence = "存疑"
        self.error = ""
        self.prov_kinds = set()   # 平台命中类型：domain/cert/icp/org/ip/cidr
        self.providers = set()    # 命中该资产的平台
        self.prov_beian = ""      # 平台返回的备案号
        self.prov_cert = ""       # 平台返回的证书信息
        self.prov_org = ""        # 平台返回的组织名
        self.reject_reason = ""   # 剔除原因
        self.urls = set()

    def key(self):
        p = self.port or (443 if self.scheme == "https" else 80 if self.scheme == "http" else "")
        return (self.host, str(p))

    def to_dict(self):
        d = {}
        for s in self.__slots__:
            v = getattr(self, s)
            if isinstance(v, set):
                v = sorted(v)
            d[s] = v
        return d


def _merge_assets(dst, src):
    """字段级合并：集合字段取并集，标量字段空才填（src 的证据不覆盖 dst 已有值）。"""
    for s in ("source", "providers", "prov_kinds", "urls"):
        getattr(dst, s).update(getattr(src, s))
    for s in ("ip", "title", "server", "scheme", "status", "beian", "prov_beian",
              "prov_cert", "prov_org", "cert_org", "cert_san", "analytics", "favicon"):
        if not getattr(dst, s):
            setattr(dst, s, getattr(src, s))


# ----------------------------------------------------------------------------
# 扫描器
# ----------------------------------------------------------------------------
def tcp_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(host, ports, threads=50, timeout=2.5):
    opened = []
    with ThreadPoolExecutor(max_workers=min(threads, max(1, len(ports)))) as ex:
        futs = {ex.submit(tcp_open, host, p, timeout): p for p in ports}
        for f in as_completed(futs):
            p = futs[f]
            try:
                if f.result():
                    opened.append(p)
            except Exception:
                pass
    return sorted(opened)


# HTTP 探测端口表：与 DEFAULT_PORTS 的 web 端口保持一致，
# 否则扫描发现开放（如 5000/7001/7002/888）却永远不做 HTTP 探测，拿不到页面证据
WEB_PORTS = frozenset((
    80, 81, 443, 444, 888, 5000, 7001, 7002, 8000, 8008,
    8080, 8081, 8082, 8088, 8090, 8143, 8181, 8443, 8888,
    9000, 9090, 9443, 10000, 18080,
))


def is_web_port(p):
    return p in WEB_PORTS


# ----------------------------------------------------------------------------
# 主引擎
# ----------------------------------------------------------------------------
class Engine(object):
    def __init__(self, args):
        self.args = args
        self.names = []
        self.domains = set()
        self.input_ips = set()
        self.spf_ips = set()      # SPF ip4:（第三方发信 IP，仅记录，不扫描不查询）
        self.assets = {}          # (host, port) -> Asset
        self.sub_map = {}         # host -> ip (被动得到)
        self.anchor = {"orgs": set(), "beian": set(), "analytics": set(),
                       "favicon": set(), "ips": set(), "domains": set(),
                       "weak_domains": set()}
        self.ip_notes = {}        # ip -> info dict
        self.provider_records = []
        self.provider_stats = {}
        self.rejected = []        # 被剔除的资产（含原因）

    # ---- 资产登记 ----
    def add_asset(self, host, port=None, scheme=None, source="", ip=None):
        a = Asset(host, port, scheme)
        k = a.key()
        if k in self.assets:
            a = self.assets[k]
        else:
            self.assets[k] = a
        if ip:
            a.ip = ip
        if source:
            a.source.add(source)
        return a

    # ---- 0.5 名称自举：搜索引擎找官网域名（无平台 Key 的第一跳） ----
    def discover_names_to_domains(self):
        """名称 → 官网域名：搜索候选 → 首页探测 → 标题/证书O= 与主体名互证。

        验证通过的域名加入 self.domains（后续 build_anchors/crt.sh/DNS/whois
        整条链对其生效）；验证不过的只记日志，不污染锚点。
        纯被动模式（--no-probe）不能探测候选首页，但查搜索引擎属于第三方
        数据源不触碰目标——候选域名以**未验证弱锚点**加入，结果只进"疑似"。
        """
        if not self.names:
            return
        if self.domains or self.input_ips:
            return  # 已有域名/IP 输入，不需要自举
        if getattr(self.args, "no_probe", False):
            for name in self.names:
                cands = discover_domains_from_search(name, max_candidates=3)
                added = []
                for dom, score in cands:
                    root = root_domain(dom)
                    if not root or root in SEARCH_JUNK_ROOTS:
                        continue
                    if root not in self.domains:
                        self.domains.add(root)
                        self.anchor["weak_domains"].add(root)
                        added.append(root)
                if added:
                    log("纯被动模式：搜索引擎候选域名（未验证，结果只进疑似）: %s"
                        % ", ".join(added), "+")
                else:
                    log("搜索引擎未找到 %s 的候选域名。" % name, "!")
            return
        for name in self.names:
            cands = discover_domains_from_search(name)
            if not cands:
                log("搜索引擎未找到 %s 的候选域名；建议手动补充域名输入。" % name, "!")
                continue
            log("搜索引擎候选域名: %s" % ", ".join("%s(%d分)" % c for c in cands))
            verified = []
            for dom, score in cands:
                if self._verify_candidate_domain(name, dom):
                    verified.append(dom)
            if verified:
                log("官网自举验证通过: %s" % ", ".join(verified), "+")
            else:
                log("候选域名均未通过验证（标题/证书与主体名不符），未加入锚点。", "!")

    def _verify_candidate_domain(self, name, dom):
        """探测候选域名首页，标题或证书 O= 与主体名互证即通过。"""
        for scheme, port in (("https", 443), ("http", 80)):
            info = http_probe(dom, port, scheme, timeout=self.args.timeout)
            if info.get("status") in ("", None):
                continue
            title = info.get("title", "") or ""
            if _org_match(name, title):
                self._add_verified_domain(dom)
                return True
            if scheme == "https":
                cert = tls_cert_info(dom, port, timeout=self.args.timeout)
                org = (cert or {}).get("org", "")
                if org and _org_match(name, org):
                    self._add_verified_domain(dom)
                    return True
        return False

    def _add_verified_domain(self, dom):
        """验证通过的域名：主机名与根域名都入锚点。

        根域名必须加——子域枚举（crt.sh/hackertarget）按根域查才能拿到
        全部子域；只枚举 www.xxx.cn 这一个主机名会漏掉其它子站。
        """
        self.domains.add(dom)
        root = root_domain(dom)
        if root and root != dom:
            self.domains.add(root)

    # ---- 1. 锚点建立 ----
    def build_anchors(self, probe=True):
        log("== 阶段1: 建立证据锚点 ==", "#")
        for name in self.names:
            self.anchor["orgs"].add(name)
            log("主体名称: %s" % name)

        for d in list(self.domains):
            self.anchor["domains"].add(d)
            log("探测锚点域名: %s" % d)
            ipset = resolve_a(d)
            for ip in ipset:
                self.anchor["ips"].add(ip)
                self.sub_map.setdefault(d, ip)
            if not probe:
                continue
            a = self.add_asset(d, None, "https", source="anchor")
            if not ipset:
                a.error = "DNS 解析失败"
                continue
            a.ip = sorted(ipset)[0]
            chosen = None
            for scheme, port in (("https", 443), ("http", 80)):
                info = http_probe(d, port, scheme, timeout=self.args.timeout)
                if info.get("status") not in ("", None):
                    chosen = (scheme, port, info)
                    break
            if chosen:
                scheme, port, info = chosen
                a.scheme, a.port = scheme, port
                a.status = str(info.get("status", ""))
                a.title = info.get("title", "")
                a.server = info.get("server", "")
                a.powered = info.get("powered", "")
                a.tech = info.get("tech", "")
                a.beian = info.get("beian", "")
                a.analytics = info.get("analytics", "")
                a.favicon = info.get("favicon", "")
                if a.beian:
                    self.anchor["beian"].add(a.beian)
                    log("  锚点备案号: %s" % a.beian, "+")
                if a.analytics:
                    self.anchor["analytics"].add(a.analytics)
                    log("  锚点统计ID: %s" % a.analytics, "+")
                if a.favicon:
                    self.anchor["favicon"].add(a.favicon)
                    log("  锚点favicon: %s" % a.favicon, "+")
                if scheme == "https":
                    cert = tls_cert_info(d, port, timeout=self.args.timeout)
                    if cert:
                        a.cert_org = cert.get("org", "")
                        a.cert_san = ",".join(cert.get("sans", [])[:20])
                        if a.cert_org:
                            self.anchor["orgs"].add(a.cert_org)
                            log("  锚点证书O=: %s" % a.cert_org, "+")
                    log("  证书: %s" % (cert.get("issuer", "") or "-"))

    # ---- 2. 被动收集 ----
    def collect_passive(self):
        log("== 阶段2: 被动收集（第三方数据源）==", "#")
        domains = list(self.domains)

        # 名称 -> 证书组织名反查
        for name in self.names:
            log("crt.sh 按组织名搜索: %s" % name)
            found = crt_by_org(name)
            if found:
                log("  证书组织名命中 %d 个域名" % len(found), "+")
                for h in found:
                    dom = self._guess_root(h)
                    if dom and dom not in self.domains:
                        self.domains.add(dom)
                        # 由组织名反推出来的根域名属于弱锚点：
                        # 同名/同集团不同主体时有误报风险，评分时按 B 级处理
                        self.anchor["weak_domains"].add(dom)
                        if dom not in domains:
                            domains.append(dom)
                for h in found:
                    self.sub_map[h] = self.sub_map.get(h, "")
                    s = self.add_asset(h, None, None, source="crt:org")
                    s.ip = self.sub_map.get(h, "")

        # 域名 -> 子域名
        for d in list(dict.fromkeys(domains)):
            log("crt.sh 子域名: %s" % d)
            subs = crt_subdomains(d)
            log("  crt.sh 得到 %d 个" % len(subs))
            ht = hackertarget_hostsearch(d)
            if ht:
                log("  hackertarget 得到 %d 个" % len(ht))
            rd = rapiddns_subdomains(d)
            if rd:
                log("  rapiddns 得到 %d 个" % len(rd))
            allsubs = set(subs) | set(ht.keys()) | set(rd)
            allsubs.add(d)
            for h in allsubs:
                ip = ht.get(h, "")
                if ip:
                    self.sub_map[h] = ip
                a = self.add_asset(h, None, None, source="passive")
                if ip:
                    a.ip = ip
                self.anchor["domains"].add(d)

            # DNS 记录（MX/NS/TXT 只做线索记录，不作为资产，避免把第三方邮件/DNS 服务商算进来）
            rec = dns_records(d)
            for mx in rec.get("MX", []):
                mx = mx.strip().rstrip(".")
                if mx:
                    log("  MX: %s" % mx)
            for ns in rec.get("NS", []):
                ns = ns.strip().rstrip(".")
                if ns:
                    log("  NS: %s" % ns)
            for txt in rec.get("TXT", []):
                for m in re.findall(r"([A-Za-z0-9_.\-]+\.[A-Za-z]{2,})", txt):
                    if any(k in m.lower() for k in ("spf", "include", "ip4", "ip6")):
                        continue
                    self.sub_map.setdefault(m.lower(), "")
                for ipm in re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+)", txt):
                    # SPF 授权的通常是 sendgrid/google 等第三方发信商 IP，
                    # 既不该被主动扫描也不该拿去平台查询，仅记录供人工研判
                    if ipm not in self.spf_ips:
                        self.spf_ips.add(ipm)
                        log("  SPF ip4（仅记录，不作为扫描/查询目标）: %s" % ipm)
                if "include:" in txt.lower():
                    log("  SPF include: %s" % txt[:120])

        # IP 反查
        all_ips = set(self.input_ips)
        for ip in list(all_ips):
            log("IP 归属/反查: %s" % ip)
            info = ip_info(ip)
            if info:
                self.ip_notes[ip] = info
                org = info.get("org") or info.get("isp") or ""
                asn = info.get("as") or ""
                # ip-api 返回的是 ISP/AS 归属组织（如 "Hangzhou Alibaba Advertising..."），
                # 只有与用户提供的主体名称相互印证时才是目标组织名（自有 AS/地址段），
                # 否则进锚点会让同一家云厂商托管的无关站点命中 A 级证书证据
                if org and any(_org_related(org, n) for n in self.names):
                    self.anchor["orgs"].add(org)
                    log("  IP归属与主体名称吻合，加入锚点: %s | %s" % (org, asn), "+")
                else:
                    log("  归属（仅记录，不进锚点）: %s | %s" % (org, asn))
            rev = reverse_ip(ip)
            if rev:
                log("  反查域名 %d 个" % len(rev), "+")
            for h in rev:
                a = self.add_asset(h, None, None, source="reverse-ip:%s" % ip)
                a.ip = ip
            prefs = bgp_prefixes(ip)
            for pf in prefs:
                self.ip_notes.setdefault(ip, {})
                self.ip_notes[ip].setdefault("prefixes", [])
                if pf not in self.ip_notes[ip]["prefixes"]:
                    self.ip_notes[ip]["prefixes"].append(pf)

        # Whois
        for d in list(self.domains):
            w = parse_whois(whois_query(d))
            org = w.get("org") or ""
            if org:
                if any(m in org for m in PRIVACY_ORG_MARKERS):
                    log("whois(%s) 注册人为隐私保护占位（%s），不进锚点" % (d, org))
                else:
                    self.anchor["orgs"].add(org)
                    log("whois(%s) 注册人: %s" % (d, org))

    @staticmethod
    def _guess_root(host):
        return root_domain(host)

    # ---- 3. 主动扫描 ----
    def scan_active(self):
        log("== 阶段3: 主动探测/扫描（已授权）==", "#")
        hosts = {}
        for k, a in list(self.assets.items()):
            if a.host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", a.host):
                hosts[a.host] = a.ip or ""

        # 解析
        def _resolve(h):
            ips = resolve_a(h)
            return h, sorted(ips)

        unresolved = [h for h, ip in hosts.items() if not ip]
        if unresolved:
            log("解析 %d 个待解析主机..." % len(unresolved))
            with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                futs = {ex.submit(_resolve, h): h for h in unresolved}
                for f in as_completed(futs):
                    try:
                        h, ips = f.result()
                    except Exception:
                        continue
                    if ips:
                        self.sub_map[h] = ips[0]
                        for k, a in self.assets.items():
                            if a.host == h:
                                a.ip = ips[0]

        ips = set(self.input_ips)
        ips |= self.anchor["ips"]
        for h, ip in self.sub_map.items():
            if ip:
                ips.add(ip)

        # C 段扩展：只对用户输入 IP 与锚点域名 IP 所在 /24 展开（与平台 cidr 查询口径一致），
        # 不再对每个被动子域 IP 各自展开（大子域集下会爆炸；同段去重后本就覆盖）
        if self.args.cscan:
            expanded, nets = set(), set()
            for ip in set(self.input_ips) | set(self.anchor["ips"]):
                try:
                    net = ipaddress.ip_network(ip + "/24", strict=False)
                except Exception:
                    continue
                if net in nets:
                    continue
                nets.add(net)
                expanded.update(str(h) for h in net.hosts())
            if len(expanded) > 5120 and not self.args.yes:
                log("警告：C 段扩展达 %d 个 IP，请确认范围（--yes 可跳过本提示）"
                    % len(expanded), "!")
            log("C 段扩展: %d 个 /24，+%d 个 IP" % (len(nets), len(expanded)))
            ips |= expanded

        ports = self.args.ports_list
        if self.args.full_ports:
            if not self.args.yes:
                log("警告：全端口扫描 1-65535 非常慢，建议改用 --top 200", "!")
            ports = list(range(1, 65536))
        log("开始扫描 %d 个 IP，端口数 %d" % (len(ips), len(ports)))

        # 扁平化并发：单 executor 摊 (ip, port) 对，总 socket 封顶 threads*2。
        # 旧实现是 IP 间 threads//2 × 单 IP 内 threads*2 ≈ threads² 个并发 socket，
        # 默认 threads=20 时约 400 个，无全局限速。
        scan_timeout = getattr(self.args, "scan_timeout", 2.5) or 2.5
        pairs = [(ip, p) for ip in sorted(ips) for p in ports]
        opened_map = {}
        cap = max(8, self.args.threads * 2)
        with ThreadPoolExecutor(max_workers=min(len(pairs) or 1, cap)) as ex:
            futs = {ex.submit(tcp_open, ip, p, scan_timeout): (ip, p)
                    for ip, p in pairs}
            for f in as_completed(futs):
                ip, p = futs[f]
                try:
                    if f.result():
                        opened_map.setdefault(ip, []).append(p)
                except Exception:
                    pass
        for ip, opened in opened_map.items():
            log("  %s 开放端口: %s" % (ip, ",".join(str(p) for p in sorted(opened))))
            for p in sorted(opened):
                a = self.add_asset(ip, p, "https" if p in (443, 8443, 9443) else "http",
                                   source="scan", ip=ip)

        # Web 探测
        self.probe_all_web()

    def probe_all_web(self, include_unported=False, limit=0, only=None):
        log("对 Web 资产做指纹/锚点探测...")
        targets = []
        for k, a in self.assets.items():
            if only is not None and k not in only:
                continue
            if not a.host:
                continue
            if a.port:
                if is_web_port(int(a.port)):
                    targets.append(a)
            elif include_unported:
                targets.append(a)
        if limit and len(targets) > limit:
            log("待探测资产过多（%d），仅探测前 %d 个（可用 --active 全量）" % (len(targets), limit), "!")
            targets = targets[:limit]
        log("待探测 Web 资产: %d" % len(targets))

        def _probe(a):
            if a.port:
                p = int(a.port)
                prefer = a.scheme or ("https" if p in (443, 8443, 9443) else "http")
                # 首选 scheme 失败时回退试另一种：8080 等端口上的纯 https 服务
                # 旧实现只试一种 scheme，永远探测失败
                other = "https" if prefer == "http" else "http"
                tries = [(prefer, p), (other, p)]
            else:
                tries = [("https", 443), ("http", 80)]
            best = None
            cert = {}
            for scheme, port in tries:
                info = http_probe(a.host, port, scheme, timeout=self.args.timeout)
                if info.get("status") not in ("", None):
                    best = (scheme, port, info)
                    if scheme == "https":
                        cert = tls_cert_info(a.host, port, timeout=self.args.timeout)
                    break
            return a, best, cert

        with ThreadPoolExecutor(max_workers=max(1, self.args.threads)) as ex:
            futs = [ex.submit(_probe, a) for a in targets]
            for f in as_completed(futs):
                try:
                    a, best, cert = f.result()
                except Exception:
                    continue
                if not best:
                    continue
                scheme, port, info = best
                a.scheme, a.port = scheme, port
                a.status = str(info.get("status", ""))
                a.title = info.get("title", "")
                a.server = info.get("server", "")
                a.powered = info.get("powered", "")
                a.tech = info.get("tech", "")
                a.beian = info.get("beian", "") or a.beian
                a.analytics = info.get("analytics", "") or a.analytics
                a.favicon = info.get("favicon", "") or a.favicon
                if cert:
                    a.cert_org = cert.get("org", "")
                    a.cert_san = ",".join(cert.get("sans", [])[:20])
                # 注意：探测到的备案号/统计ID/favicon 只作为该资产自身证据，
                # 不再回填到全局锚点，避免"任取一个第三方站点当锚点"的自我印证误报。

    # ---- 2.5 多平台聚合 ----
    def collect_providers(self):
        if not HAVE_PROVIDERS:
            log("未找到 providers.py，跳过平台聚合", "!")
            return
        cfg = prov_layer.load_config(getattr(self.args, "config", None))
        provs = prov_layer.available_providers(cfg, getattr(self.args, "providers", None))
        if not provs:
            log("未配置任何平台 API Key，跳过平台聚合。", "!")
            log("  环境变量：FOFA_EMAIL/FOFA_KEY、ZONE_KEY、HUNTER_KEY、DAYDAYMAP_KEY", "!")
            return
        cidrs = []
        if getattr(self.args, "cscan", False):
            for ip in set(self.anchor["ips"]) | set(self.input_ips):
                try:
                    cidrs.append(str(ipaddress.ip_network(ip + "/24", strict=False)))
                except Exception:
                    pass
        queries = prov_layer.build_queries(
            self.anchor["domains"], self.anchor["beian"], self.anchor["orgs"],
            set(self.anchor["ips"]) | set(self.input_ips), cidrs)
        log("平台聚合：%s | 查询 %d 条" % (",".join(sorted(provs)), len(queries)))
        recs, stats = prov_layer.run(
            provs, queries,
            pages=getattr(self.args, "provider_pages", 1),
            limit=getattr(self.args, "provider_limit", 0),
            debug=getattr(self.args, "debug_provider", False),
            log=log)
        self.provider_records = recs
        self.provider_stats = stats
        for name, st in sorted(stats.items()):
            log("  %-10s 查询 %d / 记录 %d / 错误 %d"
                % (name, st.get("queries", 0), st.get("records", 0), st.get("errors", 0)))
        log("平台聚合完成：原始结果 %d 条" % len(recs))

    def merge_providers(self):
        if not self.provider_records:
            return
        log("== 阶段2.5: 平台结果聚合去重 ==", "#")
        before = len(self.assets)
        seen_hosts = {}
        for r in self.provider_records:
            host = (r.get("host") or "").strip().lower()
            ip = (r.get("ip") or "").strip()
            try:
                port = int(r.get("port") or 0) or None
            except Exception:
                port = None
            if not host and ip:
                host = ip
            if not host:
                continue
            scheme = None
            if port:
                scheme = "https" if port in (443, 8443, 9443) else "http"

            # 若被动阶段已有"仅主机"占位资产，则复用并补端口，避免同主机重复两行。
            # 注意 (host, port) 键可能已被前一条平台记录创建——此时把占位资产
            # 累积的证据并入已有资产，而不是盲写覆盖（会丢失 providers/证据）。
            a = None
            if port:
                ph = self.assets.pop((host, ""), None)
                if ph is not None:
                    existing = self.assets.get((host, str(port)))
                    if existing is not None:
                        _merge_assets(existing, ph)
                        a = existing
                    else:
                        ph.port = port
                        if not ph.scheme:
                            ph.scheme = scheme
                        self.assets[(host, str(port))] = ph
                        a = ph
            if a is None:
                a = self.add_asset(host, port, scheme,
                                   source="prov:%s" % r.get("provider"))
            if ip and not a.ip:
                a.ip = ip
            if r.get("title") and not a.title:
                a.title = r["title"]
            if r.get("server") and not a.server:
                a.server = r["server"]
            if r.get("url"):
                a.urls.add(r["url"])
            if r.get("provider"):
                a.providers.add(r["provider"])
            if r.get("match_kind"):
                a.prov_kinds.add(r["match_kind"])
            if r.get("beian") and not a.prov_beian:
                a.prov_beian = r["beian"]
            if r.get("cert") and not a.prov_cert:
                a.prov_cert = r["cert"]
            if r.get("org") and not a.prov_org:
                a.prov_org = r["org"]

            # 主机级聚合：同一主机的不同端口共享"平台证据"
            hp = seen_hosts.setdefault(host, {"providers": set(),
                                              "kinds": set(),
                                              "beian": "", "cert": "", "org": ""})
            if r.get("provider"):
                hp["providers"].add(r["provider"])
            if r.get("match_kind"):
                hp["kinds"].add(r["match_kind"])
            for k in ("beian", "cert", "org"):
                if r.get(k) and not hp[k]:
                    hp[k] = r[k]

        # 把主机级证据回填到该主机的所有资产
        for k, a in self.assets.items():
            hp = seen_hosts.get((a.host or "").lower())
            if not hp:
                continue
            a.providers |= hp["providers"]
            a.prov_kinds |= hp["kinds"]
            if hp["beian"] and not a.prov_beian:
                a.prov_beian = hp["beian"]
            if hp["cert"] and not a.prov_cert:
                a.prov_cert = hp["cert"]
            if hp["org"] and not a.prov_org:
                a.prov_org = hp["org"]

        log("平台资产合并：%d -> %d（去重后）" % (before, len(self.assets)))

    def verify_suspects(self, limit=0):
        log("== 阶段3.5: 疑似资产复核（HTTP 探测）==", "#")
        n = limit or getattr(self.args, "verify_limit", 0) or 100
        only = set(k for k, a in self.assets.items()
                   if a.confidence in ("疑似", "存疑"))
        log("待复核（疑似/存疑）: %d，上限 %d" % (len(only), n))
        if not only:
            return
        self.probe_all_web(include_unported=True, limit=n, only=only)

    # ---- 4. 评分 ----
    def evaluate(self):
        log("== 阶段4: 证据分级 ==", "#")
        orgs = [o for o in self.anchor["orgs"] if o and len(o) >= 4]
        beians = set(self.anchor["beian"])
        if getattr(self.args, "beian", ""):
            beians.add(self.args.beian)
        # 备案号比较用主号（省简称+ICP备+主序号）：-N 只是网站序号，
        # 主号相同才是同一主体；垃圾值提取不出主号，自动不命中
        beian_keys = {k for k in (_beian_key(b) for b in beians) if k}
        domains = set(self.anchor["domains"])
        weak_domains = set(self.anchor.get("weak_domains") or ())
        domains -= weak_domains

        def under(hostname, roots):
            for d in roots:
                if hostname == d or hostname.endswith("." + d):
                    return d
            return ""

        for k, a in self.assets.items():
            ev = []
            A = B = C = 0
            host = (a.host or "").lower()
            ip = a.ip or ""
            pk = a.prov_kinds
            nprov = len(a.providers)
            title = (a.title or "")

            # ---------- 页面级证据（HTTP 探测得到）----------
            if a.beian and _beian_key(a.beian) in beian_keys:
                ev.append("A|页面备案号一致:%s" % a.beian)
                A += 1
            if a.cert_org and any(_org_match(o, a.cert_org) for o in orgs):
                ev.append("A|证书O=一致:%s" % a.cert_org)
                A += 1
            if a.analytics and a.analytics in self.anchor["analytics"]:
                ev.append("B|统计ID一致:%s" % a.analytics)
                B += 1
            if a.favicon and a.favicon in self.anchor["favicon"]:
                ev.append("B|favicon一致:%s" % a.favicon)
                B += 1

            # ---------- 域名归属 ----------
            sd = under(host, domains)
            wd = under(host, weak_domains) if not sd else ""
            if sd:
                ev.append("A|主域名子域:%s" % sd)
                A += 1
            elif wd:
                ev.append("B|疑似归属弱锚点域名:%s" % wd)
                B += 1

            # ---------- 平台匹配证据 ----------
            if "cert" in pk:
                ev.append("A|平台cert命中")
                A += 1
            if "icp" in pk:
                ev.append("A|平台icp命中")
                A += 1
            if a.prov_beian and _beian_key(a.prov_beian) in beian_keys:
                ev.append("A|平台返回备案号命中:%s" % a.prov_beian)
                A += 1
            if a.prov_cert and any(d and d in a.prov_cert.lower() for d in domains):
                ev.append("A|平台证书含主域名")
                A += 1
            elif a.prov_cert and any(o and _org_match(o, a.prov_cert) for o in orgs):
                ev.append("B|平台证书含组织名")
                B += 1

            if "domain" in pk:
                if sd:
                    ev.append("A|平台domain命中")
                    A += 1
                elif wd:
                    # 查询本身就是用这个弱锚点域名发起的，不构成独立证据
                    ev.append("B|平台domain命中(弱锚点，不重复计分)")
                else:
                    ev.append("B|平台domain命中(待核)")
                    B += 1

            if "org" in pk:
                # 公司名匹配是最容易误报的一类：仅当标题也含组织名才升 B，否则只算 C
                if any(o and o in title for o in orgs):
                    ev.append("B|平台公司名+标题命中")
                    B += 1
                else:
                    ev.append("C|平台公司名命中(同名风险)")
                    C += 1

            if nprov >= 2 and (pk & {"domain", "cert", "icp", "org"}):
                ev.append("B|多平台交叉(%d)" % nprov)
                B += 1

            # ---------- IP 证据 ----------
            if ip and ip in self.anchor["ips"]:
                ev.append("C|同锚点IP:%s" % ip)
                C += 1
            elif ("ip" in pk or "cidr" in pk) and ip:
                ev.append("C|平台IP命中:%s" % ip)
                C += 1

            # ---------- 判定 ----------
            if A >= 1 or B >= 2:
                a.confidence = "确认"
            elif B == 1 or C >= 1:
                a.confidence = "疑似"
            else:
                a.confidence = "存疑"

            # ---------- 剔除规则 ----------
            a.reject_reason = ""
            if A == 0 and B == 0 and C == 0:
                a.confidence = "存疑"
                a.reject_reason = "无任何关联证据"
            elif A == 0 and B == 0 and is_third_party_infra(host):
                a.confidence = "存疑"
                a.reject_reason = "第三方云/CDN资源，且无强关联证据"
            a.evidence = ev

    # ---- 5. 输出 ----
    def output(self):
        log("== 阶段5: 生成报告 ==", "#")
        outdir = self.args.out
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(outdir, "shadowmap_%s" % ts)

        # 合并"仅主机"占位资产（被动阶段 host-only 条目）到同主机的带端口资产：
        # 否则报告里同一主机会出现一行"无端口无标题"的重复行，新手看着像脏数据。
        # 占位资产累积的来源/证据通过 _merge_assets 并入，不丢信息。
        with_ports = {}
        for a in self.assets.values():
            if a.port and a.host:
                with_ports.setdefault((a.host or "").lower(), []).append(a)
        for k in list(self.assets.keys()):
            ph = self.assets[k]
            if ph.port is None and ph.scheme is None and ph.host:
                targets = with_ports.get(ph.host.lower())
                if targets:
                    for t in targets:
                        _merge_assets(t, ph)
                    del self.assets[k]

        rows = sorted(self.assets.values(),
                      key=lambda a: ({"确认": 0, "疑似": 1, "存疑": 2}.get(a.confidence, 3),
                                     a.host or "", str(a.port or "")))
        groups = {"确认": [], "疑似": [], "存疑": []}
        for a in rows:
            groups.get(a.confidence, groups["存疑"]).append(a)

        cols = ["confidence", "host", "ip", "port", "scheme", "status", "title",
                "server", "tech", "cert_org", "cert_san", "beian", "analytics",
                "favicon", "providers", "prov_kinds", "prov_beian", "prov_cert",
                "prov_org", "source", "evidence", "reject_reason", "urls",
                "plain"]

        def write_csv(path, items):
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(cols)
                for a in items:
                    w.writerow([
                        a.confidence, a.host, a.ip, a.port or "", a.scheme or "",
                        a.status, a.title, a.server, a.tech, a.cert_org, a.cert_san,
                        a.beian, a.analytics, a.favicon,
                        ";".join(sorted(a.providers)),
                        ";".join(sorted(a.prov_kinds)),
                        a.prov_beian, a.prov_cert, a.prov_org,
                        ";".join(sorted(a.source)),
                        ";".join(a.evidence), a.reject_reason,
                        ";".join(sorted(a.urls)),
                        plain_evidence(a.evidence),
                    ])

        # 输出格式选择（--formats / 界面开关）：md / csv / json；未指定=全出
        fmts = getattr(self.args, "output_formats", None)
        if isinstance(fmts, str):
            fmts = {f.strip().lower() for f in fmts.split(",") if f.strip()}
        elif isinstance(fmts, (list, tuple, set)):
            fmts = {str(f).strip().lower() for f in fmts if str(f).strip()}
        else:
            fmts = None
        if not fmts:
            fmts = {"md", "csv", "json"}

        files = {}
        if "csv" in fmts:
            files["confirmed"] = base + "_confirmed.csv"
            files["suspect"] = base + "_suspect.csv"
            files["rejected"] = base + "_rejected.csv"
            files["all"] = base + "_all.csv"
            write_csv(files["confirmed"], groups["确认"])
            write_csv(files["suspect"], groups["疑似"])
            write_csv(files["rejected"], groups["存疑"])
            write_csv(files["all"], rows)

        json_path = ""
        if "json" in fmts:
            json_path = base + ".json"
            meta = {
                "names": self.names,
                "domains": sorted(self.anchor["domains"]),
                "input_ips": sorted(self.input_ips),
                "anchor": {k: sorted(v) for k, v in self.anchor.items()},
                "ip_notes": self.ip_notes,
                "provider_stats": self.provider_stats,
                "provider_records": len(self.provider_records),
                "counts": {k: len(v) for k, v in groups.items()},
                "assets": [a.to_dict() for a in rows],
                "generated_at": ts,
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)

        md_path = ""
        if "md" in fmts:
            md_path = base + ".md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self._report(rows, groups, ts))

        for k in ("confirmed", "suspect", "rejected", "all"):
            if k in files:
                log("%-10s %s" % (k, files[k]), "+")
        if json_path:
            log("JSON      %s" % json_path, "+")
        if md_path:
            log("MD        %s" % md_path, "+")
        return files, json_path, md_path

    def _report(self, rows, groups, ts):
        L = []
        L.append("# ShadowMap 互联网暴露面测绘报告\n")
        L.append("- 生成时间：%s" % ts)

        # ---- 新手导读：三份清单怎么用 ----
        L.append("")
        L.append("## 怎么读这份报告\n")
        L.append("本报告把找到的资产分成三份清单，**每行资产的「归属说明」用白话解释了为什么把它算进来**：")
        L.append("")
        L.append("| 清单 | 含义 | 建议动作 |")
        L.append("|------|------|----------|")
        L.append("| **确认** | 有强证据（备案号/证书/主域名）证明属于目标单位 | 可直接登记进资产台账 |")
        L.append("| **疑似** | 有线索但不铁（图标相同/仅同名/同IP段） | 人工访问核实后再决定 |")
        L.append("| **剔除** | 查到过但证据不足，或属于第三方云平台 | 无需处理，仅留档备查 |")
        L.append("")
        L.append("> 名词：**主机**是该资产的域名或IP，**端口**是它对外开放的服务入口，")
        L.append("> **标题**是网页打开后浏览器标签上显示的名字。例如 `www.xx.com | 443 | 某某医院官网`")
        L.append("> 表示「某某医院的官网网站，通过 https://www.xx.com 可以访问」。")
        L.append("")

        if self.names:
            L.append("- 主体名称：%s" % "、".join(self.names))
        if self.anchor["domains"]:
            strong = sorted(set(self.anchor["domains"]) - set(self.anchor.get("weak_domains") or ()))
            weak = sorted(set(self.anchor.get("weak_domains") or ()))
            if strong:
                L.append("- 关联主域名：%s" % "、".join(strong))
            if weak:
                L.append("- 疑似关联域名（由组织名反查，弱锚点）：%s" % "、".join(weak))
        if self.anchor["beian"]:
            L.append("- 锚点备案号：%s" % "、".join(sorted(self.anchor["beian"])))
        if self.anchor["analytics"]:
            L.append("- 锚点统计ID：%s" % "、".join(sorted(self.anchor["analytics"])))
        if self.anchor["favicon"]:
            L.append("- 锚点favicon：%s" % "、".join(sorted(self.anchor["favicon"])))
        if self.anchor["orgs"]:
            L.append("- 关联组织名：%s" % "、".join(sorted(o for o in self.anchor["orgs"] if o)))
        L.append("")

        # 平台统计
        if self.provider_stats:
            L.append("## 平台取数统计\n")
            L.append("| 平台 | 查询次数 | 原始记录 | 错误 |")
            L.append("|------|----------|----------|------|")
            for name, st in sorted(self.provider_stats.items()):
                L.append("| %s | %s | %s | %s |" % (
                    name, st.get("queries", 0), st.get("records", 0), st.get("errors", 0)))
            L.append("")

            # 平台交叉/独有分析
            combo = {}
            for a in rows:
                if a.providers:
                    key = "+".join(sorted(a.providers))
                    combo[key] = combo.get(key, 0) + 1
            if combo:
                L.append("## 平台交叉分析\n")
                L.append("| 命中平台组合 | 资产数 |")
                L.append("|--------------|--------|")
                for k2, v2 in sorted(combo.items(), key=lambda x: -x[1]):
                    L.append("| %s | %d |" % (k2, v2))
                L.append("")

        L.append("## 结果统计\n")
        L.append("| 分类 | 数量 | 说明 |")
        L.append("|------|------|------|")
        L.append("| 确认 | %d | 命中强证据，可直接入台账 |" % len(groups["确认"]))
        L.append("| 疑似 | %d | 有弱关联，建议人工核实 |" % len(groups["疑似"]))
        L.append("| 剔除 | %d | 无关联证据/第三方资源，已排除 |" % len(groups["存疑"]))
        L.append("| **合计** | **%d** | |" % len(rows))
        L.append("")

        def table(items, show_reason=False):
            if not items:
                L.append("_无_\n")
                return
            head = ("| 主机 | IP | 端口 | 标题 | 服务器 | 平台 | 归属说明（为什么算它的） | 证据 |")
            sep = ("|------|----|------|------|--------|------|--------------------------|------|")
            if show_reason:
                head += " 剔除原因 |"
                sep += "----------|"
            L.append(head)
            L.append(sep)
            for a in items:
                line = "| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                    _md(a.host), _md(a.ip), _md(str(a.port or "")),
                    _md(a.title), _md(a.server),
                    _md(",".join(sorted(a.providers)) or "-"),
                    _md(plain_evidence(a.evidence)),
                    _md("; ".join(a.evidence)))
                if show_reason:
                    line += " %s |" % _md(a.reject_reason)
                L.append(line)
            L.append("")

        L.append("## 确认资产（%d）\n" % len(groups["确认"]))
        table(groups["确认"])
        L.append("## 疑似资产（%d）\n" % len(groups["疑似"]))
        table(groups["疑似"])
        L.append("## 已剔除（%d）\n" % len(groups["存疑"]))
        table(groups["存疑"], show_reason=True)

        L.append("## 判定规则\n")
        L.append("- **A 级（强证据）**：备案号命中 / 证书 `O=` 命中 / 已知主域名子域 / 平台 `cert`、`icp` 命中 / 平台返回证书含主域名。")
        L.append("- **B 级（较强）**：统计ID 或 favicon 命中 / 平台 `domain` 命中 / 平台公司名且标题也含组织名 / 多平台交叉印证 / 仅由组织名反查得到的弱锚点域名下的主机。")
        L.append("- **C 级（弱）**：同锚点 IP / 平台 `ip`·`cidr` 命中 / 仅公司名匹配（同名风险）。")
        L.append("- **确认** = A≥1 或 B≥2；**疑似** = B=1 或 C≥1；**剔除** = 无任何证据，或第三方云/CDN 资源且无强证据。")
        L.append("")
        L.append("## 数据来源\n")
        L.append("- 被动：crt.sh、hackertarget、rapiddns、ip-api、bgpview、whois、DNS。")
        if self.provider_stats:
            L.append("- 平台：%s。" % "、".join(sorted(self.provider_stats.keys())))
        if self.args.active:
            L.append("- 本次包含**主动扫描**，请确认在授权范围内。")
        L.append("")
        return "\n".join(L)


def _md(s):
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ")


# 证据条目 → 新手可读的白话解释（按 evidence 前缀匹配，未命中保留原文）
_PLAIN_EVIDENCE = (
    ("A|页面备案号一致", "网站页脚的ICP备案号与目标单位备案号一致"),
    ("A|证书O=一致", "该站HTTPS证书的持有单位就是目标单位"),
    ("A|主域名子域", "是目标单位主域名的子域名"),
    ("A|平台cert命中", "测绘平台证书库显示该站证书含目标单位信息"),
    ("A|平台icp命中", "测绘平台备案库显示该站备案属于目标单位"),
    ("A|平台返回备案号命中", "平台数据显示该站备案号与目标单位一致"),
    ("A|平台证书含主域名", "该站证书中包含目标单位主域名"),
    ("A|平台domain命中", "测绘平台按目标域名检索命中该站"),
    ("B|统计ID一致", "该站与目标单位官网使用同一个访问统计账号"),
    ("B|favicon一致", "该站网站图标与目标单位官网相同（同模板建站）"),
    ("B|疑似归属弱锚点域名", "域名由组织名反查得到，归属待确认"),
    ("B|平台证书含组织名", "该站证书中包含目标单位组织名"),
    ("B|平台domain命中(弱锚点", "查询本身基于弱锚点域名，不重复计分"),
    ("B|平台domain命中(待核)", "测绘平台按域名检索命中，建议人工核实"),
    ("B|平台公司名+标题命中", "平台按单位名检索命中，且页面标题也含单位名"),
    ("B|多平台交叉", "两个以上测绘平台同时收录该资产"),
    ("C|平台公司名命中", "仅单位名称相同（可能是同名机构，需人工核实）"),
    ("C|同锚点IP", "与目标单位官网部署在同一台服务器上"),
    ("C|平台IP命中", "位于目标单位的IP地址段内"),
)


def plain_evidence(evidence_list, max_items=3):
    """把 A/B/C 证据条目翻译成新手能看懂的白话，去重后拼接。

    max_items: 最多保留的解释条数（报告列宽友好），超出以"等"收尾。
    """
    out, seen = [], set()
    for ev in (evidence_list or []):
        for prefix, plain in _PLAIN_EVIDENCE:
            if ev.startswith(prefix):
                if plain not in seen:
                    seen.add(plain)
                    out.append(plain)
                break
        else:
            if ev not in seen:
                seen.add(ev)
                out.append(ev)
    if len(out) > max_items:
        out = out[:max_items] + ["等"]
    return "；".join(out)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def classify_target(t):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return "ip"
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            pass
    if re.match(r"^[A-Za-z0-9_.\-]+\.[A-Za-z]{2,}$", t):
        return "domain"
    return "name"


def _add_ip_target(ips, t):
    """把 IP 或 CIDR 加入 ips 集合；返回错误信息或 None。

    CIDR 必须足够小（IPv4 ≥/24，IPv6 ≥/120），否则返回错误——
    防 /16 一次展开六万个 IP。更大的范围请用 --cscan（只对锚点 IP 所在 /24 扩展）。
    """
    t = (t or "").strip()
    if not t:
        return None
    if "/" not in t:
        ips.add(t)
        return None
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return "无法解析网段: %s" % t
    min_len = 24 if net.version == 4 else 120
    if net.prefixlen < min_len:
        return ("网段 %s 过大（IPv4 需 ≥/24，IPv6 需 ≥/120）；"
                "请收窄范围，或改用 --cscan 只对锚点 IP 所在 /24 扩展" % t)
    for h in net.hosts():
        ips.add(str(h))
    return None


def parse_ports(s):
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                for p in range(int(a), int(b) + 1):
                    if 0 < p < 65536:
                        ports.add(p)
            except Exception:
                pass
        else:
            try:
                p = int(part)
                if 0 < p < 65536:
                    ports.add(p)
            except Exception:
                pass
    return sorted(ports)


def build_parser():
    p = argparse.ArgumentParser(
        description="单位名称 / 域名 / IP 的互联网暴露面测绘工具（默认被动，主动需 --active）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python shadowmap.py -n "某某市人民政府" -d xx.gov.cn
  python shadowmap.py -d example.com
  python shadowmap.py --ip 1.2.3.4
  python shadowmap.py -d example.com --active --top 200
  python shadowmap.py -d example.com --active --cscan
""")
    p.add_argument("target", nargs="?", help="自动识别：域名 / IP / 单位名称")
    p.add_argument("-n", "--name", action="append", default=[], help="单位名称（可多次）")
    p.add_argument("-d", "--domain", action="append", default=[], help="域名（可多次）")
    p.add_argument("--ip", action="append", default=[], help="IP（可多次）")
    p.add_argument("--beian", default="", help="已知备案号（作为强锚点，可选）")
    p.add_argument("--active", action="store_true", help="启用主动扫描（端口/批量探测），需授权")
    p.add_argument("--cscan", action="store_true", help="扩展扫描 C 段（隐含主动）")
    p.add_argument("--full-ports", action="store_true", help="全端口 1-65535（很慢）")
    p.add_argument("--top", type=int, default=0, help="使用前 N 个常见端口")
    p.add_argument("--ports", default="", help='自定义端口，如 "80,443,8000-8100"')
    p.add_argument("--threads", type=int, default=20, help="并发数（默认20）")
    p.add_argument("--timeout", type=float, default=10, help="超时秒数（默认10）")
    p.add_argument("--scan-timeout", type=float, default=2.5, dest="scan_timeout",
                   help="TCP 端口扫描连接超时秒数（默认2.5；与 --timeout 的 HTTP 超时独立）")
    p.add_argument("--out", default="shadowmap_out", help="输出目录")
    p.add_argument("--formats", default="md,csv,json", dest="output_formats",
                   help="输出哪些格式：md / csv / json，逗号分隔（默认全出）")
    p.add_argument("--no-probe", action="store_true", help="完全不触碰目标（纯第三方数据）")
    p.add_argument("--no-discover", action="store_true",
                   help="仅给名称时禁用搜索引擎官网自举（默认启用）")
    p.add_argument("--probe-found", action="store_true",
                   help="被动模式下，对发现的主机做 HTTP 探测（默认不做，避免打扰目标）")
    p.add_argument("--probe-limit", type=int, default=100,
                   help="--probe-found 时最多探测多少个主机（默认100）")
    p.add_argument("--yes", action="store_true", help="跳过主动扫描的授权确认")
    p.add_argument("--quiet", action="store_true", help="少输出")

    g = p.add_argument_group("多平台聚合（FOFA / 0.zone / Hunter鹰图 / DayDayMap）")
    g.add_argument("--providers", action="append", default=None,
                   help="只使用指定平台，可多次：fofa / zerozone / hunter / daydaymap")
    g.add_argument("--provider-pages", type=int, default=1,
                   help="每个查询最多翻多少页（默认1，越大越慢越费配额）")
    g.add_argument("--provider-limit", type=int, default=0,
                   help="单个平台最多取多少条（0=不限）")
    g.add_argument("--no-providers", action="store_true", help="不使用任何测绘平台，只跑本地被动采集")
    g.add_argument("--config", default="config.json",
                   help="平台 Key 配置文件路径（默认 config.json，环境变量优先）")
    g.add_argument("--debug-provider", action="store_true", help="打印平台查询与错误详情")
    g.add_argument("--verify", action="store_true",
                   help="被动模式下对疑似资产做一次 HTTP 复核（会触碰目标）")
    g.add_argument("--verify-limit", type=int, default=0,
                   help="--verify 时最多复核多少个（0=默认上限）")
    return p


def run_pipeline(args, names, domains, ips, should_stop=None, do_output=True):
    """执行完整测绘流水线（CLI 与 GUI 共用）。

    should_stop: 可选回调，各阶段之间检查；返回 True 时跳过剩余采集阶段，
    直接对已收集的数据做分级输出（GUI 的"停止并输出"用）。
    do_output: False 时只做采集+分级不写报告文件（GUI 先在界面里展示结果，
    报告由用户点"生成报告"按钮时再调 eng.output() 按需导出）。
    返回 (engine, files, json_path, md_path)；do_output=False 时后三项为空值。
    """
    def _stopped():
        return bool(should_stop and should_stop())

    eng = Engine(args)
    eng.names = names
    eng.domains = domains
    eng.input_ips = ips
    for b in [args.beian] if args.beian else []:
        eng.anchor["beian"].add(b)
    for n in names:
        eng.anchor["orgs"].add(n)

    log("输入 -> 名称:%s 域名:%s IP:%s" % (names or "-", sorted(domains) or "-", sorted(ips) or "-"), "#")
    if not HAVE_DNS:
        log("未安装 dnspython，DNS 记录将降级为 nslookup（建议 pip install dnspython）", "!")
    if not HAVE_CRYPTO:
        log("未安装 cryptography，证书 O= 信息不可用（建议 pip install cryptography）", "!")

    # 名称模式没有域名时：先用搜索引擎自举官网域名（无需平台 Key），
    # 再走 crt.sh 组织名反查兜底
    if names and not domains and not ips:
        if not getattr(args, "no_discover", False):
            eng.discover_names_to_domains()
        if not eng.domains:
            log("仅提供名称：官网自举未获域名，退回 crt.sh 按组织名搜索。", "!")
            log("若结果很少，建议手动补充域名输入（ICP备案查询得到的主域名）。", "!")

    eng.build_anchors(probe=not args.no_probe)
    if not _stopped():
        eng.collect_passive()
        # 多平台聚合（FOFA / 0.zone / Hunter / DayDayMap）
        if not args.no_providers:
            eng.collect_providers()
            eng.merge_providers()
    if not _stopped():
        if args.active:
            eng.scan_active()
        elif args.verify and not args.no_probe:
            eng.evaluate()          # 先分级，复核只针对疑似/存疑
            eng.verify_suspects(limit=args.verify_limit)
        elif args.probe_found and not args.no_probe:
            log("== 阶段3: 轻量探测（对被动发现的主机做 HTTP 探测）==", "#")
            eng.probe_all_web(include_unported=True,
                              limit=(args.probe_limit or 100))
    if _stopped():
        log("已请求停止：对已收集的数据做分级输出。", "!")
    eng.evaluate()
    if not do_output:
        return eng, {}, "", ""
    files, json_path, md_path = eng.output()
    return eng, files, json_path, md_path


def main():
    global QUIET
    parser = build_parser()
    args = parser.parse_args()
    QUIET = args.quiet

    try:
        # 不强制改编码（避免与控制台代码页冲突），只让不可编码字符不报错
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

    names = list(args.name)
    domains = set(d.strip().lower() for d in args.domain if d.strip())
    ips = set()
    target_errors = []
    for t in (args.ip or []):
        err = _add_ip_target(ips, t)
        if err:
            target_errors.append(err)

    if args.target:
        kind = classify_target(args.target.strip())
        t = args.target.strip()
        if kind == "ip":
            ips.add(t)
        elif kind == "cidr":
            err = _add_ip_target(ips, t)
            if err:
                target_errors.append(err)
        elif kind == "domain":
            domains.add(t.lower())
        else:
            names.append(t)

    if target_errors:
        for e in target_errors:
            print("[错误] %s" % e)
        return 2

    if not names and not domains and not ips:
        parser.print_help()
        print("\n错误：至少提供 名称 / 域名 / IP 之一。")
        return 2

    # 端口列表
    if args.ports:
        args.ports_list = parse_ports(args.ports)
    elif args.top and args.top > 0:
        if args.top > len(DEFAULT_PORTS):
            print("[!] --top %d 超过内置常见端口表长度 %d，已截断为内置全表"
                  % (args.top, len(DEFAULT_PORTS)))
        args.ports_list = DEFAULT_PORTS[:args.top]
    else:
        args.ports_list = list(DEFAULT_PORTS)
    if not args.ports_list:
        args.ports_list = list(DEFAULT_PORTS)

    if (args.active or args.cscan) and not args.yes:
        print("\n[!] 你启用了主动扫描（--active / --cscan）。")
        print("    请确认你已获得对该目标的书面授权，且扫描速率不会影响其业务。")
        try:
            ans = input("    确认继续？输入 yes 继续：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            # 管道/非交互环境下 input() 会抛 EOFError，不能让 traceback 裸奔
            print("\n未获得确认，已取消。")
            return 1
        if ans != "yes":
            print("已取消。")
            return 1
    if args.cscan:
        args.active = True

    eng, files, json_path, md_path = run_pipeline(args, names, domains, ips)

    # 终端摘要
    counts = {"确认": 0, "疑似": 0, "存疑": 0}
    for a in eng.assets.values():
        counts[a.confidence] = counts.get(a.confidence, 0) + 1
    print("")
    print("=" * 64)
    print("完成：确认 %d | 疑似 %d | 剔除 %d | 合计 %d"
          % (counts["确认"], counts["疑似"], counts["存疑"], len(eng.assets)))
    if files.get("confirmed"):
        print("确认台账：%s" % files["confirmed"])
    if md_path:
        print("报告：%s" % md_path)
    print("=" * 64)
    return 0


class _LightProbeMixin:
    pass


if __name__ == "__main__":
    sys.exit(main())
