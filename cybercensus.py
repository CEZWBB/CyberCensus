#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cybercensus.py —— CyberCensus：单位名称 / 域名 / IP 的互联网暴露面测绘工具（低误报版）

设计原则（对应《单位名称暴露面全量测绘方法》）：
  1. 名称/域名/IP 只是入口，真正的"证据锚点"是：
       ICP备案号、SSL证书 O=组织名、Whois注册人、统计代码ID、favicon哈希
  2. 默认只做【被动收集】+ 对用户提供的域名做一次锚点探测，不主动扫目标。
  3. 主动扫描（端口/批量探测/C段）必须显式 --active / --cscan。
  4. 结果按 A/B/C 证据分级自动给出 确认 / 疑似 / 存疑。

用法示例：
  python cybercensus.py -n "某某市人民政府" -d xx.gov.cn
  python cybercensus.py -d example.com
  python cybercensus.py --ip 1.2.3.4
  python cybercensus.py -d example.com --active --top 200
  python cybercensus.py -d example.com --active --cscan

依赖（可选，缺失会自动降级）：
  pip install dnspython cryptography
"""

import argparse
import base64
import csv
import html as html_mod
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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

# 探测目标时的 UA 轮换池（降低被 WAF 按单一 UA 拉黑的概率）。
# 搜索引擎查询保持固定 UA（轮换反而容易触发人机验证）。
UA_POOL = (
    UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # 移动端 UA：很多公众号/移动端系统在桌面 UA 下显示不全或被拦截
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
)


def _pick_ua():
    return random.choice(UA_POOL)


# 全局探测节流：跨线程的请求间隔下限（--probe-interval 控制，默认 0=不节流）。
# 授权测试的正确姿势是申请 WAF 白名单；这里是"礼貌探测"而非规避。
_PROBE_LOCK = threading.Lock()
_PROBE_LAST = [0.0]


def _global_throttle(interval):
    if not interval or interval <= 0:
        return
    with _PROBE_LOCK:
        wait = _PROBE_LAST[0] + interval - time.time()
        if wait > 0:
            time.sleep(wait)
        _PROBE_LAST[0] = time.time()


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


# ----------------------------------------------------------------------------
# 统一社会信用代码（GB 32100-2015）：文档 7.2 的 A 级证据，几乎零误报。
# 18 位 = 1位登记管理部门 + 1位机构类别 + 6位登记区划 + 9位主体标识 + 1位校验码。
# 带 GB32100 校验码验证——正则命中的字符串还要通过校验才算真代码。
# ----------------------------------------------------------------------------
_CREDIT_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_CREDIT_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)
# 注：不用 \b——Python3 的 \w 含中文，"莞城91120..." 这种紧邻中文的场景会漏配
CREDIT_CODE_RE = re.compile(r"(?<![0-9A-HJ-NPQRTUWXY])([0-9A-HJ-NPQRTUWXY]{18})(?![0-9A-HJ-NPQRTUWXY])")


def _credit_code_ok(code):
    """统一社会信用代码 GB32100 校验码验证。"""
    code = (code or "").strip().upper()
    if len(code) != 18:
        return False
    try:
        total = sum(_CREDIT_WEIGHTS[i] * _CREDIT_CHARS.index(code[i]) for i in range(17))
        check = _CREDIT_CHARS[(31 - total % 31) % 31]
        return check == code[17]
    except ValueError:
        return False


def extract_credit_code(text):
    """从页面/摘要文本提取第一个通过校验的统一社会信用代码；没有返回空串。"""
    if not text:
        return ""
    for m in CREDIT_CODE_RE.finditer(str(text).upper()):
        if _credit_code_ok(m.group(1)):
            return m.group(1)
    return ""


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


# 省级行政区 → 域名里常见的拼音缩写 / 全拼（运营商、银行、政府的省级站规律：
# 四川移动 = sc.10086.cn，广东电信 = gd.189.cn……）
PROVINCE_CODES = {
    "北京": ("bj", "beijing"), "天津": ("tj", "tianjin"), "河北": ("he", "hebei"),
    "山西": ("sx", "shanxi"), "内蒙古": ("nm", "neimenggu", "nmg"),
    "辽宁": ("ln", "liaoning"), "吉林": ("jl", "jilin"),
    "黑龙江": ("hl", "hlj", "heilongjiang"), "上海": ("sh", "shanghai"),
    "江苏": ("js", "jiangsu"), "浙江": ("zj", "zhejiang"), "安徽": ("ah", "anhui"),
    "福建": ("fj", "fujian"), "江西": ("jx", "jiangxi"), "山东": ("sd", "shandong"),
    "河南": ("ha", "henan"), "湖北": ("hb", "hubei"), "湖南": ("hn", "hunan"),
    "广东": ("gd", "guangdong"), "广西": ("gx", "guangxi"), "海南": ("hi", "hainan"),
    "重庆": ("cq", "chongqing"), "四川": ("sc", "sichuan"), "贵州": ("gz", "guizhou"),
    "云南": ("yn", "yunnan"), "西藏": ("xz", "xizang", "tibet"),
    "陕西": ("sn", "shaanxi", "sx"), "甘肃": ("gs", "gansu"),
    "青海": ("qh", "qinghai"), "宁夏": ("nx", "ningxia"),
    "新疆": ("xj", "xinjiang"), "台湾": ("tw", "taiwan"),
    "香港": ("hk", "hongkong"), "澳门": ("mo", "macau", "macao"),
}


def _region_hit(name, host, page_text=""):
    """名称里的省级地名与域名标签的拼音缩写互证（四川移动 ↔ sc.10086.cn）。

    必须配合行业词核验（见 _sector_hit）：单独的地域命中会误伤——
    "四川移动" 会命中任何 sc.* 的四川站点（如 www.sc.gov.cn 省政府），
    所以要求名称剔除省份后的行业词（"移动"）同时出现在页面文本中。
    """
    host = (host or "").lower()
    labels = set(host.split("."))
    region_ok = False
    for prov, codes in PROVINCE_CODES.items():
        if prov not in name:
            continue
        for c in codes:
            # 两字母缩写只认"独立标签"（防 school 里的 sc）；全拼允许子串
            if (len(c) == 2 and c in labels) or (len(c) > 2 and c in host):
                region_ok = True
                break
        if region_ok:
            break
    if not region_ok:
        return False
    return _sector_hit(name, page_text)


def _sector_hit(name, text):
    """名称剔除省级地名/后缀后的行业词是否出现在页面文本（地域互证的配套条件）。"""
    rest = name or ""
    for prov in PROVINCE_CODES:
        rest = rest.replace(prov, "")
    for suffix in ("公司", "分公司", "有限", "省", "市", "区", "县"):
        rest = rest.replace(suffix, "")
    rest = rest.strip()
    return len(rest) >= 2 and rest in (text or "")


def _bigrams(s):
    return {s[i:i + 2] for i in range(len(s) - 1)}


def _org_match_fuzzy(a, b, min_cov=0.6, min_len=4):
    """简称/别名场景的宽松组织名匹配：bigram 覆盖率 ≥ min_cov。

    用于**候选验证阶段**（bootstrap 探索"这个域名是不是它的"），不用于分级——
    "四川移动" → "中国移动通信集团四川有限公司"：{四川,移动} 均命中，覆盖 67%；
    "东莞市人民医院" vs "东莞市莞城医院"：覆盖 50% 被拒（防同城不同医院误配）。
    分级判定（evaluate）仍走严格的 _org_match，防止宽松匹配污染"确认"。
    """
    na, nb = _norm_org(a), _norm_org(b)
    if not na or not nb or len(na) < min_len:
        return False
    ga = _bigrams(na)
    if not ga:
        return False
    return len(ga & _bigrams(nb)) / len(ga) >= min_cov


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

# 指纹库（借鉴 ARL/ShuiZe/Goby 的国产组件覆盖）：
# (显示名, 页面特征列表)；特征为空表示靠 Server 头识别
TECH_MARKERS = [
    # 通用框架/语言
    ("ThinkPHP", ["thinkphp"]),
    ("Spring", ["whitelabel error page"]),
    ("WordPress", ["wp-content", "wp-includes"]),
    ("Shiro", ["rememberme=deleteme"]),
    ("Tomcat", ["apache tomcat", "tomcat"]),
    ("Weblogic", ["weblogic"]),
    ("Nginx", []),
    ("IIS", []),
    ("Vue", ["__vue__", "/static/js/app."]),
    ("React", ["__next_data__"]),
    # 国产 OA / ERP / 报表（渗透高频目标，多为已知漏洞家族）
    ("泛微OA", ["e-office", "ecology", "weaver"]),
    ("致远OA", ["seeyon", "致远"]),
    ("用友NC/U8", ["yonyou", "nccloud", "用友"]),
    ("金蝶EAS", ["kingdee", "金蝶"]),
    ("帆软报表", ["finereport", "finebi", "帆软"]),
    ("通达OA", ["tongda", "通达"]),
    ("蓝凌OA", ["landray", "蓝凌"]),
    ("若依RuoYi", ["ruoyi"]),
    ("JEECG", ["jeecg"]),
    ("禅道", ["zentao"]),
    # 中间件 / 管理台（未授权访问高频）
    ("宝塔面板", ["bt panel", "宝塔", "bt.cn"]),
    ("Nacos", ["nacos"]),
    ("Eureka", ["eureka"]),
    ("Zabbix", ["zabbix"]),
    ("Grafana", ["grafana"]),
    ("Kibana", ["kibana"]),
    ("RabbitMQ管理", ["rabbitmq"]),
    ("Solr", ["solr"]),
    ("Harbor", ["harbor"]),
    ("MinIO", ["minio"]),
    ("Docker Registry", ["docker-distribution", "registry/2.0"]),
    ("Kubernetes-Dashboard", ["kubernetes-dashboard"]),
    ("Nexus", ["nexus repository"]),
    ("Jira", ["jira"]),
    ("Confluence", ["confluence"]),
    ("GitLab", ["gitlab"]),
    ("Jenkins", ["jenkins"]),
    ("Exchange", ["owa/", "outlook web app"]),
    ("深信服SSL-VPN", ["isclogin", "深信服"]),
    ("Citrix", ["citrix"]),
    ("金和OA", ["jinhe", "金和"]),
    ("华天动力OA", ["huatian", "华天动力"]),
    ("ShowDoc", ["showdoc"]),
    ("海康威视", ["ivms", "hikvision"]),
    ("大华", ["dahua", "dh_"]),
    ("H3C", ["h3c", "华三"]),
    ("Swagger", ["swagger-ui", "swagger"]),
]

# 风险组件提示：命中即提示"建议排查对应已知漏洞家族"（不执行任何 POC）
RISKY_TECH = {
    "泛微OA": "泛微 e-office/ecology 历史多个 RCE（文件上传/反序列化）",
    "致远OA": "致远 OA 历史多个未授权 RCE（如 ajax.do 系列）",
    "用友NC/U8": "用友 NC/U8 历史反序列化 RCE 与 SQL 注入",
    "金蝶EAS": "金蝶 EAS 目录遍历/文件上传历史漏洞",
    "帆软报表": "帆软 v8/v9 未授权访问与远程命令执行",
    "通达OA": "通达 OA 未授权上传/命令执行历史漏洞",
    "蓝凌OA": "蓝凌 OA 未授权命令执行历史漏洞",
    "Shiro": "Shiro rememberMe 反序列化（默认密钥风险）",
    "Weblogic": "Weblogic 多个反序列化 RCE（CVE-2015/2017/2019 系列）",
    "Jenkins": "Jenkins 未授权脚本控制台（/script）风险",
    "Solr": "Solr Velocity 模板 RCE / 未授权配置上传",
    "Nacos": "Nacos 默认口令/未授权配置读取",
    "RabbitMQ管理": "RabbitMQ 管理台默认口令 guest/guest",
    "Zabbix": "Zabbix SQL 注入历史漏洞",
    "Grafana": "Grafana 插件目录穿越历史漏洞",
    "Kibana": "Kibana 原型污染 RCE 历史漏洞",
    "Docker Registry": "Docker Registry 未授权镜像拉取",
    "Kubernetes-Dashboard": "K8s Dashboard 未授权命令执行",
    "MinIO": "MinIO 未授权访问历史漏洞",
    "Harbor": "Harbor 未授权/权限提升历史漏洞",
    "深信服SSL-VPN": "深信服 SSL VPN 历史预认证 RCE",
    "Citrix": "Citrix ADC 历史预认证 RCE（CitrixBleed 等）",
    "Exchange": "Exchange ProxyShell/ProxyLogon 历史漏洞",
    "ThinkPHP": "ThinkPHP 历史上多个 RCE（5.x 系列）",
}


def tech_risk(tech):
    """从指纹串找出命中的风险组件提示列表。"""
    out = []
    for name, note in RISKY_TECH.items():
        if name.lower() in (tech or "").lower():
            out.append("%s：%s" % (name, note))
    return out


# WAF 指纹（借鉴 wafw00f）：靠响应头/Cookie/页面标记识别防护设备
WAF_SIGNATURES = (
    ("阿里云盾", ["aliyun", "aliyungf", "errors.aliyun.com", "yundun"]),
    ("腾讯云WAF", ["waf.tencent", "tencent-waf"]),
    ("Cloudflare", ["cloudflare", "__cfduid", "cf_clearance", "cf-ray"]),
    ("360企业安全", ["360wzws", "wzws"]),
    ("长亭雷池", ["safeline"]),
    ("安全狗", ["safedog", "waf/2.0"]),
    ("知道创宇创宇盾", ["yunsuo", "yunaq", "knownsec"]),
    ("Imperva", ["incap_ses", "visid_incap"]),
    ("Akamai", ["akamaighost", "akamai"]),
    ("F5 BIG-IP", ["bigipserver", "big-ip"]),
    ("安恒WAF", ["dbappsecurity", "dbappwaf"]),
    ("华为WAF", ["huaweicloudwaf"]),
    ("ModSecurity", ["mod_security", "modsecurity"]),
)


def detect_waf(headers_text, body):
    """识别响应中的 WAF 标记；返回 WAF 名称或空串。"""
    hay = ((headers_text or "") + " " + (body or "")[:4000]).lower()
    for name, marks in WAF_SIGNATURES:
        if any(m in hay for m in marks):
            return name
    return ""


# JS 敏感信息（借鉴 FindSomething/WebInfoHunter）：高精度密钥特征
SECRET_PATTERNS = (
    ("阿里云AccessKey", re.compile(r"LTAI[A-Za-z0-9]{12,20}")),
    ("腾讯云SecretId", re.compile(r"AKID[A-Za-z0-9]{20,40}")),
    ("AWS AccessKey", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("私钥文件内容", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


def scan_js_secrets(text):
    """扫描 JS 文本中的高精度密钥特征，返回命中的类型列表。"""
    return [name for name, pat in SECRET_PATTERNS if pat.search(text or "")]


# 常见子域字典（借鉴 ksubdomain/dnsbrute：小字典而非大爆破，只做 DNS 解析）
COMMON_SUBS = (
    "www", "mail", "oa", "erp", "crm", "hr", "vpn", "ftp", "sso", "auth",
    "api", "app", "m", "wap", "admin", "portal", "zwfw", "gov", "news",
    "bbs", "shop", "pay", "open", "dev", "test", "uat", "staging", "demo",
    "monitor", "zabbix", "git", "svn", "jenkins", "wiki", "docs", "mx",
    "ns1", "ns2", "dns", "cache", "cdn", "static", "img", "video", "file",
)


def brute_subdomains(domain, resolver=None, workers=16):
    """小字典子域枚举：只做 DNS 解析（不碰目标端口），返回 {host: ip}。"""
    resolve = resolver or resolve_a
    out = {}

    def _one(w):
        h = "%s.%s" % (w, domain)
        try:
            ips = resolve(h)
        except Exception:
            ips = ()
        return h, (sorted(ips)[0] if ips else "")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for h, ip in ex.map(_one, COMMON_SUBS):
            if ip:
                out[h] = ip
    return out

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
             max_bytes=4 * 1024 * 1024, throttle=0.0, ua=None):
    hdrs = {
        "User-Agent": ua or _pick_ua(),
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    last_err = None
    for i in range(retries + 1):
        try:
            _global_throttle(throttle)
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


EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# 明显的占位/静态资源误匹配
_EMAIL_JUNK = ("example.", "test@", "@test.", ".png", ".jpg", ".gif",
               ".js", ".css", "@2x", "sentry.io", "@w3.org", "you@", "your@",
               "@domain.com")


def _extract_emails(text, limit=8):
    """从页面/摘要提取联系邮箱（去重、去占位与静态资源误匹配）。"""
    out, seen = [], set()
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0).strip(".").lower()
        if len(e) > 80 or any(j in e for j in _EMAIL_JUNK):
            continue
        if e not in seen:
            seen.add(e)
            out.append(e)
        if len(out) >= limit:
            break
    return out


def _extract_scripts(body, base_url, limit=8):
    """从页面提取外部 JS 脚本绝对 URL（JSFinder/WebInfoHunter 的前置步骤）。"""
    out = []
    base = base_url.rstrip("/")
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', body or "", re.I):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = base + src
        elif not src.lower().startswith(("http://", "https://")):
            continue
        if src not in out:
            out.append(src)
        if len(out) >= limit:
            break
    return out


def _extract_meta(body):
    """提取页面 meta 描述/关键词/应用名——SPA 站标题为空时的关键互证文本。"""
    parts = []
    for m in re.finditer(
            r'<meta[^>]+(?:name|property)\s*=\s*["\']'
            r'(?:description|keywords|og:title|application-name)["\'][^>]*?'
            r'content\s*=\s*["\']([^"\']+)', body or "", re.I):
        parts.append(m.group(1))
    return (" ".join(parts))[:600]


def http_probe(host, port, scheme, timeout=8, throttle=0.0):
    """返回 dict：status/title/server/powered/beian/analytics/favicon/tech/body_len"""
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        url = "%s://%s/" % (scheme, host)
    else:
        url = "%s://%s:%d/" % (scheme, host, port)

    out = {"url": url, "status": "", "title": "", "server": "",
           "powered": "", "beian": "", "analytics": "", "favicon": "",
           "tech": "", "body_len": 0, "credit_code": "", "refs": [], "meta": "",
           "emails": [], "scripts": [], "waf": ""}
    body = ""
    status = ""
    hdrs = {}
    try:
        _global_throttle(throttle)
        req = urllib.request.Request(url, headers={"User-Agent": _pick_ua()})
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
    out["credit_code"] = extract_credit_code(body)   # 页脚常印统一社会信用代码
    out["meta"] = _extract_meta(body)                # SPA 站的单位名常在 meta 里
    out["emails"] = _extract_emails(body)            # 页面联系邮箱
    out["scripts"] = _extract_scripts(body, url)     # 外部 JS（后续挖域名/密钥）
    out["waf"] = detect_waf(
        " ".join("%s:%s" % (k, v) for k, v in hdrs.items()), body)  # 防护设备识别
    # 页面外链/JS 引用的域名（文档 5.2 前端深挖金矿）：候选资产线索
    out["refs"] = [m.group(1) for m in _DOMAIN_IN_TEXT_RE.finditer(body)]

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

# 注意：不排除斜杠前缀——URL 形式（https://gh.x.com）的域名引用必须能提取
_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?<![\w.\-])((?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.)+"
    r"(?:com|net|org|cn|gov|edu|info|xyz|top|vip|cc|hk|mo|tw)(?:\.cn)?)"
    r"(?![\w.\-])")

# 页面正文/JS 里出现的技术域/公共设施域：外链挖掘时排除（不作为候选资产）
PAGE_JUNK_ROOTS = SEARCH_JUNK_ROOTS | frozenset((
    # Web 标准 / 前端 CDN / 字体图标库
    "w3.org", "schema.org", "jsdelivr.net", "unpkg.com", "bootcdn.net",
    "staticfile.org", "jquery.com", "bootstrapcdn.com", "googleapis.com",
    "gstatic.com", "cloudflare.com", "cdnjs.com", "fontawesome.com",
    "vuejs.org", "reactjs.org", "npmjs.com", "gulpjs.com", "echarts.baidu.com",
    # 开发/文档/工具
    "github.io", "gitlab.com", "gitee.com", "stackoverflow.com", "runoob.com",
    "w3school.com.cn", "mdn.mozilla.org", "apache.org", "nginx.org",
    "php.net", "python.org", "mysql.com", "redis.io", "docker.com",
    # 邮件/短信/地图/支付/统计等第三方服务
    "mail.qq.com", "exmail.qq.com", "work.weixin.qq.com", "dingtalk.com",
    "taobao.com", "tmall.com", "alipay.com", "tenpay.com", "unionpay.com",
    "map.baidu.com", "amap.com", "qqmap.com", "jiathis.com", "bshare.cn",
    "umeng.com", "growingio.com", "sensors.com", "matomo.org", "hotjar.com",
    # 公众号/新媒体平台本身（文章来源域不是目标资产）
    "mp.weixin.qq.com", "weixin.qq.com", "mp.weixin.com",
))


def filter_candidate_roots(hosts, exclude_roots=()):
    """从页面/文章正文提取的域名中筛出候选根域名：滤垃圾域/三方设施/已知域。

    返回保序去重的根域名列表（候选仍需 _verify_candidate_domain 互证才入锚点）。
    """
    out, seen = [], set()
    for h in hosts or []:
        h = (h or "").lower().rstrip(".")
        if not h or "_" in h or h in seen:
            continue
        root = root_domain(h)
        if not root or root in seen:
            continue
        if root in PAGE_JUNK_ROOTS or h in PAGE_JUNK_ROOTS:
            continue
        if is_third_party_infra(root):
            continue
        if root in exclude_roots:
            continue
        seen.add(root)
        out.append(root)
    return out


def _strip_tags(html):
    return re.sub(r"<[^>]+>", " ", html or "")


def search_engine_lookup(name, timeout=15):
    """cn.bing.com 搜索（无 Key），返回 (去标签全文, 有机结果 host 列表)。

    失败/被拦截返回 ("", [])。单次、不重试翻页，控制对搜索引擎的触碰。
    """
    try:
        url = ("https://cn.bing.com/search?q=" + urllib.parse.quote(name)
               + "&count=20&mkt=zh-CN")
        # 搜索引擎查询用固定 UA：轮换 UA 反而容易触发人机验证
        html = http_get(url, timeout=timeout, retries=1,
                        headers={"Accept": "text/html, */*", "User-Agent": UA})
        hosts = [h.lower() for h
                 in re.findall(r'<h2><a[^>]+href="https?://([^/\"]+)', html)]
        return _strip_tags(html), hosts
    except Exception as e:
        log("搜索引擎查询失败(%s): %s" % (name, str(e)[:80]), "!")
        return "", []


def discover_domains_from_search(name, max_candidates=5, lookup=None):
    """从搜索引擎结果提取候选官网域名，返回 [(host, score), ...] 按分排序。

    - 有机链接 host 记 3 分（结果标题直接链接的目标）
    - 正文/摘要中出现的域名记 1 分/次（目录站摘要常含官网链接）
    - 搜索引擎自身与聚合目录站（SEARCH_JUNK_ROOTS）直接排除
    - gov.cn 门户等误留候选交给上层探测验证过滤
    - lookup: 可传入已取好的 (text, hosts)，避免重复请求搜索引擎
    """
    text, hosts = lookup if lookup else search_engine_lookup(name)
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


# ----------------------------------------------------------------------------
# 扩展被动源（全部免费、无 Key、查第三方不触碰目标）：
# Wayback 历史快照 / OTX 被动 DNS / urlscan 历史扫描 / 搜索引擎 site: 语法 /
# 搜索引擎备案号反查（无 Key 时唯一的 A 级证据来源）
# ----------------------------------------------------------------------------
def wayback_subdomains(domain, timeout=25):
    """Wayback CDX 历史 URL 提取子域。

    历史快照里埋着已下线/改名的子域——crt.sh 只能看到签过证书的，
    Wayback 能看到曾经被收录访问过的，两者互补。
    """
    subs = set()
    try:
        url = ("http://web.archive.org/cdx/search/cdx?url=*.%s&output=json"
               "&fl=original&collapse=urlkey&limit=2000" % domain)
        txt = http_get(url, timeout=timeout, retries=1)
        data = json.loads(txt)
        for row in (data[1:] if isinstance(data, list) else []):
            if not row:
                continue
            m = re.match(r"[a-zA-Z]+://([^/:?]+)", str(row[0]))
            if m:
                h = m.group(1).strip(".").lower()
                if h == domain or h.endswith("." + domain):
                    subs.add(h)
    except Exception:
        pass
    return subs


def otx_subdomains(domain, timeout=25):
    """AlienVault OTX 被动 DNS 子域（免费开放 API）。"""
    subs = set()
    try:
        url = ("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
               % urllib.parse.quote(domain))
        txt = http_get(url, timeout=timeout, retries=1)
        data = json.loads(txt)
        for e in data.get("passive_dns", []) or []:
            h = str(e.get("hostname", "")).strip().lower().rstrip(".")
            if h == domain or h.endswith("." + domain):
                subs.add(h)
    except Exception:
        pass
    return subs


def urlscan_subdomains(domain, timeout=25):
    """urlscan.io 历史扫描记录提取子域（免费搜索 API）。

    能捞到没备案、没证书、但被人扫描过的站——与 CT 日志互补。
    """
    subs = set()
    try:
        url = ("https://urlscan.io/api/v1/search/?q=domain:%s&size=1000"
               % urllib.parse.quote(domain))
        txt = http_get(url, timeout=timeout, retries=1)
        data = json.loads(txt)
        for r in data.get("results", []) or []:
            page = (r.get("page") or {})
            h = str(page.get("domain", "")).strip().lower().rstrip(".")
            if h == domain or h.endswith("." + domain):
                subs.add(h)
    except Exception:
        pass
    return subs


def bing_site_subdomains(domain):
    """搜索引擎 site: 语法反查已收录子域（免费无 Key）。"""
    text, hosts = search_engine_lookup("site:" + domain)
    out = set()
    for h in hosts:
        h = (h or "").lower().rstrip(".")
        if h == domain or h.endswith("." + domain):
            out.add(h)
    for m in _DOMAIN_IN_TEXT_RE.finditer(text):
        h = m.group(1).lower()
        if h == domain or h.endswith("." + domain):
            out.add(h)
    return out


def certspotter_subdomains(domain, timeout=25):
    """CertSpotter CT 日志子域（免费无 Key）。

    与 crt.sh 互补——实测能挖到 crt.sh 组织名查询漏掉的证书
    （如只出现在 SAN 列表里的移动端子站）。
    """
    subs = set()
    try:
        url = ("https://api.certspotter.com/v1/issuances?domain=%s"
               "&include_subdomains=true&expand=dns_names" % urllib.parse.quote(domain))
        data = json.loads(http_get(url, timeout=timeout, retries=1))
        for e in data or []:
            for n in e.get("dns_names", []) or []:
                n = str(n).strip().lower().lstrip("*.")
                if n == domain or n.endswith("." + domain):
                    subs.add(n)
    except Exception:
        pass
    return subs


def shodan_internetdb(ip, timeout=15):
    """Shodan InternetDB 免费情报（无 Key）：历史扫描的端口/主机名/CPE/CVE。

    端口是 Shodan 历史扫描结果（被动测绘，非实时——需人工复核）；
    该 IP 无数据时返回 None（404 语义）。
    """
    try:
        txt = http_get("https://internetdb.shodan.io/%s" % ip,
                       timeout=timeout, retries=1)
        data = json.loads(txt)
        if isinstance(data, dict) and data.get("ports"):
            return data
    except Exception:
        pass
    return None


def rapiddns_sameip(ip, timeout=20):
    """RapidDNS 同 IP 域名反查（免费 HTML）——hackertarget 反查的互补源。

    返回该 IP 历史解析过的全部域名（含共享托管的邻居，归属交由分级判定）。
    """
    hosts = set()
    try:
        html = http_get("https://rapiddns.io/s/%s" % ip, timeout=timeout, retries=1)
        for m in re.finditer(r"([a-zA-Z0-9][a-zA-Z0-9\-\.]{1,62}\.(?:com|net|org|cn|gov|edu|info|xyz|top|vip|cc|hk|mo|tw)(?:\.cn)?)", html):
            h = m.group(1).lower()
            if root_domain(h) == "rapiddns.io":
                continue
            hosts.add(h)
    except Exception:
        pass
    return hosts


def _gather_subdomain_sources(domain, timeout=25):
    """并行跑全部无 Key 被动子域源（平台间互不阻塞，任一失败不影响其它）。

    返回 {源名: 结果}；hackertarget 返回 dict(host->ip)，其余返回 set(host)。
    """
    jobs = (
        ("crt.sh", lambda: crt_subdomains(domain, timeout=timeout)),
        ("hackertarget", lambda: hackertarget_hostsearch(domain, timeout=timeout)),
        ("rapiddns", lambda: rapiddns_subdomains(domain, timeout=timeout)),
        ("certspotter", lambda: certspotter_subdomains(domain, timeout=timeout)),
        ("wayback历史", lambda: wayback_subdomains(domain, timeout=timeout)),
        ("OTX被动DNS", lambda: otx_subdomains(domain, timeout=timeout)),
        ("urlscan历史", lambda: urlscan_subdomains(domain, timeout=timeout)),
        ("搜索引擎site:", lambda: bing_site_subdomains(domain)),
    )
    out = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        futs = {ex.submit(fn): name for name, fn in jobs}
        for f in as_completed(futs):
            name = futs[f]
            try:
                out[name] = f.result()
            except Exception:
                out[name] = set() if name != "hackertarget" else {}
    return out


def itunes_search_apps(name, country="cn", limit=15):
    """Apple App Store 搜索 API（免费、无 Key、JSON）——移动端 APP 发现。

    返回原始结果列表 [{trackName, sellerName, bundleId, version, sellerUrl}, ...]；
    归属过滤由 Engine.discover_apps 做（应用名/开发者/地域行业词互证）。
    """
    try:
        url = ("https://itunes.apple.com/search?term=%s&country=%s"
               "&entity=software&limit=%d"
               % (urllib.parse.quote(name), country, limit))
        data = json.loads(http_get(url, timeout=15, retries=1))
        out = []
        for a in data.get("results", []) or []:
            if not isinstance(a, dict):
                continue
            out.append({
                "trackName": str(a.get("trackName") or ""),
                "sellerName": str(a.get("sellerName") or ""),
                "bundleId": str(a.get("bundleId") or ""),
                "version": str(a.get("version") or ""),
                "sellerUrl": str(a.get("sellerUrl") or ""),
                "trackViewUrl": str(a.get("trackViewUrl") or ""),
            })
        return out
    except Exception:
        return []


_SECTOR_EN = {
    "移动": "mobile", "电信": "telecom", "联通": "unicom", "银行": "bank",
    "医院": "hospital", "保险": "insurance", "邮政": "post", "电力": "power",
    "大学": "university", "学校": "school", "集团": "group",
}


def _seller_match(name, seller):
    """中文单位名 ↔ 英文开发者名（App Store 的 sellerName 常是英文）。

    地域拼音 + 行业英文词双重核验：四川移动 ↔ "China Mobile Group Sichuan ..."。
    """
    s = (seller or "").lower()
    if not s:
        return False
    prov_ok = any(c in s for prov, codes in PROVINCE_CODES.items()
                  if prov in name for c in codes if len(c) > 2)
    sec_ok = any(en in s for zh, en in _SECTOR_EN.items() if zh in name)
    return prov_ok and sec_ok


def bing_exact_hosts(query):
    """搜索引擎精确短语查询 → 命中的站点主机列表（滤掉搜索引擎/聚合站）。

    备案号反查、统一社会信用代码反查共用此通道（文档 7.2 的 A 级证据线）。
    """
    text, hosts = search_engine_lookup(query)
    out = []
    seen = set()
    for h in hosts:
        h = (h or "").lower().rstrip(".")
        if not h or "_" in h or h in seen:
            continue
        seen.add(h)
        root = root_domain(h)
        if root in SEARCH_JUNK_ROOTS or h in SEARCH_JUNK_ROOTS:
            continue
        out.append(h)
    return out


def bing_beian_search(beian):
    """搜索引擎搜备案号：页面里印着同一备案号的站点（A 级证据线索）。

    对应方法论文档的"备案号是最强反查钥匙"——拿到锚点备案号后反查，
    能找到所有底部印着这个号的站点（含平台未收录的），误报极低。
    """
    return bing_exact_hosts('"%s"' % beian)


def weixin_article_domains(name, max_articles=3):
    """搜索引擎找公众号文章（site:mp.weixin.qq.com）并提取文中外部域名。"""
    urls = [u for u in bing_dork_urls('site:mp.weixin.qq.com "%s"' % name)
            if _url_host(u) == "mp.weixin.qq.com"][:max_articles]
    domains = []
    for u in urls:
        try:
            body = http_get(u, timeout=12, retries=0, max_bytes=512 * 1024)
            domains.extend(m.group(1) for m in _DOMAIN_IN_TEXT_RE.finditer(body))
        except Exception:
            continue
    return filter_candidate_roots(domains)


def bing_dork_urls(query):
    """搜索引擎 dork 查询 → 有机结果完整 URL 列表（风险情报用，不触碰目标）。"""
    try:
        url = ("https://cn.bing.com/search?q=" + urllib.parse.quote(query)
               + "&count=20&mkt=zh-CN")
        html = http_get(url, timeout=15, retries=1,
                        headers={"Accept": "text/html, */*", "User-Agent": UA})
        return re.findall(r'<h2><a[^>]+href="(https?://[^"]+)"', html)
    except Exception:
        return []


def _url_host(u):
    """提取 URL 主机名（小写，去端口）；解析失败返回空串。"""
    m = re.match(r"[a-zA-Z]+://([^/:?#]+)", u or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _asset_url(a):
    """按资产 scheme/端口拼出可访问的 Web URL（非 Web 资产返回空串）。"""
    if not a or not a.host:
        return ""
    p = int(a.port) if a.port else None
    scheme = a.scheme or ("https" if p in (443, 8443, 9443) else "http" if p else "")
    if not scheme:
        return ""
    host = a.host if ":" not in a.host else "[%s]" % a.host
    suffix = "" if p in (None, 80, 443) else ":%d" % p
    return "%s://%s%s" % (scheme, host, suffix)


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
                 "prov_org", "reject_reason", "urls", "findings", "credit_code")

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
        self.findings = set()     # 敏感路径发现 ["路径|说明", ...]
        self.credit_code = ""     # 页面含有的统一社会信用代码

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
    for s in ("source", "providers", "prov_kinds", "urls", "findings"):
        getattr(dst, s).update(getattr(src, s))
    for s in ("ip", "title", "server", "scheme", "status", "beian", "prov_beian",
              "prov_cert", "prov_org", "cert_org", "cert_san", "analytics",
              "favicon", "credit_code"):
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


def grab_banner(ip, port, timeout=3):
    """端口 Banner 抓取：轻量服务识别（借鉴 Goby/ARL 的服务版本识别）。

    不依赖 nmap：对 Web 端口发 HEAD，对 Redis 发 PING，其余直接读欢迎语
    （SSH/FTP/SMTP/MySQL 等都会主动吐版本横幅）。返回首行文本或空串。
    """
    # 协议探针（借鉴 Goby 的服务识别）：发送最小协议请求读回版本信息
    def _http_get_probe(ip):
        return ("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" % ip).encode()

    # MongoDB isMaster（OP_QUERY admin.$cmd）
    mongo_ismaster = (b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
                      b"\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00"
                      b"\x10isMaster\x00\x01\x00\x00\x00\x00")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8000, 8008, 8080, 8081, 8088, 888, 8888, 9000):
                s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
            elif port in (9200, 2375, 5601, 3000):
                s.sendall(_http_get_probe(ip))       # Elasticsearch/Docker/Monitoring
            elif port == 6379:
                s.sendall(b"*1\r\n$4\r\nPING\r\n")   # Redis
            elif port == 11211:
                s.sendall(b"stats\r\n")              # Memcached
            elif port == 27017:
                s.sendall(mongo_ismaster)            # MongoDB
            elif port == 3306:
                pass                                 # MySQL 主动发握手包
            try:
                data = s.recv(768)
            except socket.timeout:
                return ""
            text = data.decode("utf-8", "replace")
            text = "".join(ch if ch.isprintable() else " " for ch in text)
            text = " ".join(text.split())
            return text[:120]
    except Exception:
        return ""


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
# 敏感路径探测（授权渗透信息收集：泄露面检查）
#
# 设计原则：
# 1. 每条路径都带**内容验证**——只看 200 状态码会被全站自定义 404 页骗，
#    必须检查响应体特征（git 配置的 [core]、env 的 KEY=VALUE、zip 的 PK 魔数等）。
# 2. 高信噪比精选而非大字典：每条都是渗透实测高频命中项。
# 3. 属于主动触碰目标：仅 active/verify 模式对已存活的 Web 资产执行。
# ----------------------------------------------------------------------------

def _chk_git(b):
    return b"[core]" in b


def _chk_svn(b):
    return len(b) > 0 and (b[:1].isdigit() or b[:4] == b"dir ")  # svn entries 格式


def _chk_env(b):
    return re.search(rb"^[A-Z_]{3,}=.{3,}", b, re.M) is not None


def _chk_actuator(b):
    return b"_links" in b or b"management" in b[:2000].lower()


def _chk_actuator_env(b):
    return b"propertySources" in b or b"activeProfiles" in b


def _chk_heapdump(b):
    # Java 堆转储魔数 "\x00JAVA PROFILE..."，且确实有体积
    return b"JAVA PROFILE" in b[:32] and len(b) > 4096


def _chk_swagger(b):
    return b"swagger" in b.lower()


def _chk_apidocs(b):
    return b"swagger" in b.lower() or b'"paths"' in b


def _chk_druid(b):
    return b"druid" in b.lower()


def _chk_serverstatus(b):
    return b"Apache Status" in b or b"server-status" in b.lower()


def _chk_phpinfo(b):
    return b"PHP Version" in b or b"phpinfo" in b.lower()


def _chk_h2(b):
    return b"H2 Console" in b or b"h2-console" in b.lower()


def _chk_zip(b):
    # zip 魔数 PK\x03\x04，且 >2KB（排除巧合的小文件/错误页）
    return b[:4] == b"PK\x03\x04" and len(b) > 2048


def _chk_rar(b):
    return b[:4] == b"Rar!" and len(b) > 2048


def _chk_targz(b):
    return b[:2] == b"\x1f\x8b" and len(b) > 2048


def _chk_sql(b):
    return (b"CREATE TABLE" in b[:4096] or b"INSERT INTO" in b[:4096]) and len(b) > 1024


SENSITIVE_PATHS = (
    ("/.git/config",          "Git仓库泄露(.git)",       _chk_git),
    ("/.svn/entries",         "SVN仓库泄露(.svn)",       _chk_svn),
    ("/.env",                 "环境配置泄露(.env)",       _chk_env),
    ("/actuator",             "Spring Actuator暴露",      _chk_actuator),
    ("/actuator/env",         "Spring环境信息泄露",       _chk_actuator_env),
    ("/actuator/heapdump",    "Java堆转储可下载",         _chk_heapdump),
    ("/swagger-ui.html",      "Swagger文档暴露",          _chk_swagger),
    ("/swagger-ui/index.html", "Swagger文档暴露",         _chk_swagger),
    ("/v2/api-docs",          "API接口文档泄露",          _chk_apidocs),
    ("/druid/index.html",     "Druid监控台暴露",          _chk_druid),
    ("/server-status",        "Apache状态页暴露",         _chk_serverstatus),
    ("/phpinfo.php",          "phpinfo信息泄露",          _chk_phpinfo),
    ("/h2-console",           "H2数据库控制台暴露",       _chk_h2),
    ("/web.zip",              "站点备份文件(web.zip)",    _chk_zip),
    ("/www.zip",              "站点备份文件(www.zip)",    _chk_zip),
    ("/backup.zip",           "站点备份文件(backup.zip)", _chk_zip),
    ("/site.zip",             "站点备份文件(site.zip)",   _chk_zip),
    ("/web.rar",              "站点备份文件(web.rar)",    _chk_rar),
)


def probe_sensitive_paths(host, port, scheme, timeout=6, interval=0.1):
    """对单个 Web 资产探测敏感路径，返回命中的 [(路径, 说明), ...]。

    每个请求间 sleep(interval) 控制节奏；异常静默（探测目标不在线/超时属常态）。
    """
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base = "%s://%s" % (scheme, host)
    else:
        base = "%s://%s:%d" % (scheme, host, port)
    # 动态备份路径：按域名主体名生成（dggcyy.zip / dggcyy.sql 这类域名同名备份包）
    extra = []
    label = root_domain(host).split(".")[0] if root_domain(host) else ""
    if label and len(label) >= 3 and label not in ("www", "com", "net", "org"):
        for ext, chk in ((".zip", _chk_zip), (".rar", _chk_rar),
                         (".tar.gz", _chk_targz), (".sql", _chk_sql)):
            extra.append(("/%s%s" % (label, ext),
                          "域名同名备份(%s%s)" % (label, ext), chk))
    hits = []
    for path, name, check in tuple(SENSITIVE_PATHS) + tuple(extra):
        try:
            # 泄露文件可能较大（heapdump/备份包），但只需头部判断特征，限 256KB
            data = http_get(base + path, timeout=timeout, retries=0,
                            binary=True, max_bytes=256 * 1024)
            if check(data):
                hits.append((path, name))
        except Exception:
            pass
        if interval:
            time.sleep(interval)
    return hits


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
                       "weak_domains": set(), "credit_codes": set()}
        self.ip_notes = {}        # ip -> info dict
        self.provider_records = []
        self.provider_stats = {}
        self.risk_hints = []      # 搜索引擎情报线索 [(类别, url), ...]
        self._ref_candidates = [] # 页面外链/JS 引用的域名（待互证候选）
        self.apps = []            # 移动端 APP 资产 [(名称, 开发者, 包名, 归属依据), ...]
        self.contacts = set()     # 页面/摘要提取的联系邮箱
        self._beian_candidates = set()  # 搜索摘要备案号候选（需自验证才升级）
        self._code_candidates = set()   # 搜索摘要信用代码候选（需自验证才升级）
        self._js_urls = []              # 待扫描的外部 JS 地址（JSFinder 思路）
        self.js_secrets = []            # JS 敏感信息 [(url, 类型), ...]
        self.ext_hits = []              # 外部工具 nuclei 命中 [(模板, 级别, 名称, 位置), ...]
        self.ext_used = {}              # 本轮实际调用的外部工具 {名称: 路径}
        self.ext_detected = set()       # 本机检测到的外部工具（含本轮未调用的）
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
    def _absorb_search_text(self, text):
        """从搜索引擎摘要吸收线索：备案号 / 信用代码（候选） / 联系邮箱。

        注意：搜索摘要里出现的备案号/信用代码可能是**目录站自己的**
        （求医网/博禾等聚合页同时提到单位名和它们自己的备案号），
        直接当锚点会污染确认清单——所以只进 _beian_candidates /
        _code_candidates 候选集，等 collect_passive 里用"反查结果包含
        已知域名"自验证通过后才升级为正式锚点。
        """
        for m in BEIAN_RE.finditer(text or ""):
            b = m.group(1)
            if _beian_key(b) and b not in self.anchor["beian"]:
                self._beian_candidates.add(b)
                log("搜索摘要备案号候选（待验证）: %s" % b)
        code = extract_credit_code(text)
        if code and code not in self.anchor["credit_codes"]:
            self._code_candidates.add(code)
            log("搜索摘要信用代码候选（待验证）: %s" % code)
        for e in _extract_emails(text):
            self.contacts.add(e)

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
                lookup = search_engine_lookup(name)
                self._absorb_search_text(lookup[0])
                cands = discover_domains_from_search(name, max_candidates=3, lookup=lookup)
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
            # 搜索多轮：候选域名 + 摘要里的备案号/信用代码/邮箱（A 级锚点）。
            # - name+"官网"：简称/短名提高官网命中率
            # - name+"ICP备案"：从备案信息页摘要吸收备案号（ENscan 备案维度的免费等效）
            lookups = [search_engine_lookup(name)]
            if len(name) <= 6:
                lookups.append(search_engine_lookup(name + " 官网"))
            lookups.append(search_engine_lookup(name + " ICP备案"))
            text = " ".join(t for t, _ in lookups)
            hosts = [h for _, hs in lookups for h in hs]
            lookup = (text, hosts)
            self._absorb_search_text(text)
            if len(name) <= 4:
                log("提示：检测到简称（%s），搜索引擎对简称的收录命中率低于全称；"
                    "若结果不全，请改用全称重试（如\"中国移动通信集团四川有限公司\"）。" % name, "!")
            cands = discover_domains_from_search(name, lookup=lookup)
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
        """探测候选域名首页，标题 / 证书 O= / 统一社会信用代码 任一互证即通过。

        互证对象 = 主体名称 ∪ 锚点组织名（纯域名输入时也能用证书 O= 印证）。
        匹配用严格子串 OR 简称宽松匹配（bigram 覆盖率）——"四川移动"这类
        简称能匹配到"中国移动通信集团四川有限公司"，避免简称场景整体失效。
        """
        anchor_codes = set(self.anchor.get("credit_codes") or ())
        names = set(self.names) | set(self.anchor.get("orgs") or ())

        def _hit(text):
            return any(n and (_org_match(n, text) or _org_match_fuzzy(n, text))
                       for n in names)

        for scheme, port in (("https", 443), ("http", 80)):
            info = http_probe(dom, port, scheme, timeout=self.args.timeout)
            if info.get("status") in ("", None):
                continue
            # 标题 + meta 描述一起验证（SPA 站标题常为空，单位名在 description 里）
            page_text = (info.get("title") or "") + " " + (info.get("meta") or "")
            if _hit(page_text):
                self._add_verified_domain(dom)
                return True
            # 地域拼音互证 + 行业词核验：四川移动 ↔ sc.10086.cn（页面须含"移动"）
            if any(n and _region_hit(n, dom, page_text) for n in names):
                self._add_verified_domain(dom)
                return True
            # 页面含锚点信用代码：文档 7.2 的 A 级证据，直接确认
            if info.get("credit_code") and info["credit_code"] in anchor_codes:
                self._add_verified_domain(dom)
                return True
            if scheme == "https":
                cert = tls_cert_info(dom, port, timeout=self.args.timeout)
                org = (cert or {}).get("org", "")
                if org and _hit(org):
                    self._add_verified_domain(dom)
                    return True
        return False

    def _add_verified_domain(self, dom):
        """验证通过的域名：主机名入锚点，并按深度补充上级域用于子域枚举。

        - www.x.cn（深度 1）→ 补根域 x.cn：子域枚举按根域查才全
        - wap.sc.10086.cn（深度 2）→ 只补 sc.10086.cn，**不补根域 10086.cn**：
          根域是整个移动集团的（各省公司共用），当锚点会把全国资产都卷进来
        """
        self.domains.add(dom)
        root = root_domain(dom)
        if not root or root == dom:
            return
        depth = dom.count(".") - root.count(".")
        if depth <= 1:
            self.domains.add(root)
        else:
            parent = dom.split(".", 1)[1]   # 去掉最左标签：wap.sc.10086.cn → sc.10086.cn
            if parent and parent != root:
                self.domains.add(parent)

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
                if a.credit_code:
                    self.anchor["credit_codes"].add(a.credit_code)
                    log("  锚点统一社会信用代码: %s" % a.credit_code, "+")
                for ref in (info.get("refs") or []):
                    self._ref_candidates.append(ref)
                self.contacts.update(info.get("emails") or [])
                self._js_urls.extend(info.get("scripts") or [])
                self._apply_waf(a, info.get("waf", ""))
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

        # 域名 -> 子域名（8 个免费被动源并行聚合）
        for d in list(dict.fromkeys(domains)):
            log("子域名收集: %s" % d)
            srcs = _gather_subdomain_sources(d, timeout=self.args.timeout)
            ht = {}
            allsubs = set()
            for name, items in srcs.items():
                if items:
                    log("  %s 得到 %d 个" % (name, len(items)))
                if isinstance(items, dict):
                    ht.update(items)
                    allsubs |= set(items)
                else:
                    allsubs |= set(items)
            # 小字典子域枚举（ksubdomain 思路，只做 DNS 解析不碰端口）
            if not getattr(self.args, "no_brute", False) and d not in self.anchor["weak_domains"]:
                bt = brute_subdomains(d)
                if bt:
                    log("  DNS字典 得到 %d 个" % len(bt))
                    ht.update(bt)
                    allsubs |= set(bt)
            allsubs.add(d)
            if len(allsubs) > 500:
                log("  子域过多（%d），仅取前 500 个（大集团域名常见）" % len(allsubs), "!")
                allsubs = set(sorted(allsubs)[:500])
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

        # 备案号反查（搜索引擎免费通道）：锚点备案号 → 页脚印着同一备案号的站点。
        # 无平台 Key 时唯一的 A 级证据来源；对疑似候选交由 evaluate 的备案号
        # 主号比较把关（垃圾值提取不出主号不会命中）。
        for b in sorted(set(self.anchor["beian"])):
            hosts = bing_beian_search(b)
            if hosts:
                log("备案号反查(%s): 搜索引擎命中 %d 个站点" % (b, len(hosts)), "+")
                for h in hosts:
                    a = self.add_asset(h, None, None, source="search:beian")
                    if not a.prov_beian:
                        a.prov_beian = b

        # 摘要候选备案号/信用代码自验证：反查结果必须包含已知域名才升级为锚点。
        # 搜索摘要里常混入目录站（求医网/博禾等）自己的备案号——直接采信会把
        # 目录站当目标资产（锚点污染）；反查无已知域名 = 疑似别人的号，丢弃。
        def _hosts_known(hosts):
            for h in hosts:
                for d in self.domains:
                    if d and (h == d or h.endswith("." + d)):
                        return True
            return False

        for b in sorted(self._beian_candidates):
            if b in self.anchor["beian"]:
                continue
            hosts = bing_beian_search(b)
            if _hosts_known(hosts):
                self.anchor["beian"].add(b)
                log("摘要备案号候选验证通过（反查含已知域名）: %s" % b, "+")
                for h in hosts:
                    a = self.add_asset(h, None, None, source="search:beian")
                    if not a.prov_beian:
                        a.prov_beian = b
            else:
                log("摘要备案号候选未通过自验证（反查无已知域名，疑似目录站备案）: %s"
                    % b, "!")

        for code in sorted(self._code_candidates):
            if code in self.anchor["credit_codes"]:
                continue
            hosts = bing_exact_hosts('"%s"' % code)[:5]
            if _hosts_known(hosts):
                self.anchor["credit_codes"].add(code)
                log("摘要信用代码候选验证通过: %s" % code, "+")
            else:
                log("摘要信用代码候选未通过自验证: %s" % code, "!")

        # 统一社会信用代码反查（A 级证据，无 Key 通道）：锚点代码 → 搜索引擎
        # 找提到该代码的站点 → 探测首页确认页面真的含此代码 → 入正式锚点
        for code in sorted(set(self.anchor["credit_codes"])):
            hosts = bing_exact_hosts('"%s"' % code)[:5]
            if not hosts:
                continue
            log("信用代码反查(%s): 搜索引擎候选 %d 个，逐个探测验证" % (code, len(hosts)))
            for h in hosts:
                if h in self.domains:
                    continue
                for scheme, port in (("https", 443), ("http", 80)):
                    info = http_probe(h, port, scheme, timeout=self.args.timeout)
                    if info.get("status") in ("", None):
                        continue
                    if info.get("credit_code") == code:
                        self._add_verified_domain(h)
                        log("  信用代码验证通过: %s" % h, "+")
                        break

        # IP 反查（输入 IP ∪ 锚点域名 IP——目标自己的 IP 也要做反查/情报）
        all_ips = set(self.input_ips) | set(self.anchor["ips"])
        for ip in sorted(all_ips):
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
            # RapidDNS 同 IP 反查（hackertarget 反查的互补源，含历史解析）
            same = rapiddns_sameip(ip)
            if same:
                log("  RapidDNS同IP 得到 %d 个域名" % len(same), "+")
                for h in same:
                    a = self.add_asset(h, None, None, source="rapiddns:sameip:%s" % ip)
                    a.ip = ip
            # Shodan InternetDB 免费情报：历史扫描的端口/主机名/CPE/CVE（无 Key）
            idb = shodan_internetdb(ip)
            if idb:
                for h in idb.get("hostnames", []) or []:
                    h = str(h).strip().lower().rstrip(".")
                    if h and h not in self.sub_map:
                        self.sub_map[h] = ip
                        self.add_asset(h, None, None, source="inetdb:%s" % ip, ip=ip)
                for p in idb.get("ports", []) or []:
                    scheme = "https" if p in (443, 8443, 9443) else "http"
                    self.add_asset(ip, p,
                                   scheme if is_web_port(p) else None,
                                   source="inetdb:%s" % ip, ip=ip)
                self.ip_notes.setdefault(ip, {})
                self.ip_notes[ip]["cpes"] = idb.get("cpes", [])
                self.ip_notes[ip]["vulns"] = idb.get("vulns", [])
                log("  InternetDB 历史: 端口 %s%s" % (
                    ",".join(str(p) for p in sorted(idb["ports"])[:15]),
                    (" | 漏洞记录: %s" % ", ".join(idb["vulns"][:8])) if idb.get("vulns") else ""), "!")
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
                # 非 Web 服务抓 Banner 识别（SSH/Redis/MySQL 等）
                if not is_web_port(p):
                    banner = grab_banner(ip, p, timeout=self.args.scan_timeout)
                    if banner:
                        a.tech = (a.tech + "," if a.tech else "") + banner[:60]
                        log("  %s:%d Banner: %s" % (ip, p, banner[:80]))

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
                a.credit_code = info.get("credit_code", "") or a.credit_code
                a.analytics = info.get("analytics", "") or a.analytics
                a.favicon = info.get("favicon", "") or a.favicon
                for ref in (info.get("refs") or []):
                    self._ref_candidates.append(ref)
                self.contacts.update(info.get("emails") or [])
                self._js_urls.extend(info.get("scripts") or [])
                self._apply_waf(a, info.get("waf", ""))
                if cert:
                    a.cert_org = cert.get("org", "")
                    a.cert_san = ",".join(cert.get("sans", [])[:20])
                # 注意：探测到的备案号/统计ID/favicon 只作为该资产自身证据，
                # 不再回填到全局锚点，避免"任取一个第三方站点当锚点"的自我印证误报。

    # ---- 3.5 敏感路径探测（授权渗透信息收集） ----
    def probe_sensitive(self, limit=200):
        """对已存活的 Web 资产探测敏感路径（.git/.env/Actuator/Swagger/备份包等）。

        结果挂到 Asset.findings，不参与归属分级（泄露是资产内容信息，不是归属证据）。
        """
        log("== 敏感路径探测（%d 条规则）==" % len(SENSITIVE_PATHS), "#")
        targets = []
        for a in self.assets.values():
            if not a.host or not a.port:
                continue
            if is_web_port(int(a.port)) and a.status:
                targets.append(a)
        if limit and len(targets) > limit:
            log("Web 资产过多（%d），仅探测前 %d 个" % (len(targets), limit), "!")
            targets = targets[:limit]
        log("待探测 Web 资产: %d" % len(targets))
        interval = getattr(self.args, "probe_interval", 0) or 0

        def _job(a):
            scheme = a.scheme or ("https" if int(a.port) in (443, 8443, 9443) else "http")
            hits = probe_sensitive_paths(a.host, int(a.port), scheme,
                                         timeout=self.args.timeout,
                                         interval=max(0.05, interval / 2.0 or 0.05))
            return a, hits

        found = 0
        with ThreadPoolExecutor(max_workers=max(1, min(self.args.threads, 8))) as ex:
            futs = [ex.submit(_job, a) for a in targets]
            for f in as_completed(futs):
                try:
                    a, hits = f.result()
                except Exception:
                    continue
                for path, name in hits:
                    a.findings.add("%s|%s" % (path, name))
                if hits:
                    found += 1
                    log("  [!] %s:%s 敏感发现: %s" % (
                        a.host, a.port, "、".join(n for _, n in hits)), "!")
        log("敏感路径探测完成：%d/%d 个资产存在敏感发现" % (found, len(targets)),
            "+" if found else "*")

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
            if a.credit_code and a.credit_code in self.anchor["credit_codes"]:
                ev.append("A|页面含统一社会信用代码:%s" % a.credit_code)
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
                if "search:beian" in a.source:
                    ev.append("A|搜索引擎备案号命中:%s" % a.prov_beian)
                else:
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

    # ---- 4.5 增量监控（基线对比 + 新资产告警） ----
    BASELINE_NAME = "baseline.json"

    def _merge_placeholders(self):
        """合并"仅主机"占位资产（被动阶段 host-only 条目）到同主机的带端口资产。

        否则报告里同一主机会出现一行"无端口无标题"的重复行；
        基线对比也必须先做这一步，否则占位键会造成"新增+下线"误报。
        幂等：无占位资产时无操作。
        """
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

    def _baseline_path(self):
        return os.path.join(self.args.out, self.BASELINE_NAME)

    def _fingerprint(self, a):
        """资产指纹（基线对比的稳定字段）。"""
        return {
            "ip": a.ip or "",
            "confidence": a.confidence,
            "title": (a.title or "")[:80],
            "tech": a.tech or "",
            "findings": sorted(a.findings),
        }

    def load_baseline(self):
        """读上一轮基线；不存在/损坏返回 None。"""
        try:
            with open(self._baseline_path(), "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def diff_baseline(self):
        """与输出目录中的上一轮基线对比，返回 diff dict（无基线返回 None）。

        diff = {"prev_ts":..., "added": [...], "removed": [...],
                "changed": [{"key":..., "changes": ["新敏感发现: ...", ...]}]}
        """
        base = self.load_baseline()
        if not base or not base.get("assets"):
            return None
        self._merge_placeholders()
        prev = base["assets"]
        cur = {}
        for a in self.assets.values():
            if a.host:
                cur["%s|%s" % (a.host.lower(), a.port or "")] = self._fingerprint(a)
        diff = {"prev_ts": base.get("ts", "?"), "added": [], "removed": [], "changed": []}
        for k in sorted(set(cur) - set(prev)):
            diff["added"].append((k, cur[k]))
        for k in sorted(set(prev) - set(cur)):
            diff["removed"].append((k, prev[k]))
        for k in sorted(set(cur) & set(prev)):
            changes = []
            if cur[k]["confidence"] != prev[k]["confidence"]:
                changes.append("分级 %s → %s" % (prev[k]["confidence"], cur[k]["confidence"]))
            for f, label in (("title", "标题"), ("tech", "指纹")):
                if cur[k][f] != prev[k][f] and (cur[k][f] or prev[k][f]):
                    changes.append("%s变化" % label)
            new_findings = set(cur[k]["findings"]) - set(prev[k]["findings"])
            for fd in sorted(new_findings):
                changes.append("新敏感发现: %s" % fd.split("|", 1)[-1])
            if changes:
                diff["changed"].append({"key": k, "changes": changes})
        # 日志告警（报告里也会写一节）
        n = len(diff["added"]) + len(diff["removed"]) + len(diff["changed"])
        if n:
            log("== 增量对比（基线 %s）==" % diff["prev_ts"], "#")
            for k, fp in diff["added"]:
                log("  [新增] %s（%s）" % (k, fp["confidence"]), "+")
            for c in diff["changed"]:
                log("  [变化] %s：%s" % (c["key"], "；".join(c["changes"])), "!")
            for k, fp in diff["removed"]:
                log("  [下线] %s" % k, "-")
        return diff if n else None

    def save_baseline(self):
        """把本轮资产指纹写为基线（固定文件名，每轮覆盖）。"""
        try:
            self._merge_placeholders()
            os.makedirs(self.args.out, exist_ok=True)
            snap = {
                "ts": datetime.now().strftime("%Y%m%d_%H%M%S"),
                "assets": {"%s|%s" % ((a.host or "").lower(), a.port or ""): self._fingerprint(a)
                           for a in self.assets.values() if a.host},
            }
            with open(self._baseline_path(), "w", encoding="utf-8") as f:
                json.dump(snap, f, ensure_ascii=False, indent=1)
        except Exception as e:
            log("基线保存失败: %s" % str(e)[:80], "!")

    # ---- 4.7 搜索引擎风险情报（dork，不触碰目标） ----
    def collect_risk_hints(self, max_domains=3):
        """对主体域名做搜索引擎 dork 情报收集（文档第9步：谷歌语法 + GitHub）。

        只列线索不作为资产：后台入口 / GitHub 代码泄露是后续人工渗透的方向标。
        查询走第三方搜索引擎，不访问目标。
        """
        if not self.domains:
            return
        strong = sorted(set(self.anchor["domains"]) - set(self.anchor["weak_domains"]))
        targets = (strong or sorted(self.domains))[:max_domains]
        seen = set()
        for d in targets:
            for kind, query, check in (
                    ("后台/登录入口", "site:%s (inurl:admin OR inurl:login)" % d,
                     lambda u, d=d: _url_host(u).endswith("." + d) or _url_host(u) == d),
                    ("GitHub代码泄露", 'site:github.com "%s"' % d,
                     lambda u: "github.com" in _url_host(u)),
            ):
                time.sleep(0.8)   # 引擎节奏
                n0 = len(self.risk_hints)
                for u in bing_dork_urls(query):
                    if u in seen:
                        continue
                    # Bing 的 site: 语法会漏进无关域名的结果，逐条校验归属
                    try:
                        if not check(u):
                            continue
                    except Exception:
                        continue
                    seen.add(u)
                    self.risk_hints.append((kind, u))
                if len(self.risk_hints) > n0:
                    log("dork情报(%s): %s 命中 %d 条" % (kind, d, len(self.risk_hints) - n0), "+")

    # ---- 4.8 公众号/页面外链域名挖掘（文档阶段六 + 5.2 前端深挖） ----
    def mine_weixin_domains(self, max_articles=3):
        """公众号文章 → 外部域名（文档阶段六）。

        公众号菜单/文章常挂 H5 活动页、挂号/查询系统等独立域名，这些域名
        往往不在主站上。文章经搜索引擎收录检索（best-effort：小单位常无
        收录，引擎降级返回无关结果会被域名校验自然过滤，零成本跳过）。
        候选域名仍需标题/证书/信用代码互证才入锚点。
        """
        if not self.names:
            return
        for name in self.names:
            roots = weixin_article_domains(name, max_articles=max_articles)
            if not roots:
                continue
            log("公众号文章挖掘(%s): %d 个候选域名" % (name, len(roots)))
            for root in roots:
                if root in self.domains:
                    continue
                if self._verify_candidate_domain(name, root):
                    log("  公众号关联域名验证通过: %s" % root, "+")

    def discover_apps(self):
        """移动端 APP 发现（App Store 免费 API，文档阶段六）。

        归属过滤三通道：应用名含单位名（严格/宽松）/ 开发者匹配锚点组织名 /
        中文名 ↔ 英文开发者（地域拼音+行业英文词，四川移动↔China Mobile Group
        Sichuan）。开发者主页 URL 的域名作为候选喂给页面引用互证。
        """
        if not self.names:
            return
        names = set(self.names) | set(self.anchor.get("orgs") or ())
        seen = set()
        for name in self.names:
            for app in itunes_search_apps(name):
                track = app.get("trackName") or ""
                seller = app.get("sellerName") or ""
                if not track or track in seen:
                    continue
                reason = ""
                # 应用名：模糊阈值提到 80%——"微乐四川麻将移动版" 这类
                # 凑巧共享"四川/移动"bigram 的无关应用必须拒掉
                if any(n and (_org_match(n, track)
                              or _org_match_fuzzy(n, track, min_cov=0.8))
                       for n in self.names):
                    reason = "应用名含单位名"
                # 开发者 vs 锚点组织：英文名共享 Technology/Co Ltd 等词元，
                # 模糊匹配误报率高，只用严格包含
                elif any(n and _org_match(n, seller) for n in names):
                    reason = "开发者匹配锚点组织"
                elif any(_seller_match(n, seller) for n in self.names):
                    reason = "开发者含地域+行业词"
                if not reason:
                    continue
                seen.add(track)
                self.apps.append((track, seller, app.get("bundleId") or "", reason))
                log("  APP: %s | 开发者: %s | %s" % (track, seller, reason), "+")
                # 开发者主页域名作为候选资产（互证后入锚点）
                su = app.get("sellerUrl") or ""
                m = re.match(r"https?://([^/:?#]+)", su)
                if m:
                    self._ref_candidates.append(m.group(1))
        if self.apps:
            log("移动端 APP 发现: %d 个（清单见报告）" % len(self.apps), "+")

    @staticmethod
    def _apply_waf(a, waf):
        if waf and "WAF:" not in (a.tech or ""):
            a.tech = (a.tech + "," if a.tech else "") + "WAF:%s" % waf
            log("  WAF识别: %s → %s" % (a.host, waf), "!")

    # ---- 外部引擎联动（subfinder / httpx / wafw00f / nuclei）----
    def run_external_tools(self, only=None):
        """把本机已安装的外部工具当"可选引擎"调用，输出归一化后并入台账。

        原则：只在工具存在时调用（未安装静默跳过，exe 仍零依赖）；
        subfinder 纯被动；httpx / wafw00f 触碰目标，--no-probe 时跳过；
        nuclei 属主动漏洞验证，仅 active 模式运行。
        """
        tools = ext_available()
        if only:
            if isinstance(only, str):
                only = only.split(",")
            want = {str(s).strip().lower() for s in only if str(s).strip()}
            tools = {k: v for k, v in tools.items() if k in want}

        missing = [n for n in EXT_BINARIES if n not in tools]
        if not tools:
            log("外部引擎: 未检测到 %s（跳过）。安装后本工具会自动调用。"
                % "/".join(EXT_BINARIES), "!")
            return
        self.ext_detected = set(tools)
        self.ext_used = {}
        log("== 外部引擎联动（检测到: %s）==" % ", ".join(sorted(tools)), "#")
        if missing:
            log("未安装（跳过）: %s" % ", ".join(missing))

        no_probe = getattr(self.args, "no_probe", False)
        active = getattr(self.args, "active", False)
        if no_probe:
            skipped = [n for n in ("httpx", "wafw00f", "nuclei") if n in tools]
            if skipped:
                log("纯被动模式：%s 需要连接目标，已跳过（被动源照常全部运行）。"
                    % "/".join(skipped))

        # 1) subfinder：多源被动子域枚举（不触碰目标）
        if "subfinder" in tools:
            self.ext_used["subfinder"] = tools["subfinder"]
            total = 0
            limit = int(getattr(self.args, "ext_sub_limit", 3000) or 0)
            for d in [x for x in sorted(self.domains) if x][:10]:
                subs = sorted(run_subfinder(d))
                if limit and len(subs) > limit:
                    log("  subfinder %s: %d 条，超过单域上限 %d，按字母序截断"
                        "（--ext-sub-limit 可调，0=不限）" % (d, len(subs), limit), "!")
                    subs = subs[:limit]
                for h in subs:
                    self.add_asset(h, None, None, source="ext:subfinder")
                total += len(subs)
                if subs:
                    log("  subfinder %s: %d 个子域" % (d, len(subs)), "+")
            log("subfinder 合计 %d 条（按域名证据自动归级）" % total)

        httpx_results = []
        # 2) httpx：批量存活探测 + 标题/技术栈/服务器（仅部分端口，避免不必要的触碰）
        if "httpx" in tools and not no_probe:
            self.ext_used["httpx"] = tools["httpx"]
            hosts = []
            for a in self.assets.values():
                if not a.host or a.host in hosts:
                    continue
                if a.scheme or a.port is None or is_web_port(int(a.port)):
                    hosts.append(a.host)
            httpx_results = run_httpx(hosts)
            if not httpx_results and hosts:
                log("httpx: 无存活返回（可能在授权范围外/被拦截）")
            for r in httpx_results:
                u = r.get("url") or ""
                m = re.match(r"(https?)://([^/:?#]+)(?::(\d+))?", u)
                scheme = m.group(1) if m else None
                host = m.group(2) if m else r.get("host", "")
                port = int(m.group(3)) if (m and m.group(3)) else (
                    443 if scheme == "https" else 80 if scheme == "http" else None)
                if not host:
                    continue
                a = self.add_asset(host, port, scheme, source="ext:httpx")
                if u:
                    a.urls.add(u)
                if r.get("status") and not a.status:
                    a.status = r["status"]
                if r.get("title") and not a.title:
                    a.title = r["title"]
                if r.get("server") and not a.server:
                    a.server = r["server"]
                for t in (r.get("tech") or "").split(","):
                    t = t.strip()
                    if t and t not in (a.tech or ""):
                        a.tech = (a.tech + "," if a.tech else "") + t
            log("httpx: %d 个存活 Web 资产（标题/技术栈已并入台账）" % len(httpx_results), "+")

        # 3) wafw00f：WAF 精确识别（对少量 Web 入口）
        if "wafw00f" in tools and not no_probe:
            urls = [r["url"] for r in httpx_results if r.get("url")][:10]
            if not urls:
                for a in self.assets.values():
                    if a.host and (a.scheme or (a.port and is_web_port(int(a.port)))):
                        urls.append(_asset_url(a))
                    if len(urls) >= 10:
                        break
            if urls:
                self.ext_used["wafw00f"] = tools["wafw00f"]
            for u in urls:
                waf = run_wafw00f(u)
                if not waf:
                    continue
                host = _url_host(u)
                port = 443 if u.startswith("https://") else 80
                a = self.add_asset(host, port, "https" if port == 443 else "http",
                                   source="ext:wafw00f")
                self._apply_waf(a, waf)
            if urls:
                log("wafw00f: 已检测 %d 个入口" % len(urls))

        # 4) nuclei：模板化 POC 验证（主动，仅 --active）
        if "nuclei" in tools:
            if not active or no_probe:
                log("nuclei: 属主动漏洞验证，未开启 --active，跳过。", "!")
            else:
                urls = [r["url"] for r in httpx_results if r.get("url")][:15]
                if not urls:
                    for a in self.assets.values():
                        if a.host and (a.scheme or (a.port and is_web_port(int(a.port)))):
                            urls.append(_asset_url(a))
                        if len(urls) >= 15:
                            break
                self.ext_used["nuclei"] = tools["nuclei"]
                hits = run_nuclei(urls)
                self.ext_hits = hits
                if hits:
                    log("nuclei: 命中 %d 条（见报告「外部工具联动结果」）" % len(hits), "!")
                else:
                    log("nuclei: 未命中（模板由 nuclei 维护，本工具只收结果）")

    def mine_js_secrets(self, total=40, per_limit=512 * 1024):
        """JS 文件挖掘（JSFinder + FindSomething 思路）。

        抓取页面引用的外部 JS：提取其中域名作为候选资产（常暴露未公开系统），
        扫描高精度密钥特征（云 AK/SK、私钥）进 js_secrets 供报告展示。
        """
        urls = [u for u in dict.fromkeys(self._js_urls)][:total]
        if not urls:
            return
        log("JS 挖掘: %d 个脚本" % len(urls))
        for u in urls:
            try:
                body = http_get(u, timeout=8, retries=0, max_bytes=per_limit)
            except Exception:
                continue
            for m in _DOMAIN_IN_TEXT_RE.finditer(body):
                self._ref_candidates.append(m.group(1))
            for kind in scan_js_secrets(body):
                self.js_secrets.append((u[:120], kind))
                log("  [!] JS 密钥特征: %s → %s" % (u[:80], kind), "!")
        if self.js_secrets:
            log("JS 挖掘完成: %d 处敏感信息（见报告）" % len(self.js_secrets), "!")

    def mine_and_verify_refs(self, limit=6):
        """页面外链/JS 引用挖掘（文档 5.2 前端深挖金矿）。

        探测过的每个页面正文里引用的域名（href/src/script）都可能指向
        未公开系统。候选经垃圾域过滤后逐个互证，通过才入锚点——
        合作伙伴/政府门户等外链在验证环节被标题/证书不符拦下。
        """
        exclude = set(self.domains)
        for d in self.domains:
            exclude.add(root_domain(d))
        cands = filter_candidate_roots(self._ref_candidates,
                                       exclude_roots=exclude)[:limit]
        if not cands:
            return
        log("页面引用挖掘: %d 个候选根域名（外链/JS 引用）" % len(cands))
        name = self.names[0] if self.names else ""
        for root in cands:
            if self._verify_candidate_domain(name, root):
                log("  引用域名互证通过: %s" % root, "+")

    # ---- 5. 输出 ----
    def output(self, baseline_diff=None):
        log("== 阶段5: 生成报告 ==", "#")
        outdir = self.args.out
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(outdir, "cybercensus_%s" % ts)

        self._merge_placeholders()

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
                "plain", "findings"]

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
                        ";".join(sorted(a.findings)),
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
                "apps": self.apps,
                "ext_tools": sorted(self.ext_used),
                "ext_detected": sorted(self.ext_detected),
                "ext_hits": self.ext_hits,
                "risk_hints": self.risk_hints,
                "assets": [a.to_dict() for a in rows],
                "generated_at": ts,
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)

        md_path = ""
        if "md" in fmts:
            md_path = base + ".md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self._report(rows, groups, ts, baseline_diff))

        if "html" in fmts:
            html_path = base + ".html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self._html_report(rows, groups, ts, baseline_diff))
            files["html"] = html_path

        for k in ("confirmed", "suspect", "rejected", "all"):
            if k in files:
                log("%-10s %s" % (k, files[k]), "+")
        if json_path:
            log("JSON      %s" % json_path, "+")
        if md_path:
            log("MD        %s" % md_path, "+")
        if "html" in files:
            log("HTML      %s" % files["html"], "+")
        return files, json_path, md_path

    def _report(self, rows, groups, ts, baseline_diff=None):
        L = []
        L.append("# CyberCensus 互联网暴露面测绘报告\n")
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

        # ---- 增量对比（有基线且有变化时） ----
        if baseline_diff:
            L.append("## 增量对比（对比上轮 %s）\n" % baseline_diff.get("prev_ts", "?"))
            if baseline_diff.get("added"):
                L.append("**新增资产 %d 个**：\n" % len(baseline_diff["added"]))
                L.append("| 资产 | 分级 |")
                L.append("|------|------|")
                for k, fp in baseline_diff["added"]:
                    L.append("| %s | %s |" % (_md(k), _md(fp["confidence"])))
                L.append("")
            if baseline_diff.get("changed"):
                L.append("**发生变化 %d 个**：\n" % len(baseline_diff["changed"]))
                L.append("| 资产 | 变化 |")
                L.append("|------|------|")
                for c in baseline_diff["changed"]:
                    L.append("| %s | %s |" % (_md(c["key"]), _md("；".join(c["changes"]))))
                L.append("")
            if baseline_diff.get("removed"):
                L.append("**已下线 %d 个**（本轮未再发现，可能已关停）：\n"
                         % len(baseline_diff["removed"]))
                L.append("| 资产 |")
                L.append("|------|")
                for k, fp in baseline_diff["removed"]:
                    L.append("| %s |" % _md(k))
                L.append("")
            L.append("> 新增资产请人工核实是否为最新上线业务；新敏感发现建议尽快处理。\n")

        # ---- 敏感路径发现 ----
        found_assets = [a for a in rows if a.findings]
        if found_assets:
            L.append("## ⚠️ 敏感路径发现（%d 个资产）\n" % len(found_assets))
            L.append("以下资产存在信息泄露或管理后台暴露，**建议优先处理**：\n")
            L.append("| 资产 | 分级 | 发现 |")
            L.append("|------|------|------|")
            for a in found_assets:
                names = "、".join(sorted(f.split("|", 1)[-1] for f in a.findings))
                L.append("| %s:%s | %s | %s |" % (_md(a.host), _md(str(a.port or "")),
                                                  _md(a.confidence), _md(names)))
            L.append("")

        # ---- 风险组件提示（指纹命中的已知漏洞家族） ----
        risky = []
        for a in rows:
            notes = tech_risk(a.tech)
            if notes:
                risky.append((a, notes))
        if risky:
            L.append("## ⚠️ 风险组件提示（%d 个资产，仅指纹识别，未执行任何验证）\n"
                     % len(risky))
            L.append("命中了有已知漏洞历史的组件——建议按对应漏洞家族排查（授权范围内）：\n")
            L.append("| 资产 | 指纹 | 风险提示 |")
            L.append("|------|------|----------|")
            for a, notes in risky:
                L.append("| %s:%s | %s | %s |" % (
                    _md(a.host), _md(str(a.port or "")),
                    _md(a.tech[:60]), _md("；".join(notes))))
            L.append("")

        # ---- JS 敏感信息（FindSomething/WebInfoHunter 思路） ----
        if self.js_secrets:
            L.append("## ⚠️ JS 敏感信息（%d 处，仅特征匹配，需人工确认）\n" % len(self.js_secrets))
            L.append("| 脚本地址 | 特征类型 |")
            L.append("|----------|----------|")
            for u, kind in self.js_secrets[:30]:
                L.append("| %s | %s |" % (_md(u), _md(kind)))
            L.append("")
            L.append("> 云 AccessKey/私钥泄露可能直接导致云资源失陷——**建议优先人工确认并轮换**。\n")

        # ---- 外部工具联动结果 ----
        if self.ext_used or self.ext_hits:
            L.append("## 🔧 外部工具联动结果\n")
            L.append("本机已安装的外部引擎由 CyberCensus 自动调度，输出已并入上方台账：\n")
            L.append("| 工具 | 作用 | 状态 |")
            L.append("|------|------|------|")
            desc = {
                "subfinder": "多源被动子域枚举",
                "httpx": "批量存活探测（标题/技术栈/服务器）",
                "wafw00f": "WAF 精确识别",
                "nuclei": "模板化 POC 验证（仅 --active）",
            }
            for name in sorted(EXT_BINARIES):
                if name in self.ext_used:
                    st = "已调用"
                elif name in self.ext_detected:
                    st = "已安装，本轮未调用（模式限制）"
                else:
                    st = "未安装（跳过）"
                L.append("| %s | %s | %s |" % (name, desc.get(name, ""), st))
            L.append("")
            if self.ext_hits:
                L.append("### nuclei POC 命中（%d 条，需人工复核）\n" % len(self.ext_hits))
                L.append("| 级别 | 模板 | 名称 | 位置 |")
                L.append("|------|------|------|------|")
                for tpl, sev, name, matched in self.ext_hits[:50]:
                    L.append("| %s | %s | %s | %s |" % (
                        _md(sev), _md(tpl), _md(name), _md(matched)))
                L.append("")
                L.append("> 模板与检测逻辑由 nuclei 官方模板库维护；命中结果请人工复核，"
                         "误报可能的请在授权范围内验证后再处置。\n")

        # ---- 联系方式（页面提取） ----
        if self.contacts:
            L.append("## 联系方式（页面/摘要提取，%d 个）\n" % len(self.contacts))
            for e in sorted(self.contacts):
                L.append("- `%s`" % e)
            L.append("")

        # ---- 移动端 APP 资产 ----
        if self.apps:
            L.append("## 📱 移动端应用（App Store，%d 个）\n" % len(self.apps))
            L.append("| 应用名 | 开发者 | 包名 | 归属依据 |")
            L.append("|--------|--------|------|----------|")
            for track, seller, bundle, reason in self.apps:
                L.append("| %s | %s | %s | %s |" % (
                    _md(track), _md(seller), _md(bundle), _md(reason)))
            L.append("")
            L.append("> 说明：iOS 端由 App Store 公开搜索发现；**Android 各商店（应用宝/华为/小米）"
                     "为客户端加载无法免登录自动抓取**，建议人工在应用商店搜索补全；"
                     "小程序与公众号账号本身需人工核实（小程序业务域名通常已含在本台账域名中）。\n")

        # ---- 风险线索（搜索引擎情报） ----
        if self.risk_hints:
            L.append("## 风险线索（搜索引擎情报，未验证）\n")
            L.append("以下为搜索引擎 dork 收集的线索，**仅供人工排查方向参考**，")
            L.append("点击前请确认在授权范围内（后台入口可能需要登录，GitHub 泄露可能含密钥）：\n")
            L.append("| 类别 | 链接 |")
            L.append("|------|------|")
            for kind, u in self.risk_hints[:40]:
                L.append("| %s | %s |" % (_md(kind), _md(u)))
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


    # ---- 5.1 HTML 报告（借鉴 ARL/Yakit 的 Web 交付形态，自包含单文件） ----
    def _svg_graph(self, rows, max_domains=8, max_ips=10):
        """资产关系图：主体 → 域名 → IP（Yakit 资产地图的轻量实现）。

        纯 SVG 字符串输出，无外部依赖。域名/ IP 按归属资产聚合。
        """
        esc = html_mod.escape
        dom_ips = {}
        ip_ports = {}
        order = {"确认": 0, "疑似": 1, "存疑": 2}
        for a in sorted(rows, key=lambda x: order.get(x.confidence, 3)):
            host = (a.host or "").lower()
            if not host:
                continue
            is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", host)
            key = "" if is_ip else host
            ip = a.ip or (host if is_ip else "")
            if key:
                dom_ips.setdefault(key, set())
                if ip:
                    dom_ips[key].add(ip)
            if ip:
                ip_ports.setdefault(ip, set())
                if a.port:
                    ip_ports[ip].add(str(a.port))
        domains = [d for d in dom_ips if dom_ips[d]][:max_domains]
        if not domains:
            return ""
        ips = sorted({ip for d in domains for ip in dom_ips[d]})[:max_ips]
        rows_n = max(len(domains), len(ips), 1)
        h = 40 + rows_n * 46
        parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="860" height="%d" '
                 'font-family="sans-serif" font-size="12">' % h]
        parts.append('<rect width="100%%" height="100%%" fill="#0d1117"/>')
        parts.append('<text x="20" y="22" fill="#8b949e">主体域名</text>')
        parts.append('<text x="360" y="22" fill="#8b949e">解析 IP / 开放端口</text>')
        dy_d = max(1, (h - 40) // max(1, len(domains)))
        pos = {}
        for i, d in enumerate(domains):
            y = 44 + i * dy_d
            pos[d] = y
            parts.append('<rect x="20" y="%d" width="270" height="30" rx="6" '
                         'fill="#161b22" stroke="#2f81f7"/>' % (y - 8))
            parts.append('<text x="32" y="%d" fill="#c9d1d9">%s</text>'
                         % (y + 4, esc(d[:38])))
        dy_i = max(1, (h - 40) // max(1, len(ips)))
        for j, ip in enumerate(ips):
            y = 44 + j * dy_i
            ports = ",".join(sorted(ip_ports.get(ip, ()), key=lambda p: int(p))[:6])
            parts.append('<rect x="360" y="%d" width="440" height="30" rx="6" '
                         'fill="#161b22" stroke="#3fb950"/>' % (y - 8))
            parts.append('<text x="372" y="%d" fill="#c9d1d9">%s  %s</text>'
                         % (y + 4, esc(ip), esc(("端口 " + ports) if ports else "")))
        for d in domains:
            for ip in sorted(dom_ips.get(d, ()))[:max_ips]:
                if ip in ips:
                    parts.append('<line x1="290" x2="360" y1="%d" y2="%d" '
                                 'stroke="#484f58"/>'
                                 % (pos[d] - 1, 44 + ips.index(ip) * dy_i - 1))
        parts.append("</svg>")
        return "\n".join(parts)

    def _html_report(self, rows, groups, ts, baseline_diff=None):
        """自包含单文件 HTML 报告（深色主题、卡片统计、资产关系图）。"""
        esc = html_mod.escape

        def counts():
            return {"确认": len(groups["确认"]), "疑似": len(groups["疑似"]),
                    "存疑": len(groups["存疑"])}

        c = counts()
        risky = [(a, tech_risk(a.tech)) for a in rows if tech_risk(a.tech)]
        found = [a for a in rows if a.findings]

        def table(items, show_reason=False):
            if not items:
                return "<p class='muted'>无</p>"
            head = ("<tr><th>分类</th><th>主机</th><th>IP</th><th>端口</th>"
                    "<th>标题</th><th>服务器</th><th>指纹</th><th>敏感发现</th>"
                    "<th>归属说明</th>" + ("<th>剔除原因</th>" if show_reason else "")
                    + "</tr>")
            body = []
            for a in items:
                cls = {"确认": "ok", "疑似": "warn", "存疑": "muted2"}.get(a.confidence, "")
                cells = (
                    "<td class='%s'>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                    "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                    % (cls, esc(a.confidence), esc(a.host or ""), esc(a.ip or ""),
                       esc(str(a.port or "")), esc(a.title or ""), esc(a.server or ""),
                       esc((a.tech or "")[:40]),
                       esc("、".join(f.split("|", 1)[-1] for f in sorted(a.findings))),
                       esc(plain_evidence(a.evidence))))
                if show_reason:
                    cells += "<td>%s</td>" % esc(a.reject_reason)
                body.append("<tr>%s</tr>" % cells)
            return "<table>%s%s</table>" % (head, "".join(body))

        css = """
        body{background:#0d1117;color:#c9d1d9;font-family:"Microsoft YaHei",sans-serif;margin:0;padding:24px}
        h1{color:#58a6ff}h2{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin-top:32px}
        table{border-collapse:collapse;width:100%;margin:8px 0}
        th,td{border:1px solid #30363d;padding:6px 8px;text-align:left;font-size:13px;vertical-align:top}
        th{background:#161b22}
        .cards{display:flex;gap:16px;margin:16px 0}
        .card{flex:1;background:#161b22;border-radius:10px;padding:16px;text-align:center}
        .card b{display:block;font-size:32px}
        .ok{color:#3fb950;font-weight:bold}.warn{color:#d29922;font-weight:bold}
        .muted2{color:#8b949e}.muted{color:#8b949e}
        .tip{background:#161b22;border-left:4px solid #d29922;padding:10px 14px;border-radius:4px}
        code{background:#161b22;padding:1px 4px;border-radius:3px}
        """
        parts = ["<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
                 "<title>CyberCensus 资产测绘报告</title><style>%s</style></head><body>" % css]
        parts.append("<h1>CyberCensus 资产测绘报告</h1>")
        parts.append("<p class='muted'>生成时间：%s%s</p>"
                     % (esc(ts), (" ｜ 主体：%s" % esc("、".join(self.names)))
                        if self.names else ""))
        if self.anchor["beian"]:
            parts.append("<p class='muted'>锚点备案号：%s</p>"
                         % esc("、".join(sorted(self.anchor["beian"]))))
        if self.anchor["credit_codes"]:
            parts.append("<p class='muted'>统一社会信用代码：%s</p>"
                         % esc("、".join(sorted(self.anchor["credit_codes"]))))
        parts.append("<div class='cards'>"
                     "<div class='card'><b class='ok'>%d</b>确认</div>"
                     "<div class='card'><b class='warn'>%d</b>疑似</div>"
                     "<div class='card'><b class='muted2'>%d</b>剔除</div></div>"
                     % (c["确认"], c["疑似"], c["存疑"]))

        if baseline_diff:
            parts.append("<h2>增量对比（上轮 %s）</h2>" % esc(baseline_diff.get("prev_ts", "?")))
            if baseline_diff.get("added"):
                parts.append("<p><b class='ok'>新增 %d：</b>%s</p>"
                             % (len(baseline_diff["added"]),
                                esc("、".join(k for k, _ in baseline_diff["added"][:20]))))
            if baseline_diff.get("changed"):
                parts.append("<p><b class='warn'>变化 %d：</b>%s</p>"
                             % (len(baseline_diff["changed"]),
                                esc("；".join("%s(%s)" % (ch["key"], "、".join(ch["changes"]))
                                              for ch in baseline_diff["changed"][:10]))))
            if baseline_diff.get("removed"):
                parts.append("<p class='muted'>下线 %d：%s</p>"
                             % (len(baseline_diff["removed"]),
                                esc("、".join(k for k, _ in baseline_diff["removed"][:20]))))

        graph = self._svg_graph(rows)
        if graph:
            parts.append("<h2>资产关系图</h2>")
            parts.append(graph)

        if found:
            parts.append("<h2>⚠️ 敏感路径发现（%d）</h2>" % len(found))
            parts.append("<table><tr><th>资产</th><th>分级</th><th>发现</th></tr>")
            for a in found:
                names = "、".join(sorted(f.split("|", 1)[-1] for f in a.findings))
                parts.append("<tr><td>%s:%s</td><td>%s</td><td>%s</td></tr>"
                             % (esc(a.host or ""), esc(str(a.port or "")),
                                esc(a.confidence), esc(names)))
            parts.append("</table>")

        if risky:
            parts.append("<h2>⚠️ 风险组件提示（%d，仅指纹识别，未执行验证）</h2>" % len(risky))
            parts.append("<table><tr><th>资产</th><th>指纹</th><th>风险提示</th></tr>")
            for a, notes in risky:
                parts.append("<tr><td>%s:%s</td><td>%s</td><td>%s</td></tr>"
                             % (esc(a.host or ""), esc(str(a.port or "")),
                                esc((a.tech or "")[:50]), esc("；".join(notes))))
            parts.append("</table>")

        if self.apps:
            parts.append("<h2>📱 移动端应用（App Store，%d）</h2>" % len(self.apps))
            parts.append("<table><tr><th>应用名</th><th>开发者</th><th>包名</th>"
                         "<th>归属依据</th></tr>")
            for track, seller, bundle, reason in self.apps:
                parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                             % (esc(track), esc(seller), esc(bundle), esc(reason)))
            parts.append("</table>")

        if self.js_secrets:
            parts.append("<h2>⚠️ JS 敏感信息（%d 处，仅特征匹配）</h2>" % len(self.js_secrets))
            parts.append("<table><tr><th>脚本地址</th><th>特征类型</th></tr>")
            for u, kind in self.js_secrets[:30]:
                parts.append("<tr><td>%s</td><td>%s</td></tr>" % (esc(u), esc(kind)))
            parts.append("</table>")

        if self.ext_used or self.ext_hits:
            parts.append("<h2>🔧 外部工具联动结果</h2>")
            parts.append("<table><tr><th>工具</th><th>作用</th><th>状态</th></tr>")
            _ext_desc = {
                "subfinder": "多源被动子域枚举",
                "httpx": "批量存活探测（标题/技术栈/服务器）",
                "wafw00f": "WAF 精确识别",
                "nuclei": "模板化 POC 验证（仅 --active）",
            }
            for name in sorted(EXT_BINARIES):
                if name in self.ext_used:
                    st = "已调用"
                elif name in self.ext_detected:
                    st = "已安装，本轮未调用（模式限制）"
                else:
                    st = "未安装（跳过）"
                parts.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                             % (esc(name), esc(_ext_desc.get(name, "")), esc(st)))
            parts.append("</table>")
            if self.ext_hits:
                parts.append("<h3>nuclei POC 命中（%d 条，需人工复核）</h3>"
                             % len(self.ext_hits))
                parts.append("<table><tr><th>级别</th><th>模板</th>"
                             "<th>名称</th><th>位置</th></tr>")
                for tpl, sev, name, matched in self.ext_hits[:50]:
                    parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                                 % (esc(sev), esc(tpl), esc(name), esc(matched)))
                parts.append("</table>")

        if self.contacts:
            parts.append("<h2>联系方式（页面/摘要提取）</h2><p>%s</p>"
                         % " ".join("<code>%s</code>" % esc(e) for e in sorted(self.contacts)))

        if self.risk_hints:
            parts.append("<h2>风险线索（搜索引擎情报，未验证）</h2>")
            parts.append("<table><tr><th>类别</th><th>链接</th></tr>")
            for kind, u in self.risk_hints[:40]:
                parts.append("<tr><td>%s</td><td>%s</td></tr>" % (esc(kind), esc(u)))
            parts.append("</table>")

        parts.append("<h2>确认资产（%d）</h2>" % c["确认"])
        parts.append(table(groups["确认"]))
        parts.append("<h2>疑似资产（%d）</h2>" % c["疑似"])
        parts.append(table(groups["疑似"]))
        parts.append("<h2>已剔除（%d）</h2>" % c["存疑"])
        parts.append(table(groups["存疑"], show_reason=True))
        parts.append("<p class='tip'>判定规则：确认 = 强证据(A)≥1 或 较强证据(B)≥2；"
                     "疑似 = B=1 或 弱证据(C)≥1；剔除 = 无证据或三方云资源且无强证据。"
                     "强证据：备案号 / 证书O= / 统一社会信用代码 / 已知主域名子域。</p>")
        parts.append("</body></html>")
        return "\n".join(parts)


# ----------------------------------------------------------------------------
# 外部工具联动（subfinder / httpx / wafw00f / nuclei）
#
# 设计：只做"调度 + 输出归一化"，不做模板维护、不做大字典——
#   · subfinder：大字典子域（我们的小字典互补）
#   · httpx：存活探测 + 标题 + 技术栈（批量、并发高）
#   · wafw00f：WAF 精确识别（我们的响应头指纹互补）
#   · nuclei：POC 模板验证（模板体系由 nuclei 维护，我们只收结果）
# 工具未安装则静默跳过，exe 仍保持零依赖自包含。
# ----------------------------------------------------------------------------
EXT_BINARIES = {
    "subfinder": ("subfinder",),
    "httpx": ("httpx",),
    "wafw00f": ("wafw00f",),
    "nuclei": ("nuclei",),
}


def ext_available():
    """探测本机已安装的外部工具：{名称: 可执行路径}。"""
    out = {}
    for name, cands in EXT_BINARIES.items():
        for c in cands:
            p = shutil.which(c)
            if p:
                out[name] = p
                break
    return out


def _run_ext(cmd, timeout):
    """调用外部工具：强制 UTF-8（中文标题/输出不会因 GBK 解码崩溃），
    Windows 下不弹控制台窗口（GUI 打包后调用时不闪黑框）。"""
    kw = dict(capture_output=True, text=True, encoding="utf-8",
              errors="replace", timeout=timeout)
    if os.name == "nt":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    return subprocess.run(cmd, **kw)


def run_subfinder(domain, timeout=300):
    """subfinder 大字典/多源被动子域（-silent 每行一个主机名）。"""
    binp = shutil.which("subfinder")
    if not binp:
        return set()
    try:
        r = _run_ext([binp, "-d", domain, "-silent", "-duc"], timeout)
        subs = set()
        for line in (r.stdout or "").splitlines():
            h = line.strip().lower().rstrip(".")
            if h and (h == domain or h.endswith("." + domain)):
                subs.add(h)
        return subs
    except Exception:
        return set()


def run_httpx(hosts, timeout=600):
    """httpx 批量存活探测（-json 每行一条）。返回 [{url,host,title,tech,server,status}]。"""
    binp = shutil.which("httpx")
    hosts = [h for h in hosts if h][:300]
    if not binp or not hosts:
        return []
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(hosts))
        r = _run_ext(
            [binp, "-l", tmp, "-silent", "-json", "-duc", "-title", "-tech-detect",
             "-web-server", "-status-code", "-timeout", "8"],
            timeout)
        out = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            url = str(d.get("url") or "")
            host = _url_host(url) or str(d.get("input") or "").lower()
            if not host:
                continue
            tech = d.get("tech") or []
            out.append({
                "url": url, "host": host,
                "title": str(d.get("title") or ""),
                "tech": ",".join(tech) if isinstance(tech, list) else str(tech or ""),
                "server": str(d.get("webserver") or ""),
                "status": str(d.get("status_code") or ""),
            })
        return out
    except Exception:
        return []
    finally:
        try:
            if tmp:
                os.unlink(tmp)
        except Exception:
            pass


def run_wafw00f(url, timeout=120):
    """wafw00f 精确 WAF 识别（-f json）。返回 WAF 名称或空串。"""
    binp = shutil.which("wafw00f")
    if not binp:
        return ""
    try:
        r = _run_ext([binp, "-u", url, "-f", "json"], timeout)
        data = json.loads(r.stdout or "{}")
        items = data if isinstance(data, list) else [data]
        for it in items:
            if isinstance(it, dict) and it.get("detected"):
                return str(it.get("firewall") or "")
    except Exception:
        pass
    return ""


def run_nuclei(urls, timeout=1200, severity="critical,high,medium"):
    """nuclei 模板化 POC 验证（-json 每行一条）。返回 [{template,severity,name,matched}]。"""
    binp = shutil.which("nuclei")
    urls = [u for u in urls if u][:15]
    if not binp or not urls:
        return []
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(urls))
        cmd = [binp, "-l", tmp, "-jsonl", "-silent", "-duc", "-severity", severity,
               "-timeout", "8", "-retries", "1"]
        r = _run_ext(cmd, timeout)
        # nuclei v2 没有 -jsonl（v3 才有）：按输出自动回退到 -json
        if r.returncode != 0 and "flag provided but not defined" in (
                (r.stdout or "") + (r.stderr or "")):
            cmd[3] = "-json"
            r = _run_ext(cmd, timeout)
        hits = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info") or {}
            hits.append({
                "template": str(d.get("template-id") or ""),
                "severity": str(info.get("severity") or ""),
                "name": str(info.get("name") or ""),
                "matched": str(d.get("matched-at") or d.get("host") or ""),
            })
        return hits
    except Exception:
        return []
    finally:
        try:
            if tmp:
                os.unlink(tmp)
        except Exception:
            pass


def send_webhook(url, text, timeout=10):
    """向 Webhook 推送完成通知（兼容钉钉/企业微信/飞书机器人载荷形状）。

    payload 同时带 msgtype/text 与 msg_type/content 两套键，多余键被平台忽略。
    """
    if not url:
        return False
    payload = {
        "msgtype": "text", "text": {"content": text},
        "msg_type": "text", "content": {"text": text},
    }
    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json; charset=utf-8"})
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as r:
            ok = r.status < 400
            if ok:
                log("Webhook 通知已发送", "+")
            return ok
    except Exception as e:
        log("Webhook 通知失败: %s" % str(e)[:80], "!")
        return False


def _md(s):
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ")


# 证据条目 → 新手可读的白话解释（按 evidence 前缀匹配，未命中保留原文）
_PLAIN_EVIDENCE = (
    ("A|页面备案号一致", "网站页脚的ICP备案号与目标单位备案号一致"),
    ("A|页面含统一社会信用代码", "页面中含有目标单位的统一社会信用代码（法定唯一标识）"),
    ("A|证书O=一致", "该站HTTPS证书的持有单位就是目标单位"),
    ("A|主域名子域", "是目标单位主域名的子域名"),
    ("A|平台cert命中", "测绘平台证书库显示该站证书含目标单位信息"),
    ("A|平台icp命中", "测绘平台备案库显示该站备案属于目标单位"),
    ("A|平台返回备案号命中", "平台数据显示该站备案号与目标单位一致"),
    ("A|搜索引擎备案号命中", "搜索引擎收录显示该站页脚印有目标单位备案号"),
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
  python cybercensus.py -n "某某市人民政府" -d xx.gov.cn
  python cybercensus.py -d example.com
  python cybercensus.py --ip 1.2.3.4
  python cybercensus.py -d example.com --active --top 200
  python cybercensus.py -d example.com --active --cscan
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
    p.add_argument("--out", default="cybercensus_out", help="输出目录")
    p.add_argument("--formats", default="md,csv,html", dest="output_formats",
                   help="输出哪些格式：md / csv / html / json，逗号分隔（默认 md,csv,html）")
    p.add_argument("--webhook", default="",
                   help="扫描完成/发现新增资产时推送到 Webhook（钉钉/企业微信/飞书机器人 URL）")
    p.add_argument("--no-probe", action="store_true", help="完全不触碰目标（纯第三方数据）")
    p.add_argument("--no-discover", action="store_true",
                   help="仅给名称时禁用搜索引擎官网自举（默认启用）")
    p.add_argument("--probe-found", action="store_true",
                   help="被动模式下，对发现的主机做 HTTP 探测（默认不做，避免打扰目标）")
    p.add_argument("--probe-limit", type=int, default=100,
                   help="--probe-found 时最多探测多少个主机（默认100）")
    p.add_argument("--probe-interval", type=float, default=0, dest="probe_interval",
                   help="主动 HTTP 探测的全局请求间隔秒数（默认0=不节流；建议 0.1~0.5 降噪）")
    p.add_argument("--no-brute", action="store_true",
                   help="禁用常见子域小字典 DNS 枚举（默认开启，仅解析不碰端口）")
    p.add_argument("--no-apps", action="store_true",
                   help="不查 App Store（移动端 APP 发现，默认开启）")
    p.add_argument("--no-hints", action="store_true",
                   help="不做搜索引擎 dork 风险情报（默认开启）")
    p.add_argument("--sensitive", action="store_true",
                   help="对存活 Web 资产做敏感路径探测（.git/.env/Actuator/Swagger/备份等；active 模式默认开启）")
    p.add_argument("--no-sensitive", action="store_true",
                   help="关闭敏感路径探测（即使 active 模式也不跑）")
    p.add_argument("--sensitive-limit", type=int, default=200,
                   help="敏感路径探测最多覆盖多少个 Web 资产（默认200）")
    p.add_argument("--yes", action="store_true", help="跳过主动扫描的授权确认")
    p.add_argument("--quiet", action="store_true", help="少输出")

    g = p.add_argument_group("外部引擎联动（本机已安装才调用，未安装自动跳过）")
    g.add_argument("--ext-tools", default=None, dest="ext_tools",
                   help="只调用指定外部工具，逗号分隔：subfinder,httpx,wafw00f,nuclei"
                        "（默认全部已安装的都调用；nuclei 仍需 --active）")
    g.add_argument("--no-ext", action="store_true",
                   help="不调用任何外部工具（默认自动探测并调用）")
    g.add_argument("--ext-sub-limit", type=int, default=3000, dest="ext_sub_limit",
                   help="subfinder 单域名子域上限（默认3000，0=不限；防止历史垃圾子域撑爆台账）")

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
        # 搜索引擎风险情报（dork：后台入口 / GitHub 泄露，不触碰目标）
        if not getattr(args, "no_hints", False):
            eng.collect_risk_hints()
        # 公众号文章域名挖掘（文档阶段六；需探测验证，纯被动模式跳过）
        if not args.no_probe:
            eng.mine_weixin_domains()
        # 移动端 APP 发现（App Store 免费 API，第三方查询不触碰目标）
        if not getattr(args, "no_apps", False):
            eng.discover_apps()
        # 多平台聚合（FOFA / 0.zone / Hunter / DayDayMap）
        if not args.no_providers:
            eng.collect_providers()
            eng.merge_providers()
    # 外部引擎联动（本机装了就调：subfinder / httpx / wafw00f / nuclei）
    if not _stopped() and not getattr(args, "no_ext", False):
        eng.run_external_tools(getattr(args, "ext_tools", None))
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
        # 敏感路径探测：显式 --sensitive 或 active 模式默认开（--no-sensitive 强制关）
        do_sens = (not getattr(args, "no_sensitive", False)) and (
            getattr(args, "sensitive", False) or args.active)
        if do_sens and not _stopped():
            eng.probe_sensitive(limit=getattr(args, "sensitive_limit", 200))
    if not _stopped():
        # JS 文件挖掘（域名 + 密钥特征）→ 页面外链互证
        eng.mine_js_secrets()
        eng.mine_and_verify_refs()
    if _stopped():
        log("已请求停止：对已收集的数据做分级输出。", "!")
    eng.evaluate()
    # 增量监控：与输出目录中的上一轮基线对比（新资产/新端口/新敏感发现告警）
    baseline_diff = eng.diff_baseline()
    eng.save_baseline()
    # 完成通知（ARL-Next 式 Webhook 告警）
    hook = getattr(args, "webhook", "") or ""
    if hook:
        counts = {"确认": 0, "疑似": 0, "存疑": 0}
        for a in eng.assets.values():
            counts[a.confidence] = counts.get(a.confidence, 0) + 1
        msg = ("CyberCensus 扫描完成：确认 %d / 疑似 %d / 剔除 %d / 合计 %d"
               % (counts["确认"], counts["疑似"], counts["存疑"], len(eng.assets)))
        if baseline_diff and baseline_diff.get("added"):
            msg += "；新增资产 %d 个" % len(baseline_diff["added"])
        send_webhook(hook, msg)
    if not do_output:
        return eng, {}, "", ""
    files, json_path, md_path = eng.output(baseline_diff=baseline_diff)
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
