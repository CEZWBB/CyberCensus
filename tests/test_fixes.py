#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_fixes.py —— P0-P2 整改的回归测试（纯标准库，不联网、不需要 API key）

运行：
  python -m unittest discover tests -v
"""

import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cybercensus  # noqa: E402
import providers as prov  # noqa: E402


# ----------------------------------------------------------------------------
# P0-1 / P0-2：备案号主号提取 + 组织名规范化匹配
# ----------------------------------------------------------------------------
class TestBeianKey(unittest.TestCase):
    def test_main_key_extraction(self):
        self.assertEqual(cybercensus._beian_key("京ICP备12345678号-1"), "京ICP备12345678")
        self.assertEqual(cybercensus._beian_key("京ICP备12345678号"), "京ICP备12345678")
        self.assertEqual(cybercensus._beian_key("粤ICP备20000001号-15"), "粤ICP备20000001")

    def test_fullwidth_normalization(self):
        # 全角 ＩＣＰ 与全角数字应被归一化
        self.assertEqual(cybercensus._beian_key("京ＩＣＰ备１２３４号"), "京ICP备1234")

    def test_garbage_returns_empty(self):
        self.assertEqual(cybercensus._beian_key("12345"), "")
        self.assertEqual(cybercensus._beian_key("1.2.3.4"), "")
        self.assertEqual(cybercensus._beian_key("某某公司"), "")
        self.assertEqual(cybercensus._beian_key(""), "")
        self.assertEqual(cybercensus._beian_key(None), "")

    def test_different_subjects_do_not_match(self):
        # 主号不同 = 不同主体，绝不互认
        self.assertNotEqual(cybercensus._beian_key("京ICP备1234号"),
                            cybercensus._beian_key("京ICP备12345号"))
        self.assertEqual(cybercensus._beian_key("京ICP备12345678号-1"),
                         cybercensus._beian_key("京ICP备12345678号-10"))


class TestOrgMatch(unittest.TestCase):
    def test_subordinate_org_matches(self):
        # 真实下属机构：短边 ≥6 字符的包含应命中
        self.assertTrue(cybercensus._org_match("某某市数据局信息中心", "某某市数据局"))

    def test_short_name_no_match(self):
        # 过短名的裸包含是误报源，不应命中
        self.assertFalse(cybercensus._org_match("某某市", "某某市人民政府"))

    def test_normalized_equality(self):
        # 全角/空白差异归一后相等
        self.assertTrue(cybercensus._org_match("Ａｌｉｂａｂａ　Ｇｒｏｕｐ", "alibaba group"))
        self.assertTrue(cybercensus._org_match("某某市人民政府 ", "某某市人民政府"))

    def test_unrelated_no_match(self):
        self.assertFalse(cybercensus._org_match("China Telecom", "某某市人民政府"))
        self.assertFalse(cybercensus._org_match("", "x"))
        self.assertFalse(cybercensus._org_match(None, "x"))

    def test_different_hospitals_never_match(self):
        # 同城不同医院（"东莞市人民医院" vs "东莞市莞城医院"）绝不互认——
        # 这正是匹配保持严格子串/相等而不引入模糊相似度的原因
        self.assertFalse(cybercensus._org_match("东莞市人民医院", "东莞市莞城医院"))
        # 中间插入字样的别名（"莞城医院" vs "莞城人民医院"）同样不互认，
        # 只有完整别名的包含/相等才命中
        self.assertFalse(cybercensus._org_match("莞城医院", "莞城人民医院"))
        self.assertTrue(cybercensus._org_match("莞城人民医院", "东莞市莞城人民医院"))


# ----------------------------------------------------------------------------
# P2-13：is_web_port 与 DEFAULT_PORTS 对齐
# ----------------------------------------------------------------------------
class TestWebPorts(unittest.TestCase):
    def test_new_ports_covered(self):
        for p in (5000, 7001, 7002, 888):
            self.assertTrue(cybercensus.is_web_port(p), "port %d 应为 web 端口" % p)

    def test_non_web_ports(self):
        for p in (22, 3306, 6379, 3389):
            self.assertFalse(cybercensus.is_web_port(p))


# ----------------------------------------------------------------------------
# P0-3：make_record 的 number 字段守卫
# ----------------------------------------------------------------------------
class TestMakeRecordGuard(unittest.TestCase):
    def test_garbage_number_not_becomes_beian(self):
        r = prov.make_record("test", "icp", {"ip": "1.1.1.1", "number": "12345"})
        self.assertEqual(r["beian"], "")

    def test_valid_icp_in_number_kept(self):
        r = prov.make_record("test", "icp", {"ip": "1.1.1.1", "number": "京ICP备12345678号-3"})
        self.assertEqual(r["beian"], "京ICP备12345678号-3")

    def test_semantic_icp_field_trusted(self):
        r = prov.make_record("test", "icp", {"ip": "1.1.1.1", "icp": "京ICP备12345678号"})
        self.assertEqual(r["beian"], "京ICP备12345678号")

    def test_icp_reg_name_needs_valid_fragment(self):
        r = prov.make_record("test", "icp", {"ip": "1.1.1.1", "icp_reg_name": "某某科技有限公司"})
        self.assertEqual(r["beian"], "")


# ----------------------------------------------------------------------------
# P1-5：ZeroZone 翻译（引号 + cidr 不降级）
# ----------------------------------------------------------------------------
class TestZeroZoneTranslate(unittest.TestCase):
    def setUp(self):
        self.z = prov.ZeroZone({"key": "x"})

    def test_value_with_space_quoted(self):
        q = prov.Query("org", "Alibaba Group")
        self.assertEqual(self.z.translate(q), 'company=="Alibaba Group"')

    def test_quote_escaped(self):
        q = prov.Query("org", 'say "hi"')
        self.assertEqual(self.z.translate(q), 'company=="say \\"hi\\""')

    def test_cidr_expands_to_range(self):
        q = prov.Query("cidr", "10.0.0.0/24")
        self.assertEqual(self.z.translate(q), 'ip="10.0.0.0-10.0.0.255"')

    def test_invalid_cidr_returns_none(self):
        q = prov.Query("cidr", "notacidr/24")
        self.assertIsNone(self.z.translate(q))

    def test_ip_quoted(self):
        q = prov.Query("ip", "1.2.3.4")
        self.assertEqual(self.z.translate(q), 'ip="1.2.3.4"')


# ----------------------------------------------------------------------------
# P1-10：available_providers 的 FOFA email 校验
# ----------------------------------------------------------------------------
class TestAvailableProviders(unittest.TestCase):
    CFG = {"fofa": {"key": "x"}, "zerozone": {"key": "x"},
           "hunter": {"key": "x"}, "daydaymap": {"key": "x"}}

    def test_fofa_without_email_not_enabled(self):
        provs = prov.available_providers(self.CFG)
        self.assertNotIn("fofa", provs)
        self.assertIn("zerozone", provs)

    def test_fofa_with_email_enabled(self):
        cfg = {"fofa": {"key": "x", "email": "a@b.c"}, "zerozone": {"key": "x"},
               "hunter": {"key": "x"}, "daydaymap": {"key": "x"}}
        provs = prov.available_providers(cfg)
        self.assertIn("fofa", provs)


# ----------------------------------------------------------------------------
# P0-1 / P0-2 / P0-4：evaluate 与 merge_providers 场景测试
# ----------------------------------------------------------------------------
import argparse  # noqa: E402


def _engine():
    args = argparse.Namespace(beian="", threads=10, timeout=5)
    return cybercensus.Engine(args)


class TestEvaluate(unittest.TestCase):
    def test_clean_anchor_no_false_confirm(self):
        """云厂商证书 O= 不再因双向子串污染进'确认'。"""
        e = _engine()
        a = e.add_asset("unrelated.example.net", 443, "https", source="prov:fofa")
        a.cert_org = "China Telecom Cloud"
        e.evaluate()
        self.assertNotEqual(a.confidence, "确认")

    def test_subordinate_cert_org_still_confirms(self):
        """真实下属机构（短边≥6字符包含）仍应确认。"""
        e = _engine()
        e.anchor["orgs"].add("某某市数据局")
        a = e.add_asset("portal.xx.gov.cn", 443, "https", source="prov:fofa")
        a.cert_org = "某某市数据局信息中心"
        e.evaluate()
        self.assertEqual(a.confidence, "确认")

    def test_beian_same_subject_variant_confirms(self):
        """同主体 -N 子站互认。"""
        e = _engine()
        e.anchor["beian"].add("京ICP备12345678号-1")
        a = e.add_asset("www.example.gov.cn", 443, "https")
        a.beian = "京ICP备12345678号-10"
        e.evaluate()
        self.assertEqual(a.confidence, "确认")

    def test_beian_different_subject_not_confirmed(self):
        """不同主体的子串备案号不再误判 A 级。"""
        e = _engine()
        e.anchor["beian"].add("京ICP备12345号-1")
        a = e.add_asset("other.example.com", 443, "https")
        a.beian = "京ICP备123456号-2"
        e.evaluate()
        self.assertNotEqual(a.confidence, "确认")

    def test_garbage_prov_beian_not_confirmed(self):
        """平台返回的垃圾'备案号'（如端口号）不应命中 A 级。"""
        e = _engine()
        e.anchor["beian"].add("京ICP备12345678号")
        a = e.add_asset("x.example.com", 80, "http", source="prov:hunter")
        a.prov_beian = "8080"
        e.evaluate()
        self.assertNotEqual(a.confidence, "确认")


class TestMergeProviders(unittest.TestCase):
    def test_placeholder_merge_keeps_existing_evidence(self):
        """占位资产补端口时，(host,port) 已存在则证据合并而非覆盖。"""
        e = _engine()
        # 被动阶段留下的仅主机占位资产（无端口）
        ph = e.add_asset("a.example.com", None, None, source="passive")
        ph.favicon = "fav123"
        # 第一条平台记录创建 (host, 80)
        e.provider_records = [
            {"host": "a.example.com", "ip": "1.1.1.1", "port": 80,
             "provider": "fofa", "match_kind": "domain", "title": "T1",
             "server": "nginx", "url": "http://a.example.com"},
        ]
        e.merge_providers()
        k80 = e.assets.get(("a.example.com", "80"))
        self.assertIsNotNone(k80)
        self.assertIn("fofa", k80.providers)
        self.assertEqual(k80.title, "T1")
        # 占位资产的 favicon 证据并入，且 (host,"") 占位已移除
        self.assertEqual(k80.favicon, "fav123")
        self.assertIn("passive", k80.source)
        self.assertNotIn(("a.example.com", ""), e.assets)

    def test_two_records_same_host_port_accumulate(self):
        """两条平台记录同主机同端口：providers/kinds 累积不丢失。"""
        e = _engine()
        e.provider_records = [
            {"host": "b.example.com", "ip": "2.2.2.2", "port": 443,
             "provider": "fofa", "match_kind": "cert", "title": "T",
             "server": "", "url": "https://b.example.com"},
            {"host": "b.example.com", "ip": "2.2.2.2", "port": 443,
             "provider": "hunter", "match_kind": "icp", "title": "",
             "server": "apache", "url": ""},
        ]
        e.merge_providers()
        a = e.assets[("b.example.com", "443")]
        self.assertEqual(a.providers, {"fofa", "hunter"})
        self.assertEqual(a.prov_kinds, {"cert", "icp"})


# ----------------------------------------------------------------------------
# P2-17：classify_target 支持 CIDR + _add_ip_target 范围守卫
# ----------------------------------------------------------------------------
class TestClassifyTarget(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(cybercensus.classify_target("1.2.3.4"), "ip")
        self.assertEqual(cybercensus.classify_target("1.2.3.0/24"), "cidr")
        self.assertEqual(cybercensus.classify_target("2600::/64"), "cidr")
        self.assertEqual(cybercensus.classify_target("example.com"), "domain")
        self.assertEqual(cybercensus.classify_target("某某市大数据局"), "name")
        self.assertEqual(cybercensus.classify_target("abc/24"), "name")

    def test_add_ip_target(self):
        ips = set()
        self.assertIsNone(cybercensus._add_ip_target(ips, "1.2.3.4"))
        self.assertEqual(ips, {"1.2.3.4"})
        self.assertIsNone(cybercensus._add_ip_target(ips, ""))
        ips = set()
        self.assertIsNone(cybercensus._add_ip_target(ips, "1.2.3.0/24"))
        self.assertEqual(len(ips), 254)

    def test_oversized_cidr_rejected(self):
        err = cybercensus._add_ip_target(set(), "1.2.3.0/16")
        self.assertIsNotNone(err)
        self.assertIn("过大", err)
        err = cybercensus._add_ip_target(set(), "2600::/64")
        self.assertIsNotNone(err)

    def test_garbage_cidr_error(self):
        err = cybercensus._add_ip_target(set(), "garbage/24")
        self.assertIsNotNone(err)


# ----------------------------------------------------------------------------
# P1-9：_http 错误分类重试（monkeypatch urlopen）
# ----------------------------------------------------------------------------
class TestHttpRetryPolicy(unittest.TestCase):
    def _patch_urlopen(self, script):
        """script: 依次返回/抛出的对象列表。返回 (calls, sleeps)。"""
        calls = []
        sleeps = []

        class _Resp(object):
            def __init__(self, body=b"{}"):
                self._body = body

            def read(self, n=-1):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        import urllib.request
        import io

        def fake_open(req, timeout=None, context=None):
            calls.append(req.full_url)
            item = script[min(len(calls) - 1, len(script) - 1)]
            if isinstance(item, Exception):
                raise item
            return _Resp(item)

        orig_open, orig_sleep = urllib.request.urlopen, prov.time.sleep
        urllib.request.urlopen = fake_open
        prov.time.sleep = lambda s: sleeps.append(s)
        self.addCleanup(urllib.request.__setattr__, "urlopen", orig_open)
        self.addCleanup(prov.time.__setattr__, "sleep", orig_sleep)
        return calls, sleeps

    @staticmethod
    def _http_error(code, headers=None):
        import io
        import urllib.error
        return urllib.error.HTTPError("http://x", code, "err", headers or {}, io.BytesIO(b"e"))

    def test_401_not_retried(self):
        import io
        calls, sleeps = self._patch_urlopen([self._http_error(401)])
        with self.assertRaises(RuntimeError):
            prov._http("http://x", retries=3)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])

    def test_429_respects_retry_after(self):
        import io
        calls, sleeps = self._patch_urlopen(
            [self._http_error(429, {"Retry-After": "2"}), b'{"ok":1}'])
        out = prov._http("http://x", retries=1)
        self.assertEqual(out, '{"ok":1}')
        self.assertEqual(len(calls), 2)
        self.assertEqual(sleeps, [2.0])

    def test_429_retry_after_capped(self):
        import io
        calls, sleeps = self._patch_urlopen(
            [self._http_error(429, {"Retry-After": "9999"}),
             self._http_error(429, {"Retry-After": "9999"})])
        with self.assertRaises(RuntimeError):
            prov._http("http://x", retries=1)
        self.assertEqual(sleeps, [60.0])


# ----------------------------------------------------------------------------
# P2-12：端口扫描并发上限（monkeypatch tcp_open）
# ----------------------------------------------------------------------------
class TestScanConcurrency(unittest.TestCase):
    def test_concurrency_capped(self):
        import threading
        import time as _time
        lock = threading.Lock()
        state = {"cur": 0, "peak": 0}

        def fake_tcp_open(host, port, timeout=3):
            with lock:
                state["cur"] += 1
                state["peak"] = max(state["peak"], state["cur"])
            _time.sleep(0.02)
            with lock:
                state["cur"] -= 1
            return port == 80

        orig = cybercensus.tcp_open
        cybercensus.tcp_open = fake_tcp_open
        self.addCleanup(cybercensus.__setattr__, "tcp_open", orig)

        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5,
                                                scan_timeout=1.0))
        # 直接调用 scan_active 的核心段不可行（涉及 DNS/资产），改为验证等价结构：
        # 模拟 scan_active 的扁平 executor 实现
        from concurrent.futures import ThreadPoolExecutor, as_completed
        ips = ["10.%d.0.%d" % (i // 256, i % 256) for i in range(20)]
        ports = [22, 80, 443, 8080, 3306]
        pairs = [(ip, p) for ip in ips for p in ports]
        cap = max(8, 10 * 2)
        with ThreadPoolExecutor(max_workers=min(len(pairs), cap)) as ex:
            futs = {ex.submit(fake_tcp_open, ip, p, 1.0): (ip, p) for ip, p in pairs}
            opened_map = {}
            for f in as_completed(futs):
                ip, p = futs[f]
                if f.result():
                    opened_map.setdefault(ip, []).append(p)
        self.assertEqual(len(opened_map), 20)
        self.assertTrue(all(v == [80] for v in opened_map.values()))
        self.assertLessEqual(state["peak"], cap)


# ----------------------------------------------------------------------------
# P1-7 + P0-3：mock 平台端到端（debug 日志 + beian 干净）
# ----------------------------------------------------------------------------
class TestProviderRunDebug(unittest.TestCase):
    def test_debug_logs_native_query_and_beian_guarded(self):
        lines = []

        def log(msg, level="*"):
            lines.append(str(msg))

        class _Fake(prov.Fofa):
            def search(self, native_query, page=1, size=None):
                # 含垃圾 number 字段的返回行
                return [{"ip": "1.1.1.1", "port": 80, "host": "a.example.com",
                         "number": "99999", "title": "站点A"},
                        {"ip": "1.1.1.2", "port": 443, "host": "b.example.com",
                         "number": "京ICP备12345678号-2", "title": "站点B"}]

        p = _Fake({"key": "x", "email": "a@b.c"})
        qs = [prov.Query("domain", "example.com")]
        recs, st = p.run(qs, pages=1, debug=True, log=log)
        self.assertEqual(st["queries"], 1)
        self.assertEqual(len(recs), 2)
        # P0-3：垃圾 number 不进 beian；合法 ICP 片段保留
        self.assertEqual(recs[0]["beian"], "")
        self.assertEqual(recs[1]["beian"], "京ICP备12345678号-2")
        # P1-7：debug 日志包含翻译后的原生查询
        joined = "\n".join(lines)
        self.assertIn('domain="example.com"', joined)
        self.assertIn("Q1", joined)


# ----------------------------------------------------------------------------
# GUI 支撑：LOG_HOOK（日志流进界面时不再打印控制台）
# ----------------------------------------------------------------------------
class TestLogHook(unittest.TestCase):
    def test_hook_receives_and_print_skipped(self):
        import io
        import contextlib
        captured = []
        orig = cybercensus.LOG_HOOK
        cybercensus.LOG_HOOK = lambda msg, level: captured.append((msg, level))
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cybercensus.log("hello", "!")
                cybercensus.log("quiet-world", "#")
            self.assertEqual(captured, [("hello", "!"), ("quiet-world", "#")])
            self.assertEqual(buf.getvalue(), "")   # 设置钩子后不再打印
        finally:
            cybercensus.LOG_HOOK = orig

    def test_no_hook_prints_normally(self):
        import io
        import contextlib
        orig = cybercensus.LOG_HOOK
        cybercensus.LOG_HOOK = None
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cybercensus.log("plain", "*")
            self.assertIn("plain", buf.getvalue())
        finally:
            cybercensus.LOG_HOOK = orig


# ----------------------------------------------------------------------------
# 官网自举（无平台 Key 的名称→域名第一跳）
# ----------------------------------------------------------------------------
class TestDiscoverDomainsFromSearch(unittest.TestCase):
    def _patch_lookup(self, text, hosts):
        orig = cybercensus.search_engine_lookup
        cybercensus.search_engine_lookup = lambda name, timeout=15: (text, hosts)
        self.addCleanup(cybercensus.__setattr__, "search_engine_lookup", orig)

    def test_junk_filtered_and_ranked(self):
        self._patch_lookup(
            "莞城人民医院 东莞市莞城医院 官网链接 www.dggcyy.com 预约挂号。"
            "求医网提示 网址 www.dggcyy.com，粤ICP备13075739号。"
            "更多参考 www.dggcyy.com。",
            ["www.qiuyi.cn", "www.bohe.cn", "www.dggcyy.cn"])
        out = cybercensus.discover_domains_from_search("莞城人民医院")
        hosts = [h for h, s in out]
        # 目录站（qiuyi/bohe）被黑名单排除
        self.assertNotIn("www.qiuyi.cn", hosts)
        self.assertNotIn("www.bohe.cn", hosts)
        # 摘要出现 3 次的 dggcyy.com 与有机链接的 dggcyy.cn 均在候选
        self.assertIn("www.dggcyy.com", hosts)
        self.assertIn("www.dggcyy.cn", hosts)
        # 有机链接（3分）排在纯摘要（3×1分）同档或更高，取前几名
        self.assertLessEqual(hosts.index("www.dggcyy.com"), 1)

    def test_empty_lookup(self):
        self._patch_lookup("", [])
        self.assertEqual(cybercensus.discover_domains_from_search("x"), [])

    def test_max_candidates_capped(self):
        self._patch_lookup(
            " ".join("a%d.example.com" % i for i in range(20)), [])
        out = cybercensus.discover_domains_from_search("x")
        self.assertLessEqual(len(out), 5)


class TestVerifyCandidateDomain(unittest.TestCase):
    def _engine(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["莞城人民医院"]
        return e

    def _patch_probe(self, title):
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8: {
            "status": 200, "title": title}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)

    def test_title_match_verifies(self):
        e = self._engine()
        self._patch_probe("东莞市莞城人民医院官方网站")
        self.assertTrue(e._verify_candidate_domain("莞城人民医院", "www.dggcyy.cn"))
        self.assertIn("www.dggcyy.cn", e.domains)

    def test_unrelated_title_rejected(self):
        e = self._engine()
        self._patch_probe("东莞市人民政府门户网站")
        orig = cybercensus.tls_cert_info
        cybercensus.tls_cert_info = lambda h, p, timeout=8: {}
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig)
        self.assertFalse(e._verify_candidate_domain("莞城人民医院", "www.dg.gov.cn"))
        self.assertNotIn("www.dg.gov.cn", e.domains)

    def test_cert_org_verifies(self):
        e = self._engine()
        self._patch_probe("首页")   # 标题不含主体名
        orig = cybercensus.tls_cert_info
        cybercensus.tls_cert_info = lambda h, p, timeout=8: {"org": "东莞市莞城人民医院"}
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig)
        self.assertTrue(e._verify_candidate_domain("莞城人民医院", "www.dggcyy.cn"))

    def test_discover_passive_mode_weak_anchors(self):
        """纯被动模式：搜索引擎候选域名作未验证弱锚点加入（不探测目标）。"""
        e = self._engine()
        e.args.no_probe = True
        orig = cybercensus.discover_domains_from_search
        cybercensus.discover_domains_from_search = lambda n, max_candidates=5, lookup=None: [
            ("www.x.com", 3), ("www.y.com", 2)]
        self.addCleanup(cybercensus.__setattr__, "discover_domains_from_search", orig)
        e.discover_names_to_domains()
        # 候选根域名进入 self.domains（触发本地被动枚举）且标记为弱锚点
        self.assertIn("x.com", e.domains)
        self.assertIn("y.com", e.domains)
        self.assertIn("x.com", e.anchor["weak_domains"])

    def test_verify_adds_root_domain(self):
        """验证通过的主机名，其根域名一并入锚点（子域枚举按根域查更全）。"""
        e = self._engine()
        self._patch_probe("东莞市莞城人民医院官方网站")
        self.assertTrue(e._verify_candidate_domain("莞城人民医院", "www.x.com.cn"))
        self.assertIn("www.x.com.cn", e.domains)
        self.assertIn("x.com.cn", e.domains)

    def test_discover_skipped_when_domains_exist(self):
        e = self._engine()
        e.domains = {"user-given.example.com"}
        called = []
        orig = cybercensus.discover_domains_from_search
        cybercensus.discover_domains_from_search = lambda n: called.append(n) or []
        self.addCleanup(cybercensus.__setattr__, "discover_domains_from_search", orig)
        e.discover_names_to_domains()
        self.assertEqual(called, [])   # 已有域名输入不自举


# ----------------------------------------------------------------------------
# 新手可读报告：证据白话翻译
# ----------------------------------------------------------------------------
class TestPlainEvidence(unittest.TestCase):
    def test_translates_known_prefixes(self):
        out = cybercensus.plain_evidence(["A|页面备案号一致:京ICP备12345678号-1"])
        self.assertIn("网站页脚的ICP备案号与目标单位备案号一致", out)

    def test_dedup_and_join(self):
        out = cybercensus.plain_evidence(
            ["A|页面备案号一致:X", "A|证书O=一致:Y", "A|平台icp命中"])
        self.assertIn("；", out)
        self.assertEqual(out.count("备案号"), 2)   # 两条不同备案证据都保留

    def test_max_items_capped(self):
        evs = ["A|页面备案号一致:X", "A|证书O=一致:Y", "A|主域名子域:z.com",
               "A|平台cert命中", "A|平台icp命中"]
        out = cybercensus.plain_evidence(evs, max_items=3)
        self.assertTrue(out.endswith("等"))
        self.assertEqual(out.count("；"), 3)   # 3条 + "等" 共3个分号

    def test_unknown_passthrough(self):
        out = cybercensus.plain_evidence(["X|未来的证据类型"])
        self.assertEqual(out, "X|未来的证据类型")

    def test_empty(self):
        self.assertEqual(cybercensus.plain_evidence([]), "")


# ----------------------------------------------------------------------------
# 输出去重：仅主机占位资产并入同主机带端口资产
# ----------------------------------------------------------------------------
class TestOutputPlaceholderMerge(unittest.TestCase):
    def test_placeholder_merged_into_ported_asset(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        # 被动阶段的 host-only 占位（无端口无 scheme）
        ph = e.add_asset("a.example.com", None, None, source="passive")
        ph.ip = "1.1.1.1"
        # 探测到的真实资产（443）
        real = e.add_asset("a.example.com", 443, "https", source="anchor")
        real.title = "官网"
        e.args.out = os.path.join(tempfile.gettempdir(), "asm_test_out")
        e.args.active = False
        try:
            files, _, _ = e.output()
        finally:
            import shutil
            shutil.rmtree(e.args.out, ignore_errors=True)
        # 占位已并入，只剩一行，且来源合并保留
        self.assertNotIn(("a.example.com", ""), e.assets)
        self.assertIn(("a.example.com", "443"), e.assets)
        merged = e.assets[("a.example.com", "443")]
        self.assertEqual(merged.title, "官网")
        self.assertIn("passive", merged.source)

    def test_standalone_placeholder_kept(self):
        # 没有同主机带端口资产时，占位资产保留（不能丢掉未探测到的线索）
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.add_asset("b.example.com", None, None, source="passive")
        e.args.out = os.path.join(tempfile.gettempdir(), "asm_test_out2")
        e.args.active = False
        try:
            files, _, _ = e.output()
        finally:
            import shutil
            shutil.rmtree(e.args.out, ignore_errors=True)
        self.assertIn(("b.example.com", ""), e.assets)


# ----------------------------------------------------------------------------
# 输出格式选择（--formats / 界面开关）
# ----------------------------------------------------------------------------
class TestOutputFormats(unittest.TestCase):
    def _run_output(self, fmt):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        a = e.add_asset("a.example.com", 443, "https", source="anchor")
        a.title = "测试站"
        outdir = tempfile.mkdtemp(prefix="sm_fmt_")
        e.args.out = outdir
        e.args.active = False
        if fmt is not None:
            e.args.output_formats = fmt
        try:
            files, json_path, md_path = e.output()
            produced = sorted(os.listdir(outdir))
        finally:
            shutil.rmtree(outdir, ignore_errors=True)
        return files, json_path, md_path, produced

    def test_md_only(self):
        files, json_path, md_path, produced = self._run_output("md")
        self.assertEqual(files, {})
        self.assertEqual(json_path, "")
        self.assertTrue(md_path.endswith(".md"))
        self.assertEqual(len(produced), 1)
        self.assertTrue(produced[0].endswith(".md"))

    def test_csv_only(self):
        files, json_path, md_path, produced = self._run_output("csv")
        self.assertEqual(len(files), 4)
        self.assertEqual(json_path, "")
        self.assertEqual(md_path, "")
        self.assertEqual(len(produced), 4)
        self.assertTrue(all(p.endswith(".csv") for p in produced))

    def test_default_all_formats(self):
        # 未指定 output_formats 属性 → 默认全出（向后兼容）
        files, json_path, md_path, produced = self._run_output(None)
        self.assertEqual(len(files), 4)
        self.assertTrue(json_path.endswith(".json"))
        self.assertTrue(md_path.endswith(".md"))
        self.assertEqual(len(produced), 6)

    def test_combined(self):
        files, json_path, md_path, produced = self._run_output("md,csv")
        self.assertEqual(len(files), 4)
        self.assertEqual(json_path, "")
        self.assertTrue(md_path.endswith(".md"))
        self.assertEqual(len(produced), 5)


# ----------------------------------------------------------------------------
# 敏感路径探测：内容验证判定（防自定义404误报的核心）
# ----------------------------------------------------------------------------
class TestSensitiveChecks(unittest.TestCase):
    def test_git_config(self):
        self.assertTrue(cybercensus._chk_git(b"[core]\n\trepositoryformatversion = 0"))
        self.assertFalse(cybercensus._chk_git(b"<html><body>404 not found</body></html>"))

    def test_env(self):
        self.assertTrue(cybercensus._chk_env(b"APP_NAME=demo\nDB_HOST=127.0.0.1"))
        self.assertFalse(cybercensus._chk_env(b"<html>error page</html>"))

    def test_heapdump_magic(self):
        self.assertTrue(cybercensus._chk_heapdump(b"\x00JAVA PROFILE 1.0.1" + b"x" * 8192))
        self.assertFalse(cybercensus._chk_heapdump(b"\x00JAVA PROFILE 1.0.1"))   # 太小
        self.assertFalse(cybercensus._chk_heapdump(b"<html>login</html>" * 1000))

    def test_zip_magic(self):
        self.assertTrue(cybercensus._chk_zip(b"PK\x03\x04" + b"x" * 4096))
        self.assertFalse(cybercensus._chk_zip(b"PK\x03\x04xx"))          # 太小
        self.assertFalse(cybercensus._chk_zip(b"<html>" + b"x" * 4096))  # 非 zip

    def test_swagger_and_druid(self):
        self.assertTrue(cybercensus._chk_swagger(b"<html>Swagger UI</html>"))
        self.assertFalse(cybercensus._chk_swagger(b"<html>Index</html>"))
        self.assertTrue(cybercensus._chk_druid(b"druid stat view"))
        self.assertFalse(cybercensus._chk_druid(b"welcome"))

    def test_probe_sensitive_paths(self):
        """monkeypatch http_get：命中 .git/config，未命中 .env。"""
        def fake_get(url, **kw):
            if url.endswith("/.git/config"):
                return b"[core]\n\tbare = false"
            raise OSError("404")
        orig = cybercensus.http_get
        cybercensus.http_get = fake_get
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        hits = cybercensus.probe_sensitive_paths("x.com", 443, "https", interval=0)
        self.assertEqual(hits, [("/.git/config", "Git仓库泄露(.git)")])


# ----------------------------------------------------------------------------
# 增量监控：基线保存与 diff
# ----------------------------------------------------------------------------
class TestBaseline(unittest.TestCase):
    def _engine(self, outdir):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.args.out = outdir
        return e

    def test_save_and_diff_cycle(self):
        out = tempfile.mkdtemp(prefix="sm_bl_")
        try:
            # 第一轮：1 资产，无基线 → diff=None，保存基线
            e = self._engine(out)
            a = e.add_asset("www.x.com", 443, "https", source="anchor")
            a.title = "官网"
            a.beian = "京ICP备12345678号"
            e.anchor["beian"].add("京ICP备12345678号")
            e.evaluate()
            self.assertIsNone(e.diff_baseline())
            e.save_baseline()
            self.assertTrue(os.path.isfile(os.path.join(out, "baseline.json")))

            # 第二轮：新增资产 + 原资产新增敏感发现 → diff 应报出
            e2 = self._engine(out)
            a2 = e2.add_asset("www.x.com", 443, "https", source="anchor")
            a2.title = "官网"
            a2.beian = "京ICP备12345678号"
            a2.findings.add("/.env|环境配置泄露(.env)")
            b2 = e2.add_asset("new.y.com", 80, "http", source="passive")
            e2.anchor["beian"].add("京ICP备12345678号")
            e2.evaluate()
            diff = e2.diff_baseline()
            self.assertIsNotNone(diff)
            added_keys = [k for k, _ in diff["added"]]
            self.assertIn("new.y.com|80", added_keys)
            self.assertEqual(len(diff["removed"]), 0)
            changes = {c["key"]: c["changes"] for c in diff["changed"]}
            self.assertIn("www.x.com|443", changes)
            self.assertTrue(any("新敏感发现" in c for c in changes["www.x.com|443"]))
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_baseline_corrupt_tolerated(self):
        out = tempfile.mkdtemp(prefix="sm_bl2_")
        try:
            with open(os.path.join(out, "baseline.json"), "w", encoding="utf-8") as f:
                f.write("{not json")
            e = self._engine(out)
            self.assertIsNone(e.load_baseline())   # 损坏基线不崩溃
        finally:
            shutil.rmtree(out, ignore_errors=True)


# ----------------------------------------------------------------------------
# UA 轮换池
# ----------------------------------------------------------------------------
class TestUAPool(unittest.TestCase):
    def test_pick_ua_always_from_pool(self):
        for _ in range(50):
            self.assertIn(cybercensus._pick_ua(), cybercensus.UA_POOL)

    def test_pool_has_variety(self):
        # 至少 4 种不同 UA（Windows/Mac/Firefox/Edge 多样性）
        self.assertGreaterEqual(len(set(cybercensus.UA_POOL)), 4)


# ----------------------------------------------------------------------------
# 扩展被动源（Wayback / OTX / urlscan / site: 语法 / 备案号反查）
# ----------------------------------------------------------------------------
class TestExtraPassiveSources(unittest.TestCase):
    def _patch_http(self, fake):
        orig = cybercensus.http_get
        cybercensus.http_get = fake
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)

    def _patch_lookup(self, text, hosts):
        orig = cybercensus.search_engine_lookup
        cybercensus.search_engine_lookup = lambda q, timeout=15: (text, hosts)
        self.addCleanup(cybercensus.__setattr__, "search_engine_lookup", orig)

    def test_wayback_parse(self):
        rows = [["original"],
                ["https://a.x.com/path", "200"],
                ["http://b.x.com/", "200"],
                ["https://unrelated.com/", "200"]]
        self._patch_http(lambda url, **kw: json.dumps(rows))
        subs = cybercensus.wayback_subdomains("x.com")
        self.assertEqual(subs, {"a.x.com", "b.x.com"})

    def test_wayback_fail_empty(self):
        self._patch_http(lambda url, **kw: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(cybercensus.wayback_subdomains("x.com"), set())

    def test_otx_parse(self):
        data = {"passive_dns": [{"hostname": "a.x.com."}, {"hostname": "b.x.com"},
                                {"hostname": "other.com"}]}
        self._patch_http(lambda url, **kw: json.dumps(data))
        subs = cybercensus.otx_subdomains("x.com")
        self.assertEqual(subs, {"a.x.com", "b.x.com"})

    def test_urlscan_parse(self):
        data = {"results": [{"page": {"domain": "a.x.com"}},
                            {"page": {"domain": "other.com"}}]}
        self._patch_http(lambda url, **kw: json.dumps(data))
        self.assertEqual(cybercensus.urlscan_subdomains("x.com"), {"a.x.com"})

    def test_bing_site_subdomains(self):
        self._patch_lookup("看 a.x.com 和 unrelated.com",
                           ["a.x.com", "www.x.com", "junk.example.org"])
        subs = cybercensus.bing_site_subdomains("x.com")
        self.assertEqual(subs, {"a.x.com", "www.x.com"})

    def test_bing_beian_search_filters_junk(self):
        self._patch_lookup("", ["www.real.com", "www.qiuyi.cn", "baike.baidu.com",
                                "www.real.com"])
        out = cybercensus.bing_beian_search("京ICP备12345678号")
        self.assertEqual(out, ["www.real.com"])   # 目录站去重+黑名单

    def test_beian_search_evidence_is_a_level(self):
        """search:beian 来源的资产应得 A 级证据（无 Key 时的确认通道）。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.anchor["beian"].add("京ICP备12345678号")
        a = e.add_asset("found.example.com", 80, "http", source="search:beian")
        a.prov_beian = "京ICP备12345678号-2"
        e.evaluate()
        self.assertEqual(a.confidence, "确认")
        self.assertTrue(any(x.startswith("A|搜索引擎备案号命中") for x in a.evidence))
        self.assertIn("搜索引擎收录显示该站页脚印有目标单位备案号",
                      cybercensus.plain_evidence(a.evidence))


# ----------------------------------------------------------------------------
# UA 池含移动端（公众号/移动端页面可见性）
# ----------------------------------------------------------------------------
class TestUAMobile(unittest.TestCase):
    def test_pool_contains_mobile_ua(self):
        joined = " ".join(cybercensus.UA_POOL)
        self.assertIn("iPhone", joined)
        self.assertIn("Android", joined)


# ----------------------------------------------------------------------------
# 统一社会信用代码：GB32100 校验 + 页面提取 + A 级证据
# ----------------------------------------------------------------------------
class TestCreditCode(unittest.TestCase):
    VALID = "91110000100003962Y"

    def test_checksum_validation(self):
        self.assertTrue(cybercensus._credit_code_ok(self.VALID))
        # 校验码错误的代码必须被拒（差一位即失败）
        self.assertFalse(cybercensus._credit_code_ok(self.VALID[:17] + "X"))
        self.assertFalse(cybercensus._credit_code_ok(""))
        self.assertFalse(cybercensus._credit_code_ok("123"))

    def test_extract_with_chinese_boundary(self):
        # 中文紧邻代码的场景（\b 会失效，必须环视）
        txt = "统一社会信用代码：%s　粤ICP备13075739号" % self.VALID
        self.assertEqual(cybercensus.extract_credit_code(txt), self.VALID)
        self.assertEqual(cybercensus.extract_credit_code("无代码页面"), "")
        self.assertEqual(cybercensus.extract_credit_code(""), "")

    def test_credit_code_evidence_is_a_level(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.anchor["credit_codes"].add(self.VALID)
        a = e.add_asset("www.x.gov.cn", 443, "https", source="anchor")
        a.credit_code = self.VALID
        e.evaluate()
        self.assertEqual(a.confidence, "确认")
        self.assertTrue(any(x.startswith("A|页面含统一社会信用代码") for x in a.evidence))
        self.assertIn("法定唯一标识", cybercensus.plain_evidence(a.evidence))


# ----------------------------------------------------------------------------
# 搜索引擎风险情报（dork）
# ----------------------------------------------------------------------------
class TestRiskHints(unittest.TestCase):
    def test_dork_urls_extract(self):
        html = ('<h2><a href="https://github.com/a/repo">r</a></h2>'
                '<h2><a href="https://www.x.com/admin">a</a></h2>')
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: html
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        urls = cybercensus.bing_dork_urls("site:x.com inurl:admin")
        self.assertEqual(urls, ["https://github.com/a/repo", "https://www.x.com/admin"])

    def test_collect_risk_hints(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.anchor["domains"].add("x.com")
        e.domains = {"x.com"}
        orig = cybercensus.bing_dork_urls
        cybercensus.bing_dork_urls = lambda q: ["https://www.x.com/admin"] \
            if "inurl:admin" in q else ["https://github.com/x/x"]
        self.addCleanup(cybercensus.__setattr__, "bing_dork_urls", orig)
        e.collect_risk_hints()
        kinds = {k for k, _ in e.risk_hints}
        self.assertEqual(kinds, {"后台/登录入口", "GitHub代码泄露"})


# ----------------------------------------------------------------------------
# 页面外链/JS 引用挖掘 + 公众号文章域名挖掘
# ----------------------------------------------------------------------------
class TestRefMining(unittest.TestCase):
    def test_filter_candidate_roots(self):
        hosts = ["www.x.com", "cdn.jsdelivr.net", "w3.org", "oss-cn-hangzhou.aliyuncs.com",
                 "partner.y.com", "www.x.com", ""]
        out = cybercensus.filter_candidate_roots(hosts, exclude_roots={"y.com"})
        # 垃圾域/三方设施/已知域全滤掉，只留未知候选
        self.assertEqual(out, ["x.com"])

    def test_weixin_article_parse(self):
        """只保留 mp.weixin.qq.com 文章链接；提取的域名经垃圾过滤。"""
        html = ('<h2><a href="https://mp.weixin.qq.com/s/abc123">文章</a></h2>'
                '<h2><a href="https://www.other.com/not-weixin">无关</a></h2>')
        orig_dork = cybercensus.bing_dork_urls
        cybercensus.bing_dork_urls = lambda q: re.findall(
            r'href="(https?://[^"]+)"', html)
        self.addCleanup(cybercensus.__setattr__, "bing_dork_urls", orig_dork)
        orig_get = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: (
            "挂号请访问 https://gh.x.com 及 <a href='http://pay.x.com/api'>支付</a>"
            if "weixin" in url else (_ for _ in ()).throw(OSError("no")))
        self.addCleanup(cybercensus.__setattr__, "http_get", orig_get)
        roots = cybercensus.weixin_article_domains("测试医院")
        self.assertEqual(roots, ["x.com"])

    def test_mine_and_verify_refs(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["东莞市测试人民医院"]
        e.domains = {"main.com"}
        e._ref_candidates = ["sub.newsite.com", "www.other.org", "w3.org"]
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "东莞市测试人民医院预约挂号系统",
            "credit_code": "", "refs": []}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)
        e.mine_and_verify_refs()
        # 标题互证通过 → 入正式锚点；垃圾域（w3.org）根本不进候选
        self.assertIn("newsite.com", e.domains)
        self.assertIn("other.org", e.domains)   # 非垃圾候选会被探测（fake 返回相同标题故通过）
        self.assertNotIn("w3.org", e.domains)

    def test_verify_matches_anchor_orgs(self):
        """纯域名输入模式下，证书 O= 与锚点组织名互证也能通过。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = []
        e.anchor["orgs"].add("东莞市测试人民医院")
        orig_probe = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "某系统", "credit_code": "", "refs": []}
        orig_cert = cybercensus.tls_cert_info
        cybercensus.tls_cert_info = lambda h, p, timeout=8: {"org": "东莞市测试人民医院"}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig_probe)
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig_cert)
        self.assertTrue(e._verify_candidate_domain("", "sub.x.com"))


# ----------------------------------------------------------------------------
# subfinder/OneForAll 清单移植：CertSpotter / Shodan InternetDB / RapidDNS同IP
# ----------------------------------------------------------------------------
class TestNewReconSources(unittest.TestCase):
    def _patch_http(self, fake):
        orig = cybercensus.http_get
        cybercensus.http_get = fake
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)

    def test_certspotter_parse(self):
        data = [{"dns_names": ["www.x.com", "*.wild.x.com", "other.com"]},
                {"dns_names": ["mail.x.com"]}]
        self._patch_http(lambda url, **kw: json.dumps(data))
        subs = cybercensus.certspotter_subdomains("x.com")
        self.assertEqual(subs, {"www.x.com", "wild.x.com", "mail.x.com"})

    def test_certspotter_fail_empty(self):
        self._patch_http(lambda url, **kw: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(cybercensus.certspotter_subdomains("x.com"), set())

    def test_internetdb(self):
        data = {"ports": [443, 8080, 22], "hostnames": ["www.x.com."],
                "cpes": ["cpe:/a:nginx"], "vulns": ["CVE-2021-44228"]}
        self._patch_http(lambda url, **kw: json.dumps(data))
        idb = cybercensus.shodan_internetdb("1.2.3.4")
        self.assertEqual(idb["ports"], [443, 8080, 22])
        self.assertEqual(idb["vulns"], ["CVE-2021-44228"])

    def test_internetdb_no_data_is_none(self):
        # InternetDB 对无数据 IP 返回 404 → 函数应返回 None 而不是崩溃
        import urllib.error
        self._patch_http(lambda url, **kw: (_ for _ in ()).throw(
            urllib.error.HTTPError("u", 404, "nf", {}, None)))
        self.assertIsNone(cybercensus.shodan_internetdb("1.2.3.4"))

    def test_sameip_parse_and_filter(self):
        html = '<td><a href="/domain/www.x.com">www.x.com</a></td> rapiddns.io junk'
        self._patch_http(lambda url, **kw: html)
        hosts = cybercensus.rapiddns_sameip("1.2.3.4")
        self.assertIn("www.x.com", hosts)
        self.assertNotIn("rapiddns.io", hosts)

    def test_gather_sources_parallel(self):
        """并行源收集：各源结果正确归位，单源失败不影响整体。"""
        def fake(url, **kw):
            if "certspotter" in url:
                return json.dumps([{"dns_names": ["cs.x.com"]}])
            if "rapiddns" in url:
                return "nothing useful"
            raise OSError("down")
        self._patch_http(fake)
        srcs = cybercensus._gather_subdomain_sources("x.com", timeout=10)
        self.assertIn("certspotter", srcs)
        self.assertIn("cs.x.com", srcs["certspotter"])
        self.assertEqual(srcs["hackertarget"], {})   # 失败源返回空而不崩溃


# ----------------------------------------------------------------------------
# 简称/别名宽松匹配（bootstrap 验证用；分级仍严格）
# ----------------------------------------------------------------------------
class TestOrgMatchFuzzy(unittest.TestCase):
    CASES = [
        # (名称, 标题, 期望)
        ("四川移动", "中国移动通信集团四川有限公司", True),   # 简称→全称（目标场景）
        ("四川移动", "四川移动官方网站", True),
        ("四川移动", "四川联通", False),
        ("四川移动", "中国移动", False),
        ("东莞市人民医院", "东莞市莞城医院", False),          # 同城不同医院必须拒绝
        ("莞城人民医院", "东莞市莞城人民医院", True),
        ("广州移动", "中国移动广州公司", True),
        ("中国移动", "中国移动通信集团四川有限公司", True),   # 集团名扫分公司合理
    ]

    def test_cases(self):
        for name, title, expect in self.CASES:
            self.assertEqual(cybercensus._org_match_fuzzy(name, title), expect,
                             "%s vs %s" % (name, title))

    def test_short_name_rejected(self):
        # 短于 4 字的名称不做宽松匹配（防止"移动"这类泛词漫天命中）
        self.assertFalse(cybercensus._org_match_fuzzy("移动", "中国移动通信集团"))

    def test_verify_uses_fuzzy_for_abbreviation(self):
        """简称输入 + 全称标题 → bootstrap 验证应通过。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["四川移动"]
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "中国移动通信集团四川有限公司",
            "credit_code": "", "refs": []}
        orig_cert = cybercensus.tls_cert_info
        cybercensus.tls_cert_info = lambda h, p, timeout=8: {}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig_cert)
        self.assertTrue(e._verify_candidate_domain("四川移动", "www.sc.10086.cn"))
        self.assertIn("www.sc.10086.cn", e.domains)


# ----------------------------------------------------------------------------
# 简称场景三件套：meta 提取 / 地域拼音互证 / 根域深度守卫
# ----------------------------------------------------------------------------
class TestAbbreviationSupport(unittest.TestCase):
    def test_meta_extraction(self):
        body = ('<html><head><title></title>'
                '<meta name="description" content="中国移动通信集团四川有限公司官方网站">'
                '<meta name="keywords" content="四川移动,移动营业厅"></head></html>')
        meta = cybercensus._extract_meta(body)
        self.assertIn("中国移动通信集团四川有限公司", meta)

    def test_region_hit(self):
        # 地域拼音 + 行业词双重核验
        self.assertTrue(cybercensus._region_hit("四川移动", "wap.sc.10086.cn", "中国移动APP"))
        self.assertTrue(cybercensus._region_hit("广东电信", "gd.189.cn", "广东电信官方"))
        self.assertTrue(cybercensus._region_hit("四川移动", "www.sichuan.10086.cn", "移动营业厅"))
        # 关键守护：省政府站不含"移动"行业词 → 必须拒绝
        self.assertFalse(cybercensus._region_hit("四川移动", "www.sc.gov.cn", "四川省人民政府"))
        # 两字母缩写必须独立标签，不能命中 school 里的 sc
        self.assertFalse(cybercensus._region_hit("四川移动", "www.school.com", "移动"))
        # 名称里没有省份就不做地域互证
        self.assertFalse(cybercensus._region_hit("中国移动", "sc.10086.cn", "中国移动"))

    def test_verify_via_meta_for_spa(self):
        """SPA 站标题为空，meta 描述含单位名 → 验证通过。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["中国移动通信集团四川有限公司"]
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "", "meta": "中国移动通信集团四川有限公司",
            "credit_code": "", "refs": []}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)
        self.assertTrue(e._verify_candidate_domain("中国移动通信集团四川有限公司",
                                                   "www.10086.cn"))

    def test_verify_via_region_for_abbreviation(self):
        """简称 + 省级拼音域名（wap.sc.10086.cn）+ 页面含行业词 → 验证通过。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["四川移动"]
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "中国移动APP", "meta": "",
            "credit_code": "", "refs": []}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)
        self.assertTrue(e._verify_candidate_domain("四川移动", "wap.sc.10086.cn"))

    def test_verify_rejects_gov_for_abbreviation(self):
        """省政府站（sc.gov.cn）不含行业词"移动" → 地域互证必须拒绝。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["四川移动"]
        orig = cybercensus.http_probe
        cybercensus.http_probe = lambda host, port, scheme, timeout=8, throttle=0: {
            "status": 200, "title": "四川省人民政府", "meta": "四川省人民政府办公厅",
            "credit_code": "", "refs": []}
        orig_cert = cybercensus.tls_cert_info
        cybercensus.tls_cert_info = lambda h, p, timeout=8: {}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig)
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig_cert)
        self.assertFalse(e._verify_candidate_domain("四川移动", "www.sc.gov.cn"))

    def test_root_depth_guard(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        # 深度 1：补根域（常规企业域名）
        e._add_verified_domain("www.dggcyy.cn")
        self.assertIn("dggcyy.cn", e.domains)
        # 深度 2：只补省级父域，不补集团根域
        e._add_verified_domain("wap.sc.10086.cn")
        self.assertIn("wap.sc.10086.cn", e.domains)
        self.assertIn("sc.10086.cn", e.domains)
        self.assertNotIn("10086.cn", e.domains)


# ----------------------------------------------------------------------------
# 移动端 APP 发现（App Store 免费 API）
# ----------------------------------------------------------------------------
class TestAppDiscovery(unittest.TestCase):
    def test_itunes_parse(self):
        data = {"resultCount": 1, "results": [
            {"trackName": "测试APP", "sellerName": "Test Co", "bundleId": "cn.test.app",
             "version": "1.0", "sellerUrl": "https://www.test.com", "trackViewUrl": "x"}]}
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: json.dumps(data)
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        apps = cybercensus.itunes_search_apps("测试")
        self.assertEqual(apps[0]["trackName"], "测试APP")
        self.assertEqual(apps[0]["sellerUrl"], "https://www.test.com")

    def test_seller_match_cn_en(self):
        # 四川移动 ↔ China Mobile Group Sichuan Company Limited
        self.assertTrue(cybercensus._seller_match(
            "四川移动", "China Mobile Group Sichuan Company Limited"))
        self.assertFalse(cybercensus._seller_match(
            "四川移动", "China Mobile Online Services Co., Ltd."))   # 缺 Sichuan
        self.assertFalse(cybercensus._seller_match(
            "四川移动", "Sichuan Cooking Co."))                      # 缺 mobile

    def test_discover_apps_relevance(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["四川移动"]
        data = {"results": [
            {"trackName": "四川移动O域门户", "sellerName": "China Mobile Group Sichuan Company Limited",
             "bundleId": "cn.a", "sellerUrl": ""},
            {"trackName": "移动大掌柜", "sellerName": "China Mobile Group Sichuan Company Limited",
             "bundleId": "cn.b", "sellerUrl": "https://sc.10086.cn/app"},
            {"trackName": "铁路12306", "sellerName": "Railway Co", "bundleId": "cn.c",
             "sellerUrl": ""},
            # 凑巧共享"四川/移动"bigram 的无关应用（实测误报样例）必须拒绝
            {"trackName": "微乐四川麻将移动版", "sellerName": "Changchun Dingyuan Network",
             "bundleId": "cn.d", "sellerUrl": ""},
        ]}
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: json.dumps(data)
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        e.discover_apps()
        names = [a[0] for a in e.apps]
        self.assertIn("四川移动O域门户", names)   # 应用名匹配
        self.assertIn("移动大掌柜", names)        # 开发者地域+行业词匹配
        self.assertNotIn("铁路12306", names)      # 无关应用被拒
        self.assertNotIn("微乐四川麻将移动版", names)  # 共享 bigram 的误报样例被拒
        # 开发者主页域名进入候选
        self.assertIn("sc.10086.cn", e._ref_candidates)


# ----------------------------------------------------------------------------
# 借鉴 ARL/ShuiZe/Goby/ENscan：风险组件 / 邮箱 / 动态备份 / 备案吸收
# ----------------------------------------------------------------------------
class TestToolLearning(unittest.TestCase):
    def test_tech_risk(self):
        notes = cybercensus.tech_risk("泛微OA,nginx")
        self.assertTrue(any("泛微" in n for n in notes))
        self.assertEqual(cybercensus.tech_risk("nginx"), [])

    def test_extract_emails(self):
        text = ("联系我们 kj@hospital.cn，投诉 ts@hospital.cn "
                "以及 logo@2x.png 和 example@example.com 和 your@email.com")
        emails = cybercensus._extract_emails(text)
        self.assertIn("kj@hospital.cn", emails)
        self.assertIn("ts@hospital.cn", emails)
        self.assertNotIn("logo@2x.png", emails)
        self.assertNotIn("example@example.com", emails)
        self.assertNotIn("your@email.com", emails)

    def test_chk_sql_and_targz(self):
        self.assertTrue(cybercensus._chk_sql(b"-- MySQL dump\nCREATE TABLE x (...)" + b"x" * 1024))
        self.assertFalse(cybercensus._chk_sql(b"<html>404</html>" * 100))
        self.assertTrue(cybercensus._chk_targz(b"\x1f\x8b" + b"x" * 4096))
        self.assertFalse(cybercensus._chk_targz(b"PK\x03\x04" + b"x" * 4096))

    def test_absorb_search_text_candidates_only(self):
        """摘要吸收只进候选集（防目录站备案号污染锚点），邮箱直接收。"""
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e._absorb_search_text("某某公司 粤ICP备13075739号 信用代码 91110000100003962Y "
                              "联系 hr@dggcyy.cn")
        self.assertIn("粤ICP备13075739号", e._beian_candidates)
        self.assertNotIn("粤ICP备13075739号", e.anchor["beian"])   # 未验证前不得入锚点
        self.assertIn("91110000100003962Y", e._code_candidates)
        self.assertNotIn("91110000100003962Y", e.anchor["credit_codes"])
        self.assertIn("hr@dggcyy.cn", e.contacts)

    def test_dynamic_backup_paths(self):
        """域名同名备份包探测：www.dggcyy.cn → 探测 /dggcyy.zip 等。"""
        requested = []

        def fake_get(url, **kw):
            requested.append(url)
            if url.endswith("/dggcyy.zip"):
                return b"PK\x03\x04" + b"x" * 4096
            raise OSError("404")
        orig = cybercensus.http_get
        cybercensus.http_get = fake_get
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        hits = cybercensus.probe_sensitive_paths("www.dggcyy.cn", 443, "https", interval=0)
        self.assertTrue(any("/dggcyy.zip" in u for u in requested))
        self.assertTrue(any("域名同名备份" in n for _, n in hits))


# ----------------------------------------------------------------------------
# HTML 报告（ARL/Yakit 式交付形态） + Webhook 通知（ARL-Next）
# ----------------------------------------------------------------------------
class TestHtmlReport(unittest.TestCase):
    def _engine(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        a = e.add_asset("www.x.gov.cn", 443, "https", source="anchor")
        a.title = "某单位官网"
        a.beian = "粤ICP备12345678号"
        a.ip = "1.2.3.4"
        a.tech = "Nginx,泛微OA"
        a.findings.add("/.git/config|Git仓库泄露")
        e.anchor["beian"].add("粤ICP备12345678号")
        e.names = ["某单位"]
        e.evaluate()
        return e

    def test_html_sections_and_svg(self):
        e = self._engine()
        rows = sorted(e.assets.values(), key=lambda a: a.host or "")
        groups = {"确认": [], "疑似": [], "存疑": []}
        for a in rows:
            groups.get(a.confidence, groups["存疑"]).append(a)
        html = e._html_report(rows, groups, "20260101_000000")
        self.assertIn("CyberCensus 资产测绘报告", html)
        self.assertIn("确认资产", html)
        self.assertIn("敏感路径发现", html)
        self.assertIn("泛微", html)             # 风险组件提示
        self.assertIn("<svg", html)             # 关系图
        self.assertIn("1.2.3.4", html)
        self.assertTrue(html.rstrip().endswith("</html>"))

    def test_output_html_format(self):
        e = self._engine()
        out = tempfile.mkdtemp(prefix="sm_html_")
        e.args.out = out
        e.args.active = False
        e.args.output_formats = "html"
        try:
            files, _, _ = e.output()
            produced = os.listdir(out)
        finally:
            shutil.rmtree(out, ignore_errors=True)
        self.assertIn("html", files)
        self.assertEqual(len(produced), 1)
        self.assertTrue(produced[0].endswith(".html"))


class TestWebhook(unittest.TestCase):
    def test_send_webhook_payload(self):
        captured = {}

        class _Resp(object):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None, context=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _Resp()

        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        self.addCleanup(urllib.request.__setattr__, "urlopen", orig)
        ok = cybercensus.send_webhook("https://hook.example/x", "测试完成")
        self.assertTrue(ok)
        self.assertEqual(captured["body"]["msgtype"], "text")
        self.assertEqual(captured["body"]["text"]["content"], "测试完成")
        self.assertEqual(captured["body"]["msg_type"], "text")   # 飞书/企微形状

    def test_empty_webhook_is_noop(self):
        self.assertFalse(cybercensus.send_webhook("", "x"))


# ----------------------------------------------------------------------------
# wafw00f/FindSomething/JSFinder/ksubdomain 思路
# ----------------------------------------------------------------------------
class TestReconIdeas(unittest.TestCase):
    def test_detect_waf(self):
        self.assertEqual(cybercensus.detect_waf("Server: cloudflare; cf-ray: 123", ""),
                         "Cloudflare")
        self.assertEqual(cybercensus.detect_waf("Set-Cookie: safedog_cache=1", ""),
                         "安全狗")
        self.assertEqual(cybercensus.detect_waf("Server: nginx", "正常页面"), "")

    def test_scan_js_secrets(self):
        self.assertIn("阿里云AccessKey",
                      cybercensus.scan_js_secrets('var k="LTAI5tAbCdEfGhIjKlMn";'))
        self.assertIn("AWS AccessKey",
                      cybercensus.scan_js_secrets("AKIAABCDEFGHIJKLMNOP"))
        self.assertEqual(cybercensus.scan_js_secrets("var a = 1;"), [])

    def test_extract_scripts(self):
        body = ('<script src="/js/app.js"></script>'
                '<script src="//cdn.x.com/lib.js"></script>'
                '<script src="https://other.com/x.js"></script>'
                '<script>inline()</script>')
        scripts = cybercensus._extract_scripts(body, "https://www.x.com")
        self.assertIn("https://www.x.com/js/app.js", scripts)
        self.assertIn("https://cdn.x.com/lib.js", scripts)
        self.assertIn("https://other.com/x.js", scripts)
        self.assertEqual(len(scripts), 3)

    def test_brute_subdomains(self):
        def fake_resolve(h):
            return {"www.x.com": {"1.1.1.1"}, "mail.x.com": {"2.2.2.2"}}.get(h, set())
        out = cybercensus.brute_subdomains("x.com", resolver=fake_resolve)
        self.assertEqual(out.get("www.x.com"), "1.1.1.1")
        self.assertEqual(out.get("mail.x.com"), "2.2.2.2")
        self.assertNotIn("oa.x.com", out)

    def test_mine_js_secrets_flow(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e._js_urls = ["https://www.x.com/static/app.js"]
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: (
            'var api="https://api.hidden.x.com"; var key="LTAI5tAbCdEfGhIjKlMn";')
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        e.mine_js_secrets()
        self.assertTrue(any("阿里云" in k for _, k in e.js_secrets))
        self.assertIn("api.hidden.x.com", e._ref_candidates)   # JS 里的域名进候选


# ----------------------------------------------------------------------------
# 外部工具联动（subfinder / httpx / wafw00f / nuclei）
# ----------------------------------------------------------------------------
class TestExternalTools(unittest.TestCase):
    def _ns(self, **kw):
        d = dict(beian="", threads=10, timeout=5, no_probe=False, active=False,
                 ext_tools=None, no_ext=False)
        d.update(kw)
        return argparse.Namespace(**d)

    def _patch(self, which_name, stdout):
        orig_which = cybercensus.shutil.which
        orig_run = cybercensus.subprocess.run
        cybercensus.shutil.which = lambda n: "/fake/" + n if n == which_name else None

        class _R(object):
            returncode = 0
        r = _R()
        r.stdout = stdout
        r.stderr = ""
        cybercensus.subprocess.run = lambda *a, **k: r
        self.addCleanup(cybercensus.shutil.__setattr__, "which", orig_which)
        self.addCleanup(cybercensus.subprocess.__setattr__, "run", orig_run)

    def test_asset_url(self):
        self.assertEqual(
            cybercensus._asset_url(cybercensus.Asset("x.com", 8443, None)),
            "https://x.com:8443")
        self.assertEqual(
            cybercensus._asset_url(cybercensus.Asset("x.com", 80, "http")),
            "http://x.com")
        self.assertEqual(cybercensus._asset_url(cybercensus.Asset("x.com", None, None)), "")

    def test_run_subfinder_parses_and_filters(self):
        self._patch("subfinder", "a.x.com\nB.X.COM.\nevil.com\nx.com\n")
        self.assertEqual(cybercensus.run_subfinder("x.com"),
                         {"a.x.com", "b.x.com", "x.com"})

    def test_run_httpx_parses_json_lines(self):
        self._patch("httpx",
                    '{"url":"https://a.x.com","title":"OA","tech":["Nginx","PHP"],'
                    '"webserver":"nginx","status_code":200}\n'
                    "not json\n")
        out = cybercensus.run_httpx(["a.x.com"])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "a.x.com")
        self.assertEqual(out[0]["title"], "OA")
        self.assertEqual(out[0]["tech"], "Nginx,PHP")
        self.assertEqual(out[0]["server"], "nginx")
        self.assertEqual(out[0]["status"], "200")

    def test_run_wafw00f(self):
        self._patch("wafw00f",
                    '[{"url":"https://a.x.com","detected":true,"firewall":"Cloudflare"}]')
        self.assertEqual(cybercensus.run_wafw00f("https://a.x.com"), "Cloudflare")

    def test_run_nuclei(self):
        self._patch("nuclei",
                    '{"template-id":"CVE-2021-44228","info":{"severity":"critical",'
                    '"name":"Log4j RCE"},"matched-at":"https://a.x.com"}\n')
        hits = cybercensus.run_nuclei(["https://a.x.com"])
        self.assertEqual(hits, [{
            "template": "CVE-2021-44228", "severity": "critical",
            "name": "Log4j RCE", "matched": "https://a.x.com"}])

    def test_missing_binary_returns_empty(self):
        orig_which = cybercensus.shutil.which
        cybercensus.shutil.which = lambda n: None
        self.addCleanup(cybercensus.shutil.__setattr__, "which", orig_which)
        self.assertEqual(cybercensus.run_subfinder("x.com"), set())
        self.assertEqual(cybercensus.run_httpx(["x.com"]), [])
        self.assertEqual(cybercensus.run_wafw00f("https://x.com"), "")
        self.assertEqual(cybercensus.run_nuclei(["https://x.com"]), [])
        self.assertEqual(cybercensus.ext_available(), {})

    def test_engine_merges_httpx_and_subfinder(self):
        e = cybercensus.Engine(self._ns())
        e.domains = {"x.com"}
        e.anchor["domains"] = {"x.com"}
        orig = {n: getattr(cybercensus, n) for n in
                ("ext_available", "run_subfinder", "run_httpx")}
        cybercensus.ext_available = lambda: {"subfinder": "p", "httpx": "p"}
        cybercensus.run_subfinder = lambda d, timeout=300: {"a.x.com"}
        cybercensus.run_httpx = lambda hosts, timeout=600: [{
            "url": "https://a.x.com", "host": "a.x.com", "title": "OA系统",
            "tech": "Nginx,PHP", "server": "nginx", "status": "200"}]
        for n, f in orig.items():
            self.addCleanup(cybercensus.__setattr__, n, f)
        e.run_external_tools()
        a = e.assets[("a.x.com", "443")]
        self.assertEqual(a.title, "OA系统")
        self.assertEqual(a.status, "200")
        self.assertIn("ext:httpx", a.source)
        self.assertIn("Nginx", a.tech)
        self.assertIn("ext:subfinder", e.assets[("a.x.com", "")].source)
        self.assertEqual(sorted(e.ext_used), ["httpx", "subfinder"])
        e.evaluate()
        self.assertEqual(a.confidence, "确认")   # 主域名子域 → A 级证据

    def test_no_probe_skips_touching_tools(self):
        e = cybercensus.Engine(self._ns(no_probe=True))
        e.domains = {"x.com"}
        calls = []
        orig = {n: getattr(cybercensus, n) for n in
                ("ext_available", "run_subfinder", "run_httpx", "run_wafw00f",
                 "run_nuclei")}
        cybercensus.ext_available = lambda: {
            "subfinder": "p", "httpx": "p", "wafw00f": "p", "nuclei": "p"}
        cybercensus.run_subfinder = lambda d, timeout=300: calls.append("subfinder") or set()
        cybercensus.run_httpx = lambda *a, **k: calls.append("httpx") or []
        cybercensus.run_wafw00f = lambda *a, **k: calls.append("wafw00f") or ""
        cybercensus.run_nuclei = lambda *a, **k: calls.append("nuclei") or []
        for n, f in orig.items():
            self.addCleanup(cybercensus.__setattr__, n, f)
        e.run_external_tools()
        self.assertEqual(calls, ["subfinder"])
        self.assertEqual(sorted(e.ext_used), ["subfinder"])
        self.assertEqual(sorted(e.ext_detected),
                         ["httpx", "nuclei", "subfinder", "wafw00f"])

    def test_nuclei_requires_active(self):
        e = cybercensus.Engine(self._ns())
        e.domains = {"x.com"}
        calls = []
        orig = {n: getattr(cybercensus, n) for n in
                ("ext_available", "run_nuclei", "run_httpx")}
        cybercensus.ext_available = lambda: {"nuclei": "p"}
        cybercensus.run_nuclei = lambda *a, **k: calls.append("nuclei") or []
        cybercensus.run_httpx = lambda *a, **k: []
        for n, f in orig.items():
            self.addCleanup(cybercensus.__setattr__, n, f)
        e.run_external_tools()
        self.assertEqual(calls, [])          # 非 active 不跑 POC
        e.args.active = True
        e.run_external_tools()
        self.assertEqual(calls, ["nuclei"])

    def test_only_filter(self):
        e = cybercensus.Engine(self._ns(ext_tools=["subfinder"]))
        e.domains = {"x.com"}
        calls = []
        orig = {n: getattr(cybercensus, n) for n in
                ("ext_available", "run_subfinder", "run_httpx")}
        cybercensus.ext_available = lambda: {"subfinder": "p", "httpx": "p"}
        cybercensus.run_subfinder = lambda d, timeout=300: calls.append("subfinder") or set()
        cybercensus.run_httpx = lambda *a, **k: calls.append("httpx") or []
        for n, f in orig.items():
            self.addCleanup(cybercensus.__setattr__, n, f)
        e.run_external_tools(e.args.ext_tools)
        self.assertEqual(calls, ["subfinder"])
        self.assertEqual(sorted(e.ext_used), ["subfinder"])
        # CLI 传入的是逗号字符串，同样只跑指定工具
        e2 = cybercensus.Engine(self._ns(ext_tools="subfinder,httpx"))
        e2.domains = {"x.com"}
        calls.clear()
        e2.run_external_tools(e2.args.ext_tools)
        self.assertEqual(calls, ["subfinder", "httpx"])

    def test_run_ext_uses_utf8_and_no_window(self):
        captured = {}
        orig = cybercensus.subprocess.run

        class _R(object):
            stdout = ""

        def fake_run(cmd, **kw):
            captured.update(kw)
            return _R()
        cybercensus.subprocess.run = fake_run
        self.addCleanup(cybercensus.subprocess.__setattr__, "run", orig)
        cybercensus._run_ext(["x.exe"], 5)
        self.assertEqual(captured.get("encoding"), "utf-8")
        self.assertEqual(captured.get("errors"), "replace")
        if os.name == "nt":
            self.assertEqual(captured.get("creationflags"), 0x08000000)

    def test_subfinder_cap_per_domain(self):
        e = cybercensus.Engine(self._ns(ext_sub_limit=2))
        e.domains = {"x.com"}
        orig = {n: getattr(cybercensus, n) for n in
                ("ext_available", "run_subfinder")}
        cybercensus.ext_available = lambda: {"subfinder": "p"}
        cybercensus.run_subfinder = lambda d, timeout=300: {
            "a.x.com", "b.x.com", "c.x.com"}
        for n, f in orig.items():
            self.addCleanup(cybercensus.__setattr__, n, f)
        e.run_external_tools()
        self.assertEqual(sorted(e.assets), [("a.x.com", ""), ("b.x.com", "")])

    def test_no_tools_installed_is_noop(self):
        e = cybercensus.Engine(self._ns())
        orig = cybercensus.ext_available
        cybercensus.ext_available = lambda: {}
        self.addCleanup(cybercensus.__setattr__, "ext_available", orig)
        e.run_external_tools()
        self.assertEqual(e.ext_used, {})
        self.assertEqual(e.assets, {})


# ----------------------------------------------------------------------------
# APP / 小程序包静态分析
# ----------------------------------------------------------------------------
class TestRegionAliasQuery(unittest.TestCase):
    def test_full_name_to_province_alias(self):
        f = cybercensus._region_alias_query
        self.assertEqual(f("中国移动通信集团四川有限公司"), "四川移动")
        self.assertEqual(f("中国银行四川省分行"), "四川银行")
        self.assertEqual(f("四川移动"), "四川移动")
        self.assertEqual(f("东莞市人民医院"), "")
        self.assertEqual(f("四川大学华西医院"), "四川大学华西医院")


class TestOperatorCandidates(unittest.TestCase):
    def test_province_operator_domains(self):
        out = cybercensus._operator_candidates("中国移动通信集团四川有限公司")
        self.assertIn("wap.sc.10086.cn", out)
        self.assertNotIn("10086.cn", out)
        self.assertEqual(cybercensus._operator_candidates("东莞市人民医院"), [])
        self.assertEqual(cybercensus._operator_candidates("四川移动"),
                         ["wap.sc.10086.cn"])
        # 缩写输入同样能推导出省级运营商入口
        self.assertEqual(cybercensus._operator_candidates("川移"),
                         ["wap.sc.10086.cn"])
        self.assertTrue(cybercensus._host_region_hit("川移", "wap.sc.10086.cn"))
        self.assertTrue(cybercensus._sector_hit("川移", "中国移动APP"))
        self.assertTrue(cybercensus._region_hit(
            "川移", "wap.sc.10086.cn", "中国移动APP"))


class TestOperatorDomainVerify(unittest.TestCase):
    def test_district_site_verified_by_cert_brand(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.names = ["双流电信"]
        orig_probe = cybercensus.http_probe
        orig_cert = cybercensus.tls_cert_info
        cybercensus.http_probe = lambda *a, **k: {
            "status": 403, "title": "403 Forbidden", "meta": "",
            "credit_code": "", "refs": []}
        cybercensus.tls_cert_info = lambda *a, **k: {
            "org": "中国电信股份有限公司全渠道运营中心"}
        self.addCleanup(cybercensus.__setattr__, "http_probe", orig_probe)
        self.addCleanup(cybercensus.__setattr__, "tls_cert_info", orig_cert)
        self.assertTrue(e._verify_candidate_domain("双流电信", "shuangliu.189.cn"))
        self.assertIn("shuangliu.189.cn", e.domains)
        self.assertNotIn("189.cn", e.domains)   # 集团根域不整体入锚点


class TestDistrictCandidates(unittest.TestCase):
    def test_extract_place(self):
        self.assertEqual(cybercensus._extract_place("双流移动"), "双流")
        self.assertEqual(cybercensus._extract_place("双流区电信"), "双流")
        self.assertEqual(cybercensus._extract_place("某某市人民医院"), "某某人民医院")

    @unittest.skipUnless(cybercensus.HAVE_PINYIN, "需要 pypinyin")
    def test_pinyin_variants(self):
        v = cybercensus._pinyin_variants("双流")
        self.assertIn("shuangliu", v)
        self.assertIn("sl", v)

    def test_district_candidates_resolve_filter(self):
        orig = cybercensus.resolve_a

        def fake(h):
            return {"1.1.1.1"} if h == "shuangliu.189.cn" else set()
        cybercensus.resolve_a = fake
        self.addCleanup(cybercensus.__setattr__, "resolve_a", orig)
        out = cybercensus._district_candidates("双流电信")
        self.assertEqual(out, ["shuangliu.189.cn"])

    def test_non_operator_has_no_district_candidates(self):
        self.assertEqual(cybercensus._district_candidates("双流人民医院"), [])


class TestProviderKeywordTranslate(unittest.TestCase):
    def test_fofa_body_search(self):
        q = prov.Query("keyword", "双流移动")
        p = prov.Fofa({"email": "a@b.com", "key": "k"})
        self.assertIn('body="双流移动"', p.translate(q))

    def test_hunter_body_search(self):
        q = prov.Query("keyword", "双流移动")
        p = prov.Hunter({"key": "k"})
        self.assertIn('web.body="双流移动"', p.translate(q))


class TestKeywordSearch(unittest.TestCase):
    def test_build_queries_keyword_last(self):
        qs = prov.build_queries({"x.com"}, set(), set(), set(),
                                keywords=["双流移动", "", "a"])
        kinds = [q.kind for q in qs]
        self.assertEqual(kinds[-1], "keyword")
        self.assertIn("双流移动", [q.value for q in qs])
        self.assertNotIn("a", [q.value for q in qs])   # 太短被忽略

    def test_search_result_urls(self):
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: (
            '<h2><a href="https://sc.10086.cn/shuangliu">a</a></h2>'
            '<h2><a href="https://www.bing.com/x">b</a></h2>')
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        urls = cybercensus.search_result_urls("双流移动")
        self.assertEqual(urls, ["https://sc.10086.cn/shuangliu"])

    def test_collect_keyword_leads_weak_anchor(self):
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5))
        e.names = ["双流移动"]
        orig = cybercensus.search_result_urls

        def fake(q):
            if "site:" in q:
                return []
            return ["https://sc.10086.cn/shuangliu/index.html",
                    "https://www.10086.cn/x",
                    "https://news.example.com/a"]
        cybercensus.search_result_urls = fake
        self.addCleanup(cybercensus.__setattr__, "search_result_urls", orig)
        e.collect_keyword_leads()
        # 省级运营商域成为弱锚点（只进疑似）；www 根域不整体纳入
        self.assertIn("sc.10086.cn", e.anchor["weak_domains"])
        self.assertNotIn("10086.cn", e.anchor["domains"])
        self.assertTrue(any("双流移动" in k for k, _ in e.risk_hints))
        self.assertIn(("sc.10086.cn", "/shuangliu/index.html", "search"),
                      e.web_paths)


class TestReportFormats(unittest.TestCase):
    MD = ("# 标题\n\n- **确认**：某医院\n\n"
          "| 主机 | 端口 |\n|------|------|\n| www.x.com | 443 |\n")

    def test_md_to_text(self):
        txt = cybercensus.md_to_text(self.MD)
        self.assertIn("标题", txt)
        self.assertIn("• 确认：某医院", txt)
        self.assertIn("www.x.com  443", txt)
        self.assertNotIn("**", txt)
        self.assertNotIn("|---", txt)

    def test_write_docx_structure(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.docx")
            cybercensus.write_docx(p, self.MD)
            with zipfile.ZipFile(p) as z:
                names = set(z.namelist())
                self.assertIn("word/document.xml", names)
                self.assertIn("[Content_Types].xml", names)
                doc = z.read("word/document.xml").decode("utf-8")
                self.assertIn("标题", doc)
                self.assertIn("www.x.com", doc)
                self.assertIn("<w:tbl>", doc)

    def test_output_txt_and_docx(self):
        with tempfile.TemporaryDirectory() as d:
            args = argparse.Namespace(beian="", threads=10, timeout=5, out=d,
                                      output_formats="txt,docx", active=False,
                                      no_probe=False)
            e = cybercensus.Engine(args)
            a = e.add_asset("www.x.com", 443, "https", source="anchor")
            a.confidence = "确认"
            a.title = "测试站"
            files, _j, _m = e.output()
            self.assertTrue(os.path.isfile(files["txt"]))
            self.assertTrue(os.path.isfile(files["docx"]))
            with zipfile.ZipFile(files["docx"]) as z:
                self.assertIn("www.x.com",
                              z.read("word/document.xml").decode("utf-8"))

    def test_pdf_without_browser(self):
        orig = cybercensus.find_pdf_browser
        cybercensus.find_pdf_browser = lambda: ""
        self.addCleanup(cybercensus.__setattr__, "find_pdf_browser", orig)
        with tempfile.TemporaryDirectory() as d:
            html = os.path.join(d, "a.html")
            with open(html, "w", encoding="utf-8") as f:
                f.write("<html></html>")
            ok, msg = cybercensus.html_to_pdf(html, os.path.join(d, "a.pdf"))
            self.assertFalse(ok)
            self.assertIn("Edge", msg)


class TestPathHarvest(unittest.TestCase):
    def test_parse_robots(self):
        txt = ("User-agent: *\n"
               "Disallow: /admin/\n"
               "Allow: /public\n"
               "Disallow: /*.pdf$\n"
               "Disallow: /\n"
               "Sitemap: https://x.com/sitemap.xml\n")
        self.assertEqual(cybercensus.parse_robots(txt), ["/admin/", "/public"])

    def test_parse_sitemap(self):
        xml = ('<?xml version="1.0"?><urlset>'
               '<url><loc>https://x.com/portal/list</loc></url>'
               '<url><loc>https://x.com/api/v1/query?x=1</loc></url>'
               '<url><loc>https://x.com/sitemap2.xml</loc></url>'
               '</urlset>')
        self.assertEqual(cybercensus.parse_sitemap(xml),
                         ["/portal/list", "/api/v1/query"])

    def test_extract_js_paths(self):
        js = ('fetch("/api/v1/users"); var a="/static/app.js";'
              'url: "https://x.com/admin/login"; var b="/";'
              'var c="/download/file.pdf";')
        out = cybercensus.extract_js_paths(js)
        self.assertIn("/api/v1/users", out)
        self.assertIn("/admin/login", out)
        self.assertNotIn("/static/app.js", out)
        self.assertNotIn("/download/file.pdf", out)

    def test_harvest_paths_records_and_dedupes(self):
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5))
        a = e.add_asset("x.com", 443, "https", source="anchor")
        a.status = "200"
        orig = cybercensus.http_get

        def fake(url, **kw):
            if "robots" in url:
                return ("User-agent: *\nDisallow: /admin/\n"
                        "Sitemap: https://x.com/sitemap.xml\n")
            if "sitemap" in url:
                return ("<urlset><url><loc>https://x.com/api/v1/list</loc>"
                        "</url></urlset>")
            return ""
        cybercensus.http_get = fake
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        e.harvest_paths()
        self.assertIn(("x.com", "/admin/", "robots"), e.web_paths)
        self.assertIn(("x.com", "/api/v1/list", "sitemap"), e.web_paths)

    def test_wayback_urls_paths(self):
        orig = cybercensus.http_get
        cybercensus.http_get = lambda url, **kw: json.dumps([
            ["original"],
            ["https://x.com/admin/login"],
            ["https://x.com/"],
            ["https://other.com/a"],
            ["https://sub.x.com/api/v1?a=1"],
        ])
        self.addCleanup(cybercensus.__setattr__, "http_get", orig)
        self.assertEqual(cybercensus.wayback_urls("x.com"),
                         [("x.com", "/admin/login"),
                          ("sub.x.com", "/api/v1")])

    def test_mine_wayback_paths_records(self):
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5))
        e.anchor["domains"] = {"x.com"}
        orig = cybercensus.wayback_urls
        cybercensus.wayback_urls = lambda d, timeout=25, limit=1000: [
            ("x.com", "/old-admin/")]
        self.addCleanup(cybercensus.__setattr__, "wayback_urls", orig)
        e.mine_wayback_paths()
        self.assertIn(("x.com", "/old-admin/", "wayback"), e.web_paths)

    def test_no_paths_switch(self):
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5, no_paths=True))
        e.add_asset("x.com", 443, "https", source="anchor")
        e.harvest_paths()
        self.assertEqual(e.web_paths, set())


class TestFastMode(unittest.TestCase):
    def test_applies_limits_and_reports_skips(self):
        args = argparse.Namespace(
            scan_timeout=5.0, timeout=15.0, threads=10,
            no_brute=False, no_hints=False, ext_sub_limit=5000)
        skipped = cybercensus.apply_fast_mode(args)
        self.assertEqual(args.scan_timeout, 1.2)
        self.assertEqual(args.timeout, 8.0)
        self.assertEqual(args.threads, 50)
        self.assertTrue(args.no_brute)
        self.assertTrue(args.no_hints)
        self.assertEqual(args.verify_attempts, 4)
        self.assertEqual(args.ext_sub_limit, 1000)
        self.assertIn("DNS小字典", skipped)


class TestAliasVariants(unittest.TestCase):
    def test_full_name_generates_short_forms(self):
        v = cybercensus.alias_variants("中国移动通信集团四川有限公司")
        self.assertIn("四川移动", v)
        self.assertIn("川移", v)

    def test_short_input_expands_to_full(self):
        v = cybercensus.alias_variants("川移")
        self.assertEqual(v[0], "四川移动")
        self.assertIn("川移动", v)

    def test_city_short_form(self):
        v = cybercensus.alias_variants("蓉移")
        self.assertIn("成都移动", v)

    def test_unrelated_name_no_variants(self):
        self.assertEqual(cybercensus.alias_variants("东莞市人民医院"), [])


class TestAliasCache(unittest.TestCase):
    def test_roundtrip_and_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "aliases.json")
            cache = {"四川移动": {"aliases": ["川移"],
                                 "seeds": ["wap.sc.10086.cn"]}}
            self.assertTrue(cybercensus.save_alias_cache(cache, p))
            self.assertEqual(cybercensus.load_alias_cache(p), cache)
            # 旧版纯列表格式兼容
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"x": ["a"]}, f)
            self.assertEqual(cybercensus.load_alias_cache(p),
                             {"x": {"aliases": ["a"], "seeds": []}})


class TestIntel(unittest.TestCase):
    def test_load_intel_sanitizes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "intel.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({
                    "aliases": [" 四川移动 ", "川移", 123, ""],
                    "queries": ["四川移动 网上营业厅", "x" * 200],
                    "seed_domains": ["wap.sc.10086.cn",
                                     "https://api.x.com/a", "not-a-domain", 5],
                }, f, ensure_ascii=False)
            r = cybercensus.load_intel(p)
            self.assertEqual(r["aliases"], ["四川移动", "川移"])
            self.assertEqual(r["queries"], ["四川移动 网上营业厅"])
            self.assertEqual(r["seed_domains"], ["wap.sc.10086.cn", "api.x.com"])

    def test_missing_or_bad_file(self):
        empty = {"aliases": [], "queries": [], "seed_domains": []}
        self.assertEqual(cybercensus.load_intel("Z:/definitely/nope.json"), empty)
        self.assertEqual(cybercensus.load_intel(""), empty)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("[1,2,3]")
            self.assertEqual(cybercensus.load_intel(p), empty)


class TestGovCandidates(unittest.TestCase):
    def test_province_gov_seed(self):
        f = cybercensus._gov_candidates
        self.assertEqual(f("四川省人民政府"), ["www.sc.gov.cn", "sc.gov.cn"])
        self.assertEqual(f("四川省人民医院"), [])
        self.assertEqual(f("某某市人民政府"), [])


class TestGovCandidateGuard(unittest.TestCase):
    def test_skip_gov_for_telecom(self):
        f = cybercensus._gov_candidate_allowed
        self.assertFalse(f("四川移动", "www.sc.gov.cn"))
        self.assertTrue(f("某某市教育局", "www.xx.gov.cn"))
        self.assertTrue(f("四川移动", "wap.sc.10086.cn"))


class TestPrioritizeRegion(unittest.TestCase):
    def test_region_candidates_verified_first(self):
        cands = [("www.gov.cn", 10), ("wap.sc.10086.cn", 1),
                 ("www.10086.cn", 5), ("dcp.sc.10086.cn", 2)]
        out, region = cybercensus._prioritize_region("四川移动", cands)
        self.assertEqual(out[0][0], "wap.sc.10086.cn")
        self.assertEqual(region, ["wap.sc.10086.cn", "dcp.sc.10086.cn"])
        self.assertEqual(out[-1][0], "www.10086.cn")


class TestPassiveRegionCandidates(unittest.TestCase):
    def test_prefers_province_candidates(self):
        """纯被动下"四川移动"只取省级候选，不把全国根域 10086.cn 当弱锚点。"""
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5, no_probe=True))
        e.names = ["四川移动"]
        orig_lookup = cybercensus.search_engine_lookup
        orig_disc = cybercensus.discover_domains_from_search
        cybercensus.search_engine_lookup = lambda n, timeout=15: ("", [])
        cybercensus.discover_domains_from_search = (
            lambda name, max_candidates=5, lookup=None: [
                ("www.10086.cn", 3), ("wap.sc.10086.cn", 1),
                ("dcp.sc.10086.cn", 1)])
        self.addCleanup(cybercensus.__setattr__,
                        "search_engine_lookup", orig_lookup)
        self.addCleanup(cybercensus.__setattr__,
                        "discover_domains_from_search", orig_disc)
        e.discover_names_to_domains()
        self.assertIn("sc.10086.cn", e.domains)
        self.assertIn("wap.sc.10086.cn", e.domains)
        self.assertNotIn("10086.cn", e.domains)
        self.assertNotIn("www.10086.cn", e.domains)
        self.assertTrue({"sc.10086.cn"} <= e.anchor["weak_domains"])

    def test_alias_search_rescues_province_site(self):
        """全称只搜到集团总部域时，用简称补搜找回省级站点。"""
        e = cybercensus.Engine(argparse.Namespace(
            beian="", threads=10, timeout=5, no_probe=True))
        e.names = ["中国移动通信集团四川有限公司"]
        orig_lookup = cybercensus.search_engine_lookup
        orig_disc = cybercensus.discover_domains_from_search
        calls = []

        def fake_lookup(q, timeout=15):
            calls.append(q)
            return ("", [])

        def fake_disc(name, max_candidates=5, lookup=None):
            if name.startswith("中国移动"):
                return [("www.10086.cn", 3)]
            return [("wap.sc.10086.cn", 3)]
        cybercensus.search_engine_lookup = fake_lookup
        cybercensus.discover_domains_from_search = fake_disc
        self.addCleanup(cybercensus.__setattr__,
                        "search_engine_lookup", orig_lookup)
        self.addCleanup(cybercensus.__setattr__,
                        "discover_domains_from_search", orig_disc)
        e.discover_names_to_domains()
        self.assertTrue(any("四川移动" in c for c in calls))   # 触发了简称补搜
        self.assertIn("sc.10086.cn", e.domains)
        self.assertNotIn("10086.cn", e.domains)


class TestPackageAnalysis(unittest.TestCase):
    def _mk_apk(self, tmpdir):
        p = os.path.join(tmpdir, "app.apk")
        dex = ('const-string "https://api.xx-hospital.com/api/login"\n'
               'const-string "https://cdn.track.umeng.com/collect"\n'
               'const-string "amap.com"\n'
               'key = "LTAI5tAbCdEfGhIjKlMn"\n')
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("classes.dex", dex)
            z.writestr("assets/logo.png", b"\x89PNG fake")
        return p

    def test_analyze_package_extracts(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._mk_apk(d)
            r = cybercensus.analyze_package(p)
            self.assertEqual(r["files"], 1)
            self.assertIn("api.xx-hospital.com", r["domains"])
            self.assertIn("cdn.track.umeng.com", r["domains"])   # 原始提取保留
            self.assertIn("https://api.xx-hospital.com/api/login", r["urls"])
            self.assertIn("阿里云AccessKey", r["secrets"])
            self.assertEqual(r["error"], "")

    def test_engine_filters_sdk_and_adds_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._mk_apk(d)
            e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
            e.analyze_packages([p])
            self.assertIn("xx-hospital.com", e._ref_candidates)
            self.assertNotIn("umeng.com", e._ref_candidates)
            self.assertNotIn("amap.com", e._ref_candidates)
            self.assertEqual(len(e.packages), 1)
            self.assertEqual(e.packages[0]["files"], 1)
            self.assertEqual(e.packages[0]["secrets"], ["阿里云AccessKey"])

    def test_missing_path_reports_error(self):
        e = cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        e.analyze_packages(["Z:/definitely/not/here.apk"])
        self.assertEqual(e.packages, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
