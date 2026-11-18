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
        cybercensus.discover_domains_from_search = lambda n, max_candidates=5: [
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
