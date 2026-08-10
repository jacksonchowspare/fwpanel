#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fwpanel 单元测试 + HTTP API 冒烟测试（无需 root，使用临时目录 + dry-run）"""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request

# ---- 必须在 import panel 前设置测试环境 ----
TMP = tempfile.mkdtemp(prefix="fwpanel-test-")
os.environ["FW_TEST_DIR"] = TMP
os.environ["FW_DRY_RUN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import panel  # noqa: E402

# ---- 准备测试配置 ----
TEST_USER = "tester"
TEST_PASS = "TestPass123"
panel.Config.__init__ = lambda self: setattr(self, "data", {})  # 避免读真实配置


def make_cfg(user=TEST_USER, pwd=TEST_PASS, mode="permissive"):
    """每个测试独立配置，避免状态污染"""
    cfg = panel.Config()
    cfg.data = {
        "username": user,
        "password_hash": panel.hash_password(pwd),
        "port": 17999,
        "bind": "127.0.0.1",
        "mode": mode,
        "ssh_port": 22,
    }
    return cfg


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg()
        self.auth = panel.Auth(self.cfg)

    def test_login_ok(self):
        token, msg = self.auth.login(TEST_USER, TEST_PASS)
        self.assertTrue(token, msg)
        self.assertTrue(self.auth.check(token))

    def test_login_wrong(self):
        token, msg = self.auth.login(TEST_USER, "wrongpass")
        self.assertIsNone(token)

    def test_lockout(self):
        auth = panel.Auth(make_cfg())
        for _ in range(panel.LOCK_MAX_FAIL):
            auth.login(TEST_USER, "bad")
        self.assertTrue(auth.check_locked())
        token, _ = auth.login(TEST_USER, TEST_PASS)
        self.assertIsNone(token, "锁定期内不应允许登录")

    def test_hash(self):
        h = panel.hash_password("abc12345")
        self.assertTrue(panel.verify_password("abc12345", h))
        self.assertFalse(panel.verify_password("abc12346", h))


class TestRules(unittest.TestCase):
    def setUp(self):
        panel.RuleStore._load = lambda self: []   # 隔离：不读磁盘
        self.store = panel.RuleStore()
        self.store.rules = []
        self.cfg = make_cfg()

    def test_render_permissive(self):
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 80, "comment": "web"},
            {"id": "2", "type": "port_deny", "proto": "tcp", "port": 23, "comment": ""},
            {"id": "3", "type": "ip_allow", "ip": "1.2.3.4", "comment": ""},
            {"id": "4", "type": "ip_deny", "ip": "5.6.7.8", "comment": "bad"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("policy accept", text)
        self.assertIn("tcp dport 80 accept", text)
        self.assertIn("# web", text)
        self.assertIn("tcp dport 23 drop", text)
        self.assertIn("ip saddr 1.2.3.4 accept", text)
        self.assertIn("ip saddr 5.6.7.8 drop", text)
        self.assertIn("# bad", text)
        # SSH 保护永远存在
        self.assertIn("tcp dport 22 accept   # SSH 保护", text)
        # 顺序：SSH 保护必须在用户规则之前
        self.assertLess(text.index("SSH 保护"), text.index("tcp dport 80"))

    def test_render_strict(self):
        strict_cfg = make_cfg(mode="strict")
        text = self.store.render(strict_cfg)
        self.assertIn("policy drop", text)

    def test_render_ipv6(self):
        self.store.rules = [{"id": "1", "type": "ip_allow", "ip": "2001:db8::1", "comment": ""}]
        text = self.store.render(self.cfg)
        self.assertIn("ip6 saddr 2001:db8::1 accept", text)

    def test_render_both(self):
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "both", "port": 8080, "comment": "双协议"},
            {"id": "2", "type": "port_deny", "proto": "both", "port": 4444, "comment": ""},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 8080 accept", text)
        self.assertIn("udp dport 8080 accept", text)
        self.assertIn("# 双协议", text)
        self.assertIn("tcp dport 4444 drop", text)
        self.assertIn("udp dport 4444 drop", text)

    def test_ip_net_rule_render(self):
        """IP 段黑名单/白名单渲染（IPv4+IPv6 CIDR）"""
        self.store.rules = [
            {"id": "1", "type": "ip_deny", "ip": "1.2.3.0/24", "comment": "封禁段"},
            {"id": "2", "type": "ip_deny", "ip": "2001:db8::/32", "comment": "封禁v6段"},
            {"id": "3", "type": "ip_allow", "ip": "10.0.0.0/8", "comment": "白名单段"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("ip saddr 1.2.3.0/24 drop", text)
        self.assertIn("ip6 saddr 2001:db8::/32 drop", text)
        self.assertIn("ip saddr 10.0.0.0/8 accept", text)
        self.assertIn("封禁段", text)

    def test_deny_before_ssh_accept(self):
        """黑名单规则必须排在 SSH 保护 accept 之前（否则封禁对 SSH 失效）"""
        self.store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 8080, "comment": ""},
            {"id": "2", "type": "ip_deny", "ip": "1.2.3.4", "comment": "封禁"},
            {"id": "3", "type": "port_deny", "proto": "tcp", "port": 9999, "comment": ""},
        ]
        text = self.store.render(self.cfg)
        self.assertLess(text.index("ip saddr 1.2.3.4 drop"), text.index("tcp dport 22 accept"))
        self.assertLess(text.index("tcp dport 9999 drop"), text.index("tcp dport 22 accept"))
        self.assertGreater(text.index("tcp dport 8080 accept"), text.index("tcp dport 22 accept"))

    def test_protected_rule_not_deletable(self):
        self.store.rules = [{"id": "x1", "type": "port_allow", "proto": "tcp",
                             "port": 22, "comment": "SSH 保护(不可删除)", "protected": True}]
        ok, msg = self.store.remove("x1")
        self.assertFalse(ok)
        self.assertIn("不可删除", msg)

    def test_add_remove(self):
        r = self.store.add({"type": "port_allow", "proto": "tcp", "port": 8080, "comment": "t"})
        self.assertIn("id", r)
        self.assertEqual(len(self.store.rules), 1)
        ok, _ = self.store.remove(r["id"])
        self.assertTrue(ok)
        self.assertEqual(len(self.store.rules), 0)


class TestAPI(unittest.TestCase):
    """HTTP API 冒烟测试：真实起服务 + urllib 请求（dry-run 不执行 nft）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17999), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17999"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def test_open_port(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 一键开放端口
        code, d = self._req("POST", "/api/open-port", {"port": 9000, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertIn("已开放", d["msg"])
        # 幂等：重复开放返回成功且不报错
        code, d = self._req("POST", "/api/open-port", {"port": 9000, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200)
        self.assertIn("已在放行列表", d["msg"])
        # 规则确实存在
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("port") == 9000 for r in d["rules"]))
        # 非法端口
        code, d = self._req("POST", "/api/open-port", {"port": 99999}, token=token)
        self.assertEqual(code, 400)

    def test_open_port_both(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # TCP+UDP 同时开放
        code, d = self._req("POST", "/api/open-port", {"port": 9100, "proto": "both"}, token=token)
        self.assertEqual(code, 200, d)
        # 幂等
        code, d = self._req("POST", "/api/open-port", {"port": 9100, "proto": "both"}, token=token)
        self.assertEqual(code, 200)
        self.assertIn("已在放行列表", d["msg"])
        # 渲染应生成 tcp+udp 两行
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 9100 accept", text)
        self.assertIn("udp dport 9100 accept", text)
        # 非法协议
        code, d = self._req("POST", "/api/open-port", {"port": 9200, "proto": "icmp"}, token=token)
        self.assertEqual(code, 400)

    def test_ssh_api(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 查询状态
        code, d = self._req("GET", "/api/ssh", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["protected_port"], 22)
        # 仅更新保护端口
        code, d = self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh", token=token)
        self.assertEqual(d["protected_port"], 2222)
        # 规则渲染应保护新端口
        text = self.store.render(self.cfg)
        self.assertIn("tcp dport 2222 accept   # SSH 保护", text)
        # 恢复
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_ssh_apply(self):
        """同步修改系统 SSH 端口：验证防锁死流程（旧端口临时放行 + 保护更新）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real = panel.apply_sshd_port
        panel.apply_sshd_port = lambda port: (True, f"系统 SSH 端口已切换为 {port}")
        # 屏蔽后台监控（mock 函数本身，不能 mock threading.Thread——那是标准库全局对象）
        real_watch = panel.watch_ssh_switch
        panel.watch_ssh_switch = lambda old, new, timeout=3600: None
        try:
            code, d = self._req("POST", "/api/ssh/apply", {"ssh_port": 3333}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("已启动自动检测", d["msg"])
            # 保护端口已更新
            code, d = self._req("GET", "/api/ssh", token=token)
            self.assertEqual(d["protected_port"], 3333)
            # 旧端口临时放行规则存在
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertTrue(any(r.get("comment") == panel.SSH_OLD_PORT_COMMENT
                                and r.get("port") == 22 for r in d["rules"]),
                            "应存在旧端口临时放行规则")
            # 渲染：新保护端口 + 旧端口临时放行都在
            text = self.store.render(self.cfg)
            self.assertIn("tcp dport 3333 accept   # SSH 保护", text)
            self.assertIn(f"tcp dport 22 accept  # {panel.SSH_OLD_PORT_COMMENT}", text)
        finally:
            panel.apply_sshd_port = real
            panel.watch_ssh_switch = real_watch
            # 清理测试痕迹
            self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.SSH_OLD_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_mode_strict_auto_port(self):
        """切严格模式自动放行面板端口（防锁死）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/mode", {"mode": "strict"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertIn("已自动放行面板端口", d["msg"])
        # 面板端口规则已添加（cfg port=17999）
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("comment") == panel.PANEL_PORT_COMMENT
                            and r.get("port") == 17999 for r in d["rules"]),
                        "严格模式下应自动放行面板端口")
        text = self.store.render(self.cfg)
        self.assertIn("policy drop", text)
        self.assertIn("tcp dport 17999 accept", text)
        # 恢复宽松
        code, d = self._req("POST", "/api/mode", {"mode": "permissive"}, token=token)
        self.assertEqual(code, 200)
        # 清理自动添加的面板端口规则（避免影响后续测试）
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("comment") == panel.PANEL_PORT_COMMENT:
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_panel_port(self):
        """修改面板端口：旧端口放行规则全部删除 + 新端口自动放行"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 预置：面板端口规则 + 一条手动开放的旧端口规则（模拟残留）
        self.store.add({"type": "port_allow", "proto": "tcp", "port": 17999,
                        "comment": panel.PANEL_PORT_COMMENT})
        self.store.add({"type": "port_allow", "proto": "tcp", "port": 17999,
                        "comment": "手动开放"})
        # mock 重启动作（只 mock restart_service，不碰 subprocess.run，避免影响 status 等接口）
        real_timer, real_restart = panel.threading.Timer, panel.restart_service
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        panel.restart_service = lambda: None
        try:
            # 改端口
            code, d = self._req("POST", "/api/panel/port", {"port": 18001}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("18001", d["msg"])
            # 配置已更新
            code, d = self._req("GET", "/api/status", token=token)
            self.assertEqual(d["panel_port"], 18001)
            # 旧端口 17999 的所有放行规则已删除（含手动开放的）
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertFalse(any(r.get("type") == "port_allow" and r.get("port") == 17999
                                 for r in d["rules"]),
                             "旧端口放行规则应全部删除")
            # 新端口有面板端口放行规则（1 条）
            new_rules = [r for r in d["rules"] if r.get("comment") == panel.PANEL_PORT_COMMENT]
            self.assertEqual(len(new_rules), 1)
            self.assertEqual(new_rules[0]["port"], 18001)
            # 占用端口拒绝
            code, d = self._req("POST", "/api/panel/port", {"port": 17999}, token=token)
            self.assertEqual(code, 400)
            # 非法端口
            code, d = self._req("POST", "/api/panel/port", {"port": "abc"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.threading.Timer = real_timer
            panel.restart_service = real_restart
            # 恢复配置和规则
            self.server.config.set("port", 17999)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.PANEL_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_panel_port_auto_allow(self):
        """无面板端口规则时改端口，应自动添加新端口放行（防严格模式锁死）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real_timer, real_restart = panel.threading.Timer, panel.restart_service
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        panel.restart_service = lambda: None
        try:
            # 不预置任何面板端口规则，直接改端口
            code, d = self._req("POST", "/api/panel/port", {"port": 18002}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/rules", token=token)
            self.assertTrue(any(r.get("comment") == panel.PANEL_PORT_COMMENT
                                and r.get("port") == 18002 for r in d["rules"]),
                            "改端口后应自动添加新端口放行规则")
            # 渲染应包含新端口放行
            text = self.store.render(self.cfg)
            self.assertIn("tcp dport 18002 accept", text)
        finally:
            panel.threading.Timer = real_timer
            panel.restart_service = real_restart
            self.server.config.set("port", 17999)
            code, d = self._req("GET", "/api/rules", token=token)
            for r in d["rules"]:
                if r.get("comment") == panel.PANEL_PORT_COMMENT:
                    self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_username(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 修改用户名
        code, d = self._req("POST", "/api/username", {"username": "newadmin"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(d["username"], "newadmin")
        # 非法用户名
        code, d = self._req("POST", "/api/username", {"username": "a!"}, token=token)
        self.assertEqual(code, 400)
        # 恢复
        code, d = self._req("POST", "/api/username", {"username": TEST_USER}, token=token)
        self.assertEqual(code, 200)

    def test_ssh_service_dynamic_port(self):
        """SSH 服务开关端口跟随保护端口（不固定 22）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 设置保护端口 2222
        code, d = self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertEqual(code, 200)
        # 打开 SSH 服务开关
        code, d = self._req("POST", "/api/service", {"name": "ssh", "enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("port") == 2222 and r.get("comment") == "服务:ssh"
                            for r in d["rules"]),
                        "SSH 服务开关应放行当前保护端口 2222")
        self.assertFalse(any(r.get("port") == 22 and r.get("comment") == "服务:ssh"
                             for r in d["rules"]),
                         "不应再放行固定 22")
        # 恢复
        self._req("POST", "/api/service", {"name": "ssh", "enabled": False}, token=token)
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_ssh_set_disables_auto(self):
        """手动设置保护端口后关闭自动同步"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        self._req("POST", "/api/ssh", {"ssh_port": 2222}, token=token)
        self.assertFalse(self.cfg.get("ssh_port_auto"), "手动设置后应关闭自动同步")
        self._req("POST", "/api/ssh", {"ssh_port": 22}, token=token)

    def test_cleanup_old_ssh_rules(self):
        """清理旧 SSH 端口规则：删除全部放行规则（含手动开放），保留面板端口规则"""
        store = panel.RuleStore()
        store.rules = [
            {"id": "1", "type": "port_allow", "proto": "tcp", "port": 22, "comment": panel.SSH_OLD_PORT_COMMENT},
            {"id": "2", "type": "port_allow", "proto": "tcp", "port": 22, "comment": "服务:ssh"},
            {"id": "3", "type": "port_allow", "proto": "tcp", "port": 22, "comment": "手动开放"},
            {"id": "4", "type": "port_allow", "proto": "tcp", "port": 22, "comment": panel.PANEL_PORT_COMMENT},
            {"id": "5", "type": "port_allow", "proto": "tcp", "port": 80, "comment": "其他"},
        ]
        store.save()
        changed = panel.cleanup_old_ssh_rules(22)
        self.assertTrue(changed)
        rules = panel.RuleStore().rules
        pairs = [(r["port"], r["comment"]) for r in rules]
        self.assertNotIn((22, panel.SSH_OLD_PORT_COMMENT), pairs)
        self.assertNotIn((22, "服务:ssh"), pairs)
        self.assertNotIn((22, "手动开放"), pairs)
        self.assertIn((22, panel.PANEL_PORT_COMMENT), pairs, "面板端口规则应保留")
        self.assertIn((80, "其他"), pairs)
        # 无匹配规则时返回 False
        self.assertFalse(panel.cleanup_old_ssh_rules(9999))
        # 清理测试痕迹
        panel.RuleStore().rules = []
        panel.RuleStore().save()

    def test_watch_ssh_switch_delayed_cleanup(self):
        """连接确认后延迟 600 秒再清理旧端口规则"""
        calls = {"sleep": [], "cleanup": 0}
        real_sleep = panel.time.sleep
        real_has = panel.has_established_on_port
        real_cleanup = panel.cleanup_old_ssh_rules
        panel.time.sleep = lambda s: calls["sleep"].append(s)
        panel.has_established_on_port = lambda p: True   # 立即检测到连接
        panel.cleanup_old_ssh_rules = lambda p: (calls.__setitem__("cleanup", calls["cleanup"] + 1) or True)
        try:
            panel.watch_ssh_switch(22, 3333, confirm_delay=600, wait_timeout=600)
            self.assertEqual(calls["cleanup"], 1, "确认连接后应执行清理")
            self.assertEqual(calls["sleep"][-1], 600, "清理前应延迟 600 秒")
        finally:
            panel.time.sleep = real_sleep
            panel.has_established_on_port = real_has
            panel.cleanup_old_ssh_rules = real_cleanup

    def test_has_established_on_port(self):
        """连接检测：ss 输出非空 = 有连接"""
        import subprocess as sp
        real = panel.subprocess.run
        def fake(cmd, *a, **k):
            out = "ESTAB 0 0 1.2.3.4:3333 5.6.7.8:51234\n" if "3333" in " ".join(cmd) else ""
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        panel.subprocess.run = fake
        try:
            self.assertTrue(panel.has_established_on_port(3333))
            self.assertFalse(panel.has_established_on_port(4444))
        finally:
            panel.subprocess.run = real

    def test_ip_net_validation(self):
        """IP/IP 段校验：单 IP 与 CIDR（IPv4/IPv6）合法，非法拒绝"""
        for ok in ("1.2.3.4", "1.2.3.0/24", "10.0.0.0/8", "2001:db8::1",
                   "2001:db8::/32", "0.0.0.0/0", "::/0"):
            self.assertTrue(panel.is_valid_ip_or_net(ok), f"{ok} 应合法")
        for bad in ("", "1.2.3.999", "1.2.3.0/33", "999.1.1.1", "abc",
                    "1.2.3.4/24/32", "2001:db8::/129"):
            self.assertFalse(panel.is_valid_ip_or_net(bad), f"{bad} 应非法")

    def test_ip_net_api(self):
        """API 添加 IP 段规则 + 非法格式拒绝"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "203.0.113.0/24", "comment": "攻击段"},
                            token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("ip") == "203.0.113.0/24" for r in d["rules"]))
        # 非法格式
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "1.2.3.0/33"}, token=token)
        self.assertEqual(code, 400)
        # 清理
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("ip") == "203.0.113.0/24":
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_ip_range_validation(self):
        """IP 范围格式校验：start-end 同版本且正序"""
        for ok in ("1.2.3.1-1.2.3.50", "10.0.0.1-10.0.0.255",
                   "2001:db8::1-2001:db8::ff"):
            self.assertTrue(panel.is_valid_ip_or_net(ok), f"{ok} 应合法")
        for bad in ("1.2.3.50-1.2.3.1",          # 反序
                    "1.2.3.1-2001:db8::1",       # 跨版本
                    "1.2.3.1-1.2.3.999",         # 非法端点
                    "1.2.3.1-1.2.3.2-1.2.3.3",   # 多个 -
                    "1.2.3.1-"):                 # 缺终点
            self.assertFalse(panel.is_valid_ip_or_net(bad), f"{bad} 应非法")

    def test_ip_range_render(self):
        """IP 范围规则渲染（IPv4+IPv6）"""
        self.store.rules = [
            {"id": "1", "type": "ip_deny", "ip": "1.2.3.1-1.2.3.50", "comment": "范围封禁"},
        ]
        text = self.store.render(self.cfg)
        self.assertIn("ip saddr 1.2.3.1-1.2.3.50 drop", text)

    def test_ip_range_api(self):
        """API 添加 IP 范围规则"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "ip_deny", "ip": "198.51.100.1-198.51.100.50",
                             "comment": "范围封禁"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("ip") == "198.51.100.1-198.51.100.50" for r in d["rules"]))
        # 清理
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("ip") == "198.51.100.1-198.51.100.50":
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)

    def test_bruteforce_api(self):
        """防爆破配置 API：查询/保存/校验/手动解封"""
        # 注意：本测试按字母序最先执行，密码还是初始值 TEST_PASS
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/bruteforce", token=token)
        self.assertEqual(code, 200)
        self.assertFalse(d["enabled"])
        # 保存配置
        code, d = self._req("POST", "/api/bruteforce",
                            {"enabled": True, "max_fails": 3, "ban_seconds": 600},
                            token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/bruteforce", token=token)
        self.assertTrue(d["enabled"])
        self.assertEqual(d["max_fails"], 3)
        self.assertEqual(d["ban_seconds"], 600)
        # 非法参数
        code, d = self._req("POST", "/api/bruteforce", {"max_fails": 0}, token=token)
        self.assertEqual(code, 400)
        # 手动解封不存在 IP（幂等）
        code, d = self._req("DELETE", "/api/bruteforce/203.0.113.66", token=token)
        self.assertEqual(code, 200)
        # 恢复默认
        self._req("POST", "/api/bruteforce", {"enabled": False}, token=token)

    def test_detect_distro(self):
        """发行版自动识别：读 /etc/os-release，返回非空"""
        d = panel.detect_distro()
        self.assertIsInstance(d, str)
        self.assertTrue(len(d) > 0, "发行版识别不应为空")

    def test_status_includes_distro(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 200)
        self.assertTrue(d.get("distro"), "status 应包含发行版信息")
        self.assertTrue(d.get("hostname"))

    def test_firewall_api(self):
        """一键开关防火墙 API"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 关闭（dry-run 环境：disable 走 dry-run 返回成功）
        code, d = self._req("POST", "/api/firewall", {"enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        self.assertFalse(self.cfg.get("firewall_enabled"), "关闭后应记录状态")
        # 开启
        code, d = self._req("POST", "/api/firewall", {"enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        self.assertTrue(self.cfg.get("firewall_enabled"))

    def test_password_with_username(self):
        """账户设置：一次请求同时修改用户名和密码"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 同时改用户名和密码
        code, d = self._req("POST", "/api/password",
                            {"old_password": "NewPass123", "new_password": "NewPass456",
                             "username": "newadmin2"}, token=token)
        self.assertEqual(code, 200, d)
        # 新密码可登录
        code, d = self._req("POST", "/api/login",
                            {"username": "newadmin2", "password": "NewPass456"})
        self.assertEqual(code, 200)
        # 只改密码（不带 username）
        code, d = self._req("POST", "/api/password",
                            {"old_password": "NewPass456", "new_password": "NewPass123"},
                            token=token)
        self.assertEqual(code, 200)
        # 原密码错误拒绝
        code, d = self._req("POST", "/api/password",
                            {"old_password": "wrong", "new_password": "NewPass789"},
                            token=token)
        self.assertEqual(code, 400)
        # 恢复
        self._req("POST", "/api/password",
                  {"old_password": "NewPass123", "username": TEST_USER}, token=token)

    def test_proxy_api(self):
        """反向代理 API：添加/查询/删除 + 防火墙 80/443 联动"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        # 查询（空）
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["proxies"], [])
        # 添加
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "app.example.com", "target_host": "127.0.0.1",
                             "target_port": 8080, "websocket": True}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        # 防火墙仅自动放行 443（80 不放行）
        code, d = self._req("GET", "/api/rules", token=token)
        ports = {r.get("port") for r in d["rules"] if r.get("type") == "port_allow"}
        self.assertIn(443, ports)
        # 目标端口 8080 自动禁止公网直连
        deny = [r for r in d["rules"] if r.get("type") == "port_deny" and r.get("port") == 8080]
        self.assertTrue(deny, "目标端口应有禁止规则")
        self.assertEqual(deny[0]["comment"], panel.PROXY_TARGET_DENY_COMMENT)
        self.assertNotIn(80, ports, "80 不应自动放行")
        # 查询列表
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(len(d["proxies"]), 1)
        self.assertEqual(d["proxies"][0]["domain"], "app.example.com")
        # 重复域名拒绝
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "app.example.com", "target_host": "1.2.3.4",
                             "target_port": 80}, token=token)
        self.assertEqual(code, 400)
        # 停用/启用
        code, d = self._req("POST", f"/api/proxy/{pid}", {"action": "enable", "enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        # 删除
        code, d = self._req("DELETE", f"/api/proxy/{pid}", token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertEqual(d["proxies"], [])
        # 清理 443 规则（避免影响其他测试）
        code, d = self._req("GET", "/api/rules", token=token)
        for r in d["rules"]:
            if r.get("comment") == "反代:HTTPS":
                self._req("DELETE", f"/api/rules/{r['id']}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_proxy_install_api(self):
        """一键安装 API：缺组件时安装，装好后自动应用配置"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real_nginx, real_cert, real_install = (panel.nginx_available,
                                               panel.certbot_available, panel.install_pkgs)
        panel.nginx_available = lambda: False
        panel.certbot_available = lambda: False
        panel.install_pkgs = lambda pkgs: (True, "已安装: " + " ".join(pkgs))
        try:
            code, d = self._req("POST", "/api/proxy/install", {}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("nginx", d["msg"])
            self.assertIn("certbot", d["msg"])
        finally:
            panel.nginx_available = real_nginx
            panel.certbot_available = real_cert
            panel.install_pkgs = real_install

    def test_proxy_renew_blockip_api(self):
        """代理续期 + 禁止 IP 访问 API"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "renew.example.com", "target_host": "127.0.0.1",
                             "target_port": 9001}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        real_renew = panel.renew_cert
        panel.renew_cert = lambda dom: (True, "证书已续期")
        try:
            code, d = self._req("POST", f"/api/proxy/{pid}", {"action": "renew"}, token=token)
            self.assertEqual(code, 200, d)
        finally:
            panel.renew_cert = real_renew
        # 禁止 IP 访问
        code, d = self._req("POST", f"/api/proxy/{pid}",
                            {"action": "blockip", "enabled": True}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/proxy", token=token)
        self.assertTrue(d["proxies"][0]["block_ip"])
        # 关闭
        code, d = self._req("POST", f"/api/proxy/{pid}",
                            {"action": "blockip", "enabled": False}, token=token)
        self.assertEqual(code, 200, d)
        self._req("DELETE", f"/api/proxy/{pid}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_proxy_cert_paths(self):
        """有证书的代理返回公钥/私钥路径"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "path.example.com", "target_host": "127.0.0.1",
                             "target_port": 9002}, token=token)
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        real_exists = panel.cert_files_exist
        panel.cert_files_exist = lambda dom: dom == "path.example.com"
        try:
            code, d = self._req("GET", "/api/proxy", token=token)
            p = d["proxies"][0]
            self.assertEqual(p["cert_path"], "/etc/letsencrypt/live/path.example.com/fullchain.pem")
            self.assertEqual(p["key_path"], "/etc/letsencrypt/live/path.example.com/privkey.pem")
        finally:
            panel.cert_files_exist = real_exists
            self._req("DELETE", f"/api/proxy/{pid}", token=token)
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_edit_rule_comment(self):
        """修改规则备注 API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": 9991,
                             "comment": "原始备注"}, token=token)
        self.assertEqual(code, 200, d)
        rid = d["rule"]["id"]
        # 修改备注
        code, d = self._req("POST", f"/api/rules/{rid}",
                            {"comment": "新备注"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = next(x for x in d["rules"] if x["id"] == rid)
        self.assertEqual(r["comment"], "新备注")
        # 不存在的规则
        code, d = self._req("POST", "/api/rules/nonexist",
                            {"comment": "x"}, token=token)
        self.assertEqual(code, 400)
        self._req("DELETE", f"/api/rules/{rid}", token=token)

    def test_bruteforce_manual_ban(self):
        """手动封禁/解封 IP API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 手动封禁
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.77"
                            for r in d["rules"]), "应存在封禁规则")
        # 封禁记录写入 bans（防爆破模块显示剩余时间）
        self.assertIn("198.51.100.77", panel.load_bans(), "手动封禁应写入封禁记录")
        # 重复封禁拒绝
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 400)
        # 非法 IP
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "1.2.3.0/24"}, token=token)
        self.assertEqual(code, 400)
        # 手动解封
        code, d = self._req("POST", "/api/bruteforce/unban",
                            {"ip": "198.51.100.77"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertFalse(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.77"
                             for r in d["rules"]), "解封后不应有封禁规则")

    def test_manual_ban_expires_removes_rule(self):
        """手动封禁到期后：bans 记录与规则同时清理（回归：规则残留）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/bruteforce/ban",
                            {"ip": "198.51.100.88"}, token=token)
        self.assertEqual(code, 200, d)
        # 到期时间改为过去（固定值，配合 now=2000 触发到期）
        bans = panel.load_bans()
        self.assertIn("198.51.100.88", bans)
        bans["198.51.100.88"] = 1000
        panel.save_bans(bans)
        # 手动封禁的规则在磁盘上存在
        before = panel.RuleStore().rules
        self.assertTrue(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.88"
                            for r in before), "封禁后应有规则")
        # 触发一轮扫描（mock 失败检测为空，避免新增其他封禁）
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 99, "ban_seconds": 600, "fail_window": 300})
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {}
        panel.get_established_ips = lambda p: set()
        try:
            logs = panel.bruteforce_cycle(cfg, panel.RuleStore(), now=2000)
            self.assertTrue(any("198.51.100.88" in log for log in logs), logs)
        finally:
            panel.get_failed_ssh_attempts, panel.get_established_ips = real_a, real_e
        # 磁盘规则应已删除（含手动封禁）
        after = panel.RuleStore().rules
        self.assertFalse(any(r.get("type") == "ip_deny" and r.get("ip") == "198.51.100.88"
                             for r in after), "到期后规则应被清理")
        # 清理
        self._req("POST", "/api/bruteforce/unban",
                  {"ip": "198.51.100.88"}, token=token)
        self._req("POST", "/api/bruteforce",
                  {"enabled": False}, token=token)

    def test_close_port_api(self):
        """一键删除端口放行规则 API（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 放行 tcp 5005 和 both 5006
        self._req("POST", "/api/open-port", {"port": 5005, "proto": "tcp"}, token=token)
        self._req("POST", "/api/open-port", {"port": 5006, "proto": "both"}, token=token)
        # tcp 删 5005
        code, d = self._req("POST", "/api/close-port", {"port": 5005, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertFalse(any(r.get("port") == 5005 for r in d["rules"]), "5005 应已删除")
        # both 删 5006（存储为 1 条 both 规则，渲染时拆 tcp/udp 两条 nft 规则）
        code, d = self._req("POST", "/api/close-port", {"port": 5006, "proto": "both"}, token=token)
        self.assertEqual(code, 200, d)
        self.assertEqual(d["removed"], 1)
        # 无规则端口
        code, d = self._req("POST", "/api/close-port", {"port": 59999, "proto": "tcp"}, token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["removed"], 0)
        # 非法
        code, d = self._req("POST", "/api/close-port", {"port": 0}, token=token)
        self.assertEqual(code, 400)

    def test_bbr_api(self):
        """BBR API：查询 + 开启（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("GET", "/api/bbr", token=token)
        self.assertEqual(code, 200)
        self.assertIn("enabled", d)
        self.assertTrue(d.get("kernel"), "应返回内核版本")
        code, d = self._req("POST", "/api/bbr", {}, token=token)
        self.assertEqual(code, 200, d)

    def test_restart_api(self):
        """重启面板 API：dry-run 环境直接返回成功"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/restart", {}, token=token)
        self.assertEqual(code, 200, d)
        self.assertTrue(d.get("ok"))

    def test_panel_port_syncs_proxy(self):
        """修改面板端口：指向旧端口的反代自动同步 + 目标端口 deny 规则迁移"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        cur_port = int(self._req("GET", "/api/status", token=token)[1]["panel_port"])
        code, d = self._req("POST", "/api/proxy",
                            {"domain": "sync.example.com", "target_host": "127.0.0.1",
                             "target_port": cur_port}, token=token)
        self.assertEqual(code, 200, d)
        new_port = cur_port + 1 if cur_port + 1 <= 65535 else cur_port - 1
        real_restart = panel.restart_service
        panel.restart_service = lambda: None   # 避免真的 systemctl restart
        try:
            code, d = self._req("POST", "/api/panel/port",
                                {"port": new_port}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("已同步", d["msg"])
        finally:
            panel.restart_service = real_restart
        # 代理 target_port 已更新为新端口
        code, d = self._req("GET", "/api/proxy", token=token)
        p = [x for x in d["proxies"] if x["domain"] == "sync.example.com"][0]
        self.assertEqual(p["target_port"], new_port)
        # deny 规则迁移：新端口有、旧端口无
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r.get("type") == "port_deny" and r.get("port") == new_port
                            and r.get("comment") == panel.PROXY_TARGET_DENY_COMMENT
                            for r in d["rules"]), "新端口应有目标端口禁止规则")
        self.assertFalse(any(r.get("type") == "port_deny" and r.get("port") == cur_port
                             and r.get("comment") == panel.PROXY_TARGET_DENY_COMMENT
                             for r in d["rules"]), "旧端口禁止规则应已迁移")
        # 清理：删代理 + 恢复端口
        self._req("DELETE", "/api/proxy/" + p["id"], token=token)
        self._req("POST", "/api/panel/port", {"port": cur_port}, token=token)

    def test_cert_api(self):
        """独立证书 API：申请/列表/续期/移除（按字母序在 full_flow 前，密码为初始值）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        if os.path.exists(panel.CERT_FILE):
            os.remove(panel.CERT_FILE)
        real_issue, real_renew, real_nginx, real_reload = panel.issue_cert, panel.renew_cert, panel.nginx_available, panel.reload_nginx
        panel.issue_cert = lambda dom, email: (True, "证书已签发")
        panel.renew_cert = lambda dom: (True, "证书已续期")
        panel.nginx_available = lambda: True
        panel.reload_nginx = lambda: (True, "nginx 已重载")
        try:
            # 申请
            code, d = self._req("POST", "/api/cert",
                                {"domain": "solo.example.com", "email": "a@b.com"}, token=token)
            self.assertEqual(code, 200, d)
            # 列表
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["certs"]), 1)
            self.assertEqual(d["certs"][0]["domain"], "solo.example.com")
            # 续期
            code, d = self._req("POST", "/api/cert/solo.example.com",
                                {"action": "renew"}, token=token)
            self.assertEqual(code, 200, d)
            # 移除
            code, d = self._req("POST", "/api/cert/solo.example.com",
                                {"action": "delete"}, token=token)
            self.assertEqual(code, 200, d)
            code, d = self._req("GET", "/api/cert", token=token)
            self.assertEqual(len(d["certs"]), 0)
            # 非法域名
            code, d = self._req("POST", "/api/cert",
                                {"domain": "bad domain!"}, token=token)
            self.assertEqual(code, 400)
        finally:
            panel.issue_cert, panel.renew_cert, panel.nginx_available, panel.reload_nginx = real_issue, real_renew, real_nginx, real_reload
            if os.path.exists(panel.CERT_FILE):
                os.remove(panel.CERT_FILE)

    def test_ipv6_mode(self):
        """IPv6 模式设置：sysctl.d + gai.conf 写入（隔离路径）"""
        import tempfile
        d = tempfile.mkdtemp()
        real_sysctl, real_gai = panel.IPV6_SYSCTL, panel.GAI_CONF
        panel.IPV6_SYSCTL = os.path.join(d, "99-ipv6.conf")
        panel.GAI_CONF = os.path.join(d, "gai.conf")
        try:
            ok, msg = panel.set_ipv6_mode("v4_first")
            self.assertTrue(ok, msg)
            self.assertIn("disable_ipv6=0", open(panel.IPV6_SYSCTL).read())
            self.assertIn("precedence ::ffff:0:0/96 100", open(panel.GAI_CONF).read())
            ok, msg = panel.set_ipv6_mode("disable")
            self.assertTrue(ok, msg)
            self.assertIn("disable_ipv6=1", open(panel.IPV6_SYSCTL).read())
            self.assertTrue(open(panel.GAI_CONF).read().strip().startswith("#"),
                            "gai.conf 的 precedence 行应被注释")
            ok, msg = panel.set_ipv6_mode("xxx")
            self.assertFalse(ok)
        finally:
            panel.IPV6_SYSCTL, panel.GAI_CONF = real_sysctl, real_gai

    def test_ipv6_api(self):
        """IPv6 API：查询 + 设置（隔离路径，不触碰真实 /etc）"""
        import tempfile
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        d0 = tempfile.mkdtemp()
        real_s, real_g = panel.IPV6_SYSCTL, panel.GAI_CONF
        panel.IPV6_SYSCTL = os.path.join(d0, "ipv6.conf")
        panel.GAI_CONF = os.path.join(d0, "gai.conf")
        try:
            code, d = self._req("GET", "/api/ipv6", token=token)
            self.assertEqual(code, 200)
            self.assertIn("status", d)
            code, d = self._req("POST", "/api/ipv6",
                                {"mode": "bad"}, token=token)
            self.assertEqual(code, 400)
            code, d = self._req("POST", "/api/ipv6",
                                {"mode": "enable"}, token=token)
            self.assertEqual(code, 200, d)
        finally:
            panel.IPV6_SYSCTL, panel.GAI_CONF = real_s, real_g

    def test_open_port_comment(self):
        """开放端口支持自定义注释（服务开关用「服务:标签」区分规则）"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        port = 31555
        code, d = self._req("POST", "/api/open-port",
                            {"port": port, "proto": "tcp", "comment": "服务:3X-UI"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = [x for x in d["rules"] if x.get("port") == port and x.get("type") == "port_allow"]
        self.assertTrue(r and r[0].get("comment") == "服务:3X-UI", d)
        # 幂等重开：注释更新
        code, d = self._req("POST", "/api/open-port",
                            {"port": port, "proto": "tcp", "comment": "服务:Reality"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/rules", token=token)
        r = [x for x in d["rules"] if x.get("port") == port and x.get("type") == "port_allow"]
        self.assertEqual(r[0].get("comment"), "服务:Reality", "幂等时应更新注释")
        # 清理
        self._req("DELETE", "/api/rules/" + r[0]["id"], token=token)

    def test_ssh_allow_ips(self):
        """SSH 白名单：渲染 ip saddr + drop；空列表恢复默认"""
        rules = panel.RuleStore()
        cfg = panel.Config()
        # 白名单模式
        cfg.set("mode", "strict")
        cfg.set("ssh_port", 2222)
        cfg.set("ssh_allow_ips", ["1.2.3.4", "2001:db8::1"])
        txt = rules.render(cfg)
        self.assertIn("ip saddr {1.2.3.4} tcp dport 2222 accept", txt)
        self.assertIn("ip6 saddr {2001:db8::1} tcp dport 2222 accept", txt)
        self.assertIn("tcp dport 2222 drop", txt)
        # 空列表恢复默认
        cfg.set("ssh_allow_ips", [])
        txt = rules.render(cfg)
        self.assertIn("tcp dport 2222 accept   # SSH 保护(不可删除)", txt)
        self.assertNotIn("tcp dport 2222 drop", txt)

    def test_ssh_allow_ips_api(self):
        """SSH 白名单 API：设置/查询/非法 IP"""
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": "1.2.3.4, 5.6.7.0/24"}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh/allow-ips", token=token)
        self.assertEqual(sorted(d["ips"]), ["1.2.3.4", "5.6.7.0/24"])
        # 非法 IP
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": "999.1.1.1"}, token=token)
        self.assertEqual(code, 400)
        # 清空恢复
        code, d = self._req("POST", "/api/ssh/allow-ips",
                            {"ips": ""}, token=token)
        self.assertEqual(code, 200, d)
        code, d = self._req("GET", "/api/ssh/allow-ips", token=token)
        self.assertEqual(d["ips"], [])

    def test_cert_renew_status(self):
        """证书自动续期状态检测：结构完整（测试环境无 certbot.timer）"""
        info = panel.cert_renew_status()
        self.assertIn("enabled", info)
        self.assertIsInstance(info["enabled"], bool)
        if info["enabled"]:
            self.assertIn("via", info)

    def _token(self):
        """登录拿 token（测试通用；兼容字母序前后密码变化）"""
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        self.fail("无法获取测试 token")

    def test_proxy_edit(self):
        """代理编辑：修改 scheme/websocket/hsts"""
        # 先添加一个代理（dry-run 环境 apply_proxies 安全）
        code, d = self._req("POST", "/api/proxy", {
            "domain": "edit.example.com", "target_host": "127.0.0.1",
            "target_port": 8080, "scheme": "http"}, token=self._token())
        self.assertEqual(code, 200, d)
        pid = d["proxy"]["id"]
        code, d = self._req("POST", "/api/proxy/" + pid, {
            "action": "edit", "scheme": "https",
            "websocket": True, "hsts": True}, token=self._token())
        self.assertEqual(code, 200, d)
        self.assertIn("HSTS: 开", d.get("msg", ""))
        code, d = self._req("GET", "/api/proxy", token=self._token())
        p = next(x for x in d["proxies"] if x["id"] == pid)
        self.assertEqual(p["scheme"], "https")
        self.assertTrue(p["websocket"])
        self.assertTrue(p["hsts"])
        # 非法 scheme
        code, d = self._req("POST", "/api/proxy/" + pid, {
            "action": "edit", "scheme": "ftp"}, token=self._token())
        self.assertEqual(code, 400)
        # 清理
        self._req("DELETE", "/api/proxy/" + pid, token=self._token())

    def test_proxy_hsts(self):
        """反代 HSTS：配置渲染包含 Strict-Transport-Security"""
        p = {"domain": "hsts.example.com", "target_host": "127.0.0.1",
             "target_port": 8080, "scheme": "http", "ssl": True,
             "websocket": False, "hsts": True}
        # mock 证书文件存在
        real = panel.LE_LIVE
        panel.LE_LIVE = tempfile.mkdtemp(prefix="fwpanel-le-")
        try:
            os.makedirs(os.path.join(panel.LE_LIVE, "hsts.example.com"), exist_ok=True)
            for f in ("fullchain.pem", "privkey.pem"):
                with open(os.path.join(panel.LE_LIVE, "hsts.example.com", f), "w") as fh:
                    fh.write("x")
            conf = panel.render_proxy_conf(p)
            self.assertIn('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', conf)
            # 未启用 HSTS 不渲染
            p["hsts"] = False
            conf2 = panel.render_proxy_conf(p)
            self.assertNotIn("Strict-Transport-Security", conf2)
        finally:
            tmp_le = panel.LE_LIVE
            panel.LE_LIVE = real
            shutil.rmtree(tmp_le, ignore_errors=True)

    def test_upgrade_api_check(self):
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        token = d["token"]
        real = panel.get_latest_version
        panel.get_latest_version = lambda: "9.9.9"
        try:
            code, d = self._req("GET", "/api/upgrade/check", token=token)
            self.assertEqual(code, 200)
            self.assertEqual(d["current"], panel.CURRENT_VERSION)
            self.assertEqual(d["latest"], "9.9.9")
            self.assertTrue(d["update_available"])
            # 未登录拒绝
            code, _ = self._req("GET", "/api/upgrade/check")
            self.assertEqual(code, 401)
        finally:
            panel.get_latest_version = real

    def test_full_flow(self):
        # 未登录访问被拒
        code, _ = self._req("GET", "/api/status")
        self.assertEqual(code, 401)
        # 登录
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": TEST_PASS})
        self.assertEqual(code, 200)
        token = d["token"]
        # 状态
        code, d = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(d["mode"], "permissive")
        # 添加端口规则
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": 8080,
                             "comment": "test-web"}, token=token)
        self.assertEqual(code, 200, d)
        # 添加非法规则被拒
        code, d = self._req("POST", "/api/rules",
                            {"type": "port_allow", "proto": "tcp", "port": "abc"}, token=token)
        self.assertEqual(code, 400)
        # 列表
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertEqual(code, 200)
        self.assertEqual(len(d["rules"]), 1)
        rid = d["rules"][0]["id"]
        # 删除
        code, d = self._req("DELETE", f"/api/rules/{rid}", token=token)
        self.assertEqual(code, 200)
        # 服务开关
        code, d = self._req("POST", "/api/service", {"name": "http", "enabled": True}, token=token)
        self.assertEqual(code, 200)
        code, d = self._req("GET", "/api/rules", token=token)
        self.assertTrue(any(r["port"] == 80 for r in d["rules"]))
        # 模式切换
        code, d = self._req("POST", "/api/mode", {"mode": "strict"}, token=token)
        self.assertEqual(code, 200)
        # 改密码（错误旧密码）
        code, d = self._req("POST", "/api/password",
                            {"old_password": "wrong", "new_password": "NewPass123"}, token=token)
        self.assertEqual(code, 400)
        # 改密码（正确）
        code, d = self._req("POST", "/api/password",
                            {"old_password": TEST_PASS, "new_password": "NewPass123"}, token=token)
        self.assertEqual(code, 200)
        # 新密码可登录
        code, d = self._req("POST", "/api/login",
                            {"username": TEST_USER, "password": "NewPass123"})
        self.assertEqual(code, 200)
        # 登出后 token 失效
        self._req("GET", "/api/logout", token=token)
        code, _ = self._req("GET", "/api/status", token=token)
        self.assertEqual(code, 401)


class TestUpgrade(unittest.TestCase):
    """一键升级核心逻辑：备份/替换/回滚（APP_DIR 指向临时目录，不碰真实系统）"""

    def setUp(self):
        self.app_tmp = tempfile.mkdtemp(prefix="fwpanel-app-")
        os.makedirs(os.path.join(self.app_tmp, "static"))
        self.old_app_dir = panel.APP_DIR
        panel.APP_DIR = self.app_tmp
        # 模拟"已安装"的旧文件
        with open(os.path.join(self.app_tmp, "panel.py"), "w") as f:
            f.write('# CURRENT_VERSION = "1.2.0"\nprint("old panel")\n')
        with open(os.path.join(self.app_tmp, "static", "index.html"), "w") as f:
            f.write("<html>old</html>")
        # 屏蔽重启动作
        self.real_timer = panel.threading.Timer
        class FakeTimer:
            def __init__(self, delay, fn):
                self.fn = fn
            def start(self):
                pass
        panel.threading.Timer = FakeTimer
        self.real_restart = panel.restart_service
        panel.restart_service = lambda: None

    def tearDown(self):
        panel.APP_DIR = self.old_app_dir
        panel.threading.Timer = self.real_timer
        panel.restart_service = self.real_restart
        shutil.rmtree(self.app_tmp, ignore_errors=True)

    def _make_new_files(self, version="9.9.9", broken=False):
        src = tempfile.mkdtemp(prefix="fwpanel-new-")
        py_content = f'CURRENT_VERSION = "{version}"\nprint("new panel")\n'
        if broken:
            py_content = "def broken(:\n"
        with open(os.path.join(src, "panel.py"), "w") as f:
            f.write(py_content)
        with open(os.path.join(src, "index.html"), "w") as f:
            f.write("<html>new</html>")
        logo = os.path.join(src, "github-logo.png")
        with open(logo, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\nfake-logo")
        ico = os.path.join(src, "favicon.ico")
        with open(ico, "wb") as f:
            f.write(b"\x00\x00\x01\x00fake-ico")
        return os.path.join(src, "panel.py"), os.path.join(src, "index.html"), logo, ico

    def test_upgrade_success(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: self._make_new_files("9.9.9")
        ok, msg = panel.perform_upgrade()
        self.assertTrue(ok, msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("9.9.9", f.read())
        self.assertTrue(os.path.exists(os.path.join(self.app_tmp, "panel.py.bak")),
                        "升级应生成备份文件")
        self.assertTrue(os.path.exists(os.path.join(self.app_tmp, "static", "favicon.ico")),
                        "升级应部署 favicon.ico")

    def test_version_compare(self):
        self.assertTrue(panel.version_gt("1.10.0", "1.9.0"))
        self.assertTrue(panel.version_gt("1.2.1", "1.2.0"))
        self.assertFalse(panel.version_gt("1.2.0", "1.2.0"))
        self.assertFalse(panel.version_gt("1.1.3", "1.2.0"))

    def test_ssh_service_name(self):
        """SSH 服务名检测：有 ssh.service 用 ssh，否则 sshd"""
        import subprocess as sp
        real = panel.subprocess.run
        def fake(cmd, *a, **k):
            out = "ssh.service enabled\nsshd.service enabled\n" if "list-unit" in " ".join(cmd) else ""
            return sp.CompletedProcess(cmd, 0, stdout=out, stderr="")
        panel.subprocess.run = fake
        try:
            self.assertEqual(panel.ssh_service_name(), "ssh")
        finally:
            panel.subprocess.run = real
        def fake2(cmd, *a, **k):
            return sp.CompletedProcess(cmd, 0, stdout="sshd.service enabled\n", stderr="")
        panel.subprocess.run = fake2
        try:
            self.assertEqual(panel.ssh_service_name(), "sshd")
        finally:
            panel.subprocess.run = real

    def test_bf_cfg_defaults(self):
        cfg = make_cfg()
        bf = panel.bf_cfg(cfg)
        self.assertEqual(bf["enabled"], False)
        self.assertEqual(bf["max_fails"], 5)
        self.assertEqual(bf["ban_seconds"], 3600)
        self.assertEqual(bf["fail_window"], 300)
        cfg.set("bruteforce", {"enabled": True, "max_fails": 3, "ban_seconds": 600, "fail_window": 120})
        bf = panel.bf_cfg(cfg)
        self.assertEqual(bf["max_fails"], 3)
        self.assertEqual(bf["ban_seconds"], 600)

    def test_bf_cycle_bans_and_expires(self):
        """防爆破一轮扫描：封禁超阈值 IP + 到期自动解封"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 3, "ban_seconds": 600, "fail_window": 300})
        store = panel.RuleStore()
        store.rules = []
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {"203.0.113.66": 3, "127.0.0.1": 99}
        panel.get_established_ips = lambda p: set()
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            # 超阈值被封禁，回环 IP 豁免
            self.assertTrue(any(r.get("ip") == "203.0.113.66" for r in store.rules))
            self.assertFalse(any(r.get("ip") == "127.0.0.1" for r in store.rules))
            bans = panel.load_bans()
            self.assertEqual(bans["203.0.113.66"], 1600, "封禁到期时间 = now + ban_seconds")
            # 到期后自动解封
            panel.bruteforce_cycle(cfg, store, now=1700)
            self.assertFalse(any(r.get("ip") == "203.0.113.66" for r in store.rules),
                             "到期应自动解封")
            self.assertNotIn("203.0.113.66", panel.load_bans())
        finally:
            panel.get_failed_ssh_attempts = real_a
            panel.get_established_ips = real_e
            panel.RuleStore().rules = []
            panel.RuleStore().save()
            if os.path.exists(panel.BANS_FILE):
                os.remove(panel.BANS_FILE)

    def test_bf_cycle_exempt_established(self):
        """当前已连接 IP 豁免封禁（防把自己锁死）"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 2, "ban_seconds": 600, "fail_window": 300})
        store = panel.RuleStore()
        store.rules = []
        real_a, real_e = panel.get_failed_ssh_attempts, panel.get_established_ips
        panel.get_failed_ssh_attempts = lambda w: {"198.51.100.9": 5}
        panel.get_established_ips = lambda p: {"198.51.100.9"}
        try:
            panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertFalse(any(r.get("ip") == "198.51.100.9" for r in store.rules),
                             "当前连接 IP 应豁免")
        finally:
            panel.get_failed_ssh_attempts = real_a
            panel.get_established_ips = real_e
            panel.RuleStore().rules = []
            panel.RuleStore().save()
            if os.path.exists(panel.BANS_FILE):
                os.remove(panel.BANS_FILE)

    def test_bf_disabled_no_action(self):
        cfg = make_cfg()   # 默认未启用
        store = panel.RuleStore()
        store.rules = []
        real_a = panel.get_failed_ssh_attempts
        panel.get_failed_ssh_attempts = lambda w: {"1.2.3.4": 999}
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertEqual(logs, [])
            self.assertEqual(store.rules, [])
        finally:
            panel.get_failed_ssh_attempts = real_a

    def test_disable_deletes_table(self):
        """关闭防火墙：删除 fwpanel 表"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_dry = panel.DRY_RUN

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.DRY_RUN = False
        try:
            nft = panel.NFTManager(panel.RuleStore(), make_cfg())
            ok, msg = nft.disable()
            self.assertTrue(ok, msg)
            self.assertIn(["nft", "delete", "table", "inet", "fwpanel"], calls)
        finally:
            panel.subprocess.run = real_run
            panel.DRY_RUN = real_dry

    def test_bf_skipped_when_fw_disabled(self):
        """防火墙关闭时防爆破扫描跳过"""
        cfg = make_cfg()
        cfg.set("bruteforce", {"enabled": True, "max_fails": 2, "ban_seconds": 600, "fail_window": 300})
        cfg.set("firewall_enabled", False)
        store = panel.RuleStore()
        store.rules = []
        real_a = panel.get_failed_ssh_attempts
        panel.get_failed_ssh_attempts = lambda w: {"1.2.3.4": 99}
        try:
            logs = panel.bruteforce_cycle(cfg, store, now=1000)
            self.assertEqual(logs, [])
            self.assertEqual(store.rules, [])
        finally:
            panel.get_failed_ssh_attempts = real_a

    def test_render_proxy_conf(self):
        """nginx 反代配置生成：HTTP/ACME 挑战/WebSocket/HTTPS 跳转"""
        real = panel.cert_files_exist
        panel.cert_files_exist = lambda d: False
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": True, "ssl": False,
            })
            self.assertIn("server_name app.example.com;", conf)
            self.assertIn("proxy_pass http://127.0.0.1:8080;", conf)
            self.assertIn("location /.well-known/acme-challenge/", conf)
            self.assertIn("proxy_set_header Upgrade $http_upgrade;", conf)
            self.assertNotIn("listen 443", conf)
        finally:
            panel.cert_files_exist = real
        # 有证书时：HTTP 跳转 + HTTPS server
        panel.cert_files_exist = lambda d: True
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "10.0.0.2",
                "target_port": 3000, "scheme": "http", "websocket": False, "ssl": True,
            })
            self.assertIn("listen 443 ssl;", conf)
            self.assertIn("ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;", conf)
            self.assertIn("return 301 https://$host$request_uri;", conf)
        finally:
            panel.cert_files_exist = real

    def test_proxy_store_crud(self):
        """ProxyStore 增删查"""
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)
        store = panel.ProxyStore()
        p = store.add({"domain": "a.example.com", "target_host": "127.0.0.1",
                       "target_port": 8080, "scheme": "http", "websocket": False, "ssl": False})
        self.assertTrue(p["id"])
        self.assertEqual(store.get(p["id"])["domain"], "a.example.com")
        store2 = panel.ProxyStore()
        self.assertEqual(len(store2.proxies), 1, "应持久化到文件")
        self.assertTrue(store.remove(p["id"]))
        self.assertFalse(store.remove(p["id"]))
        if os.path.exists(panel.PROXIES_FILE):
            os.remove(panel.PROXIES_FILE)

    def test_apply_proxies_dry_run(self):
        """apply_proxies 在 dry-run 环境返回成功"""
        store = panel.ProxyStore()
        ok, msg = panel.apply_proxies(store)
        self.assertTrue(ok, msg)

    def test_pkg_mgr_detected(self):
        """包管理器检测（本机应为 apt）"""
        mgr = panel.pkg_mgr()
        self.assertIn(mgr, ("apt", "pacman", "dnf"))

    def test_install_pkgs_apt(self):
        """install_pkgs：apt 系执行 update + install"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.pkg_mgr = lambda: "apt"
        try:
            ok, msg = panel.install_pkgs(["nginx", "certbot"])
            self.assertTrue(ok, msg)
            self.assertTrue(any(c[0] == "apt-get" and c[1] == "update" for c in calls))
            self.assertTrue(any(c[0] == "apt-get" and "install" in c and "nginx" in c for c in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr

    def test_host_guard(self):
        """host 守卫：普通域名精确匹配，通配符域名正则匹配"""
        g = panel.host_guard("app.example.com")
        self.assertIn('if ($host != "app.example.com")', g)
        self.assertIn("return 444", g)
        g2 = panel.host_guard("*.example.com")
        self.assertIn("!~", g2)
        self.assertNotIn('$host != "', g2)

    def test_render_proxy_conf_block_ip(self):
        """开启禁止 IP 访问时配置包含 host 守卫"""
        real = panel.cert_files_exist
        panel.cert_files_exist = lambda d: False
        try:
            conf = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": False,
                "ssl": False, "block_ip": True,
            })
            self.assertIn('if ($host != "app.example.com")', conf)
            self.assertIn("return 444", conf)
            conf2 = panel.render_proxy_conf({
                "domain": "app.example.com", "target_host": "127.0.0.1",
                "target_port": 8080, "scheme": "http", "websocket": False,
                "ssl": False, "block_ip": False,
            })
            self.assertNotIn("return 444", conf2)
        finally:
            panel.cert_files_exist = real

    def test_bbr_status_detected(self):
        """BBR 状态检测：返回布尔值（本机 Linux 有 /proc/sys）"""
        self.assertIsInstance(panel.bbr_status(), bool)
        self.assertIsInstance(panel.bbr_available(), bool)

    def test_enable_bbr_dry_run(self):
        """BBR 开启在 dry-run 环境：不写文件直接返回成功"""
        ok, msg = panel.enable_bbr()
        self.assertTrue(ok, msg)

    def test_enable_bbr_verify(self):
        """BBR 开启后回读校验：生效返回成功，未生效返回失败"""
        import subprocess as sp
        real_run, real_avail, real_status = (panel.subprocess.run,
                                             panel.bbr_available, panel.bbr_status)
        real_dry, real_conf = panel.DRY_RUN, os.environ.get("FW_BBR_CONF")
        os.environ["FW_BBR_CONF"] = "/tmp/fwpanel-bbr-test.conf"
        panel.DRY_RUN = False
        panel.bbr_available = lambda: True
        panel.subprocess.run = lambda cmd, *a, **k: sp.CompletedProcess(cmd, 0, stdout="", stderr="")
        try:
            panel.bbr_status = lambda: True
            ok, msg = panel.enable_bbr()
            self.assertTrue(ok, msg)
            panel.bbr_status = lambda: False
            ok, msg = panel.enable_bbr()
            self.assertFalse(ok, "回读未生效应返回失败")
            self.assertIn("未生效", msg)
        finally:
            panel.subprocess.run, panel.bbr_available, panel.bbr_status = real_run, real_avail, real_status
            panel.DRY_RUN = real_dry
            if real_conf is None:
                os.environ.pop("FW_BBR_CONF", None)
            else:
                os.environ["FW_BBR_CONF"] = real_conf
            if os.path.exists("/tmp/fwpanel-bbr-test.conf"):
                os.remove("/tmp/fwpanel-bbr-test.conf")

    def test_ensure_nginx_default_blocks_ip(self):
        """默认兜底配置：80 default_server + 443 ssl_reject_handshake（禁止 IP 直连）"""
        import tempfile
        d = tempfile.mkdtemp()
        real_dir, real_dry, real_ver = (panel.nginx_conf_dir, panel.DRY_RUN,
                                        panel.nginx_supports_reject_handshake)
        panel.nginx_conf_dir = lambda: d
        panel.DRY_RUN = False
        panel.nginx_supports_reject_handshake = lambda: True
        try:
            panel.ensure_nginx_default()
            content = open(os.path.join(d, "fwpanel-default.conf")).read()
            self.assertIn("listen 80 default_server;", content)
            self.assertIn("return 444;", content)
            self.assertIn("listen 443 ssl default_server;", content)
            self.assertIn("ssl_reject_handshake on;", content)
            # 幂等：再次调用不报错且内容不变
            panel.ensure_nginx_default()
            content2 = open(os.path.join(d, "fwpanel-default.conf")).read()
            self.assertEqual(content, content2)
        finally:
            panel.nginx_conf_dir, panel.DRY_RUN = real_dir, real_dry
            panel.nginx_supports_reject_handshake = real_ver

    def test_sync_ssh_port(self):
        """SSH 保护端口自动同步：自动模式跟随系统端口，手动模式不覆盖"""
        cfg = make_cfg()
        real = panel.get_sshd_port
        panel.get_sshd_port = lambda: 2222
        try:
            # 自动模式：同步到检测端口
            cfg.set("ssh_port_auto", True)
            cfg.set("ssh_port", 22)
            changed = panel.sync_ssh_port(cfg)
            self.assertTrue(changed)
            self.assertEqual(int(cfg.get("ssh_port")), 2222)
            # 手动模式：不覆盖
            cfg.set("ssh_port_auto", False)
            cfg.set("ssh_port", 33)
            changed = panel.sync_ssh_port(cfg)
            self.assertFalse(changed)
            self.assertEqual(int(cfg.get("ssh_port")), 33)
        finally:
            panel.get_sshd_port = real

    def test_apply_is_idempotent(self):
        """apply 必须先删旧表再加载（防 nft -f 追加累积），回归测试"""
        import subprocess as sp
        calls = []
        real_run = panel.subprocess.run
        real_dry = panel.DRY_RUN

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        panel.subprocess.run = fake_run
        panel.DRY_RUN = False
        try:
            store = panel.RuleStore()
            store.rules = [{"id": "1", "type": "port_allow", "proto": "tcp",
                            "port": 8080, "comment": "t"}]
            nft = panel.NFTManager(store, make_cfg())
            ok, msg = nft.apply()
            self.assertTrue(ok, msg)
            # 调用序列中 delete 必须在 nft -f 之前
            delete_idx = next(i for i, c in enumerate(calls)
                              if c[:5] == ["nft", "delete", "table", "inet", "fwpanel"])
            load_idx = next(i for i, c in enumerate(calls) if c[:2] == ["nft", "-f"])
            self.assertLess(delete_idx, load_idx, "必须先删除旧表再加载新规则")
        finally:
            panel.subprocess.run = real_run
            panel.DRY_RUN = real_dry

    def test_upgrade_same_version(self):
        panel.get_latest_version = lambda: panel.CURRENT_VERSION
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        self.assertIn("已是最新", msg)

    def test_upgrade_download_fail_keeps_old(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: None
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("old panel", f.read())

    def test_upgrade_broken_file_keeps_old(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: self._make_new_files(broken=True)
        ok, msg = panel.perform_upgrade()
        self.assertFalse(ok)
        self.assertIn("校验失败", msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("old panel", f.read())


class TestDocker(unittest.TestCase):
    """Docker 模块 API 测试：mock docker_* 辅助函数（真实环境无 docker）"""

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg()
        cls.store = panel.RuleStore()
        cls.store.rules = []
        cls.nft = panel.NFTManager(cls.store, cls.cfg)
        cls.auth = panel.Auth(cls.cfg)
        cls.server = panel.PanelServer(("127.0.0.1", 17998), panel.PanelHandler,
                                       cls.cfg, cls.store, cls.nft, cls.auth)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:17998"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _req(self, method, path, data=None, token=None):
        req = urllib.request.Request(self.base + path, method=method)
        if token:
            req.add_header("Authorization", "Bearer " + token)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, body) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {}

    def _token(self):
        for pw in (TEST_PASS, "NewPass123"):
            code, d = self._req("POST", "/api/login",
                                {"username": TEST_USER, "password": pw})
            if code == 200:
                return d["token"]
        raise RuntimeError("无法登录")

    def _patch_docker(self, **mocks):
        saved = {}
        for name, fn in mocks.items():
            saved[name] = getattr(panel, name)
            setattr(panel, name, fn)
        return saved

    def test_docker_status_not_installed(self):
        tok = self._token()
        saved = self._patch_docker(docker_available=lambda: False)
        try:
            code, d = self._req("GET", "/api/docker", token=tok)
            self.assertEqual(code, 200)
            self.assertFalse(d["installed"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_status_installed(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_available=lambda: True,
            docker_status=lambda: {"installed": True, "service_active": True,
                                   "version": "Docker version 27.0.0",
                                   "containers": 2, "running": 1})
        try:
            code, d = self._req("GET", "/api/docker", token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["installed"])
            self.assertEqual(d["containers"], 2)
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_containers(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_containers=lambda all_: [
                {"id": "abc123", "name": "nginx", "image": "nginx:latest",
                 "status": "Up 2 hours", "ports": "0.0.0.0:80->80/tcp", "running": True}])
        try:
            code, d = self._req("GET", "/api/docker/containers", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["containers"]), 1)
            self.assertEqual(d["containers"][0]["name"], "nginx")
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_official(self):
        tok = self._token()
        saved = self._patch_docker(install_docker_pkgs=lambda source="official": (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "official"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_china(self):
        tok = self._token()
        saved = self._patch_docker(install_docker_pkgs=lambda source="official": (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "china"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_invalid_source_defaults(self):
        """非法 source 应回退 official（不报错）"""
        tok = self._token()
        calls = []
        saved = self._patch_docker(
            install_docker_pkgs=lambda source="official": calls.append(source) or (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/install",
                                {"source": "hack"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_install_official_apt_fallback(self):
        """apt 官方源：docker-compose-v2 不存在时回退 docker-compose（v1）"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            # apt-get update 成功；install v2 失败（找不到包）；install v1 成功
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            if "docker-compose-v2" in args:
                return types.SimpleNamespace(
                    returncode=100, stdout="",
                    stderr="E: Unable to locate package docker-compose-v2")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.install_docker_pkgs("official")
            self.assertTrue(ok)
            # 断言第二次 install 用了 docker-compose（v1 回退）
            self.assertTrue(any("docker-compose" in a and "docker-compose-v2" not in a
                                for a in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_docker_install_official_apt_both_fail(self):
        """apt 官方源：v2 和 v1 都失败 → 返回失败"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            if args[0] == "apt-get" and args[1] == "update":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(
                returncode=100, stdout="",
                stderr="E: Unable to locate package docker-compose")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.install_docker_pkgs("official")
            self.assertFalse(ok)
            self.assertIn("安装失败", msg)
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_docker_action_valid(self):
        tok = self._token()
        saved = self._patch_docker(docker_action=lambda act, cid: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/action",
                                {"action": "restart", "id": "abc123"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_action_invalid(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/action",
                            {"action": "hack", "id": "abc123"}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_create_missing_fields(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/create",
                            {"name": "", "image": ""}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_pull(self):
        tok = self._token()
        saved = self._patch_docker(docker_pull=lambda name: (True, "pulled"))
        try:
            code, d = self._req("POST", "/api/docker/pull",
                                {"name": "nginx:latest"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_rmi(self):
        tok = self._token()
        saved = self._patch_docker(docker_rmi=lambda iid: (True, "removed"))
        try:
            code, d = self._req("POST", "/api/docker/rmi",
                                {"id": "abc123"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_up(self):
        tok = self._token()
        saved = self._patch_docker(docker_compose_up=lambda c: (True, "up"))
        try:
            code, d = self._req("POST", "/api/docker/compose/up",
                                {"content": "services:\n  web:\n    image: nginx\n"}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_compose_up_empty(self):
        tok = self._token()
        code, d = self._req("POST", "/api/docker/compose/up",
                            {"content": ""}, token=tok)
        self.assertEqual(code, 400)

    def test_docker_compose_down(self):
        tok = self._token()
        saved = self._patch_docker(docker_compose_down=lambda: (True, "down"))
        try:
            code, d = self._req("POST", "/api/docker/compose/down", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_stats(self):
        tok = self._token()
        saved = self._patch_docker(
            docker_stats=lambda: [{"name": "nginx", "cpu": "0.10%",
                                   "mem": "10MiB / 500MiB", "mem_pct": "2.00%",
                                   "net": "1MB / 2MB", "block": "0B / 0B"}])
        try:
            code, d = self._req("GET", "/api/docker/stats", token=tok)
            self.assertEqual(code, 200)
            self.assertEqual(len(d["stats"]), 1)
            self.assertEqual(d["stats"][0]["name"], "nginx")
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_dirs_create(self):
        """一键创建目录：mock create_docker_dirs 返回成功"""
        tok = self._token()
        saved = self._patch_docker(create_docker_dirs=lambda: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/dirs", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_docker_dirs_status(self):
        """目录状态 API 返回结构（mock 已存在）"""
        tok = self._token()
        saved = self._patch_docker(
            create_docker_dirs=lambda: (True, "ok"))
        # mock os.path.isdir 和 DOCKER_DATA_DIRS 用真实值
        real_isdir = os.path.isdir
        try:
            os.path.isdir = lambda p: p.startswith("/DockerData")
            code, d = self._req("GET", "/api/docker/dirs", token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["exists"])
            self.assertEqual(d["base"], "/DockerData")
            self.assertEqual(d["total"], len(panel.DOCKER_DATA_DIRS))
        finally:
            os.path.isdir = real_isdir
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_create_docker_dirs_idempotent(self):
        """重复创建不报错（exist_ok）"""
        real_makedirs = os.makedirs
        real_base = panel.DOCKER_DATA_BASE
        try:
            panel.DOCKER_DATA_BASE = tempfile.mkdtemp(prefix="fw-dockerdata-")
            panel.DRY_RUN = False
            calls = []
            os.makedirs = lambda p, exist_ok=False: calls.append(p)
            ok, msg = panel.create_docker_dirs()
            self.assertTrue(ok)
            self.assertIn("已创建", msg)
            # 第二次调用（已存在）也应成功
            ok2, _ = panel.create_docker_dirs()
            self.assertTrue(ok2)
        finally:
            os.makedirs = real_makedirs
            panel.DOCKER_DATA_BASE = real_base
            panel.DRY_RUN = True

    def test_docker_uninstall_api(self):
        """卸载 API：mock uninstall_docker_pkgs 返回成功"""
        tok = self._token()
        saved = self._patch_docker(uninstall_docker_pkgs=lambda: (True, "ok"))
        try:
            code, d = self._req("POST", "/api/docker/uninstall", {}, token=tok)
            self.assertEqual(code, 200)
            self.assertTrue(d["ok"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)

    def test_uninstall_docker_apt_covers_both_sources(self):
        """apt 卸载命令必须包含国内(docker-ce) + 国外(docker.io)两种来源包名"""
        import types
        real_run = panel.subprocess.run
        real_mgr = panel.pkg_mgr
        real_dry = panel.DRY_RUN
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        try:
            panel.pkg_mgr = lambda: "apt"
            panel.DRY_RUN = False
            panel.subprocess.run = fake_run
            ok, msg = panel.uninstall_docker_pkgs()
            self.assertTrue(ok)
            # 找到 apt-get remove 命令，断言同时含 docker-ce 和 docker.io
            remove_calls = [a for a in calls if a[0] == "apt-get" and a[1] == "remove"]
            self.assertTrue(remove_calls)
            self.assertTrue(any("docker-ce" in a for a in remove_calls))
            self.assertTrue(any("docker.io" in a for a in remove_calls))
            self.assertTrue(any("docker-compose-plugin" in a for a in remove_calls))
            # 停止服务命令存在
            self.assertTrue(any(a[0] == "systemctl" and a[1] == "stop" for a in calls))
        finally:
            panel.subprocess.run = real_run
            panel.pkg_mgr = real_mgr
            panel.DRY_RUN = real_dry

    def test_docker_logs(self):
        tok = self._token()
        saved = self._patch_docker(docker_logs=lambda cid, tail=200: "log line 1")
        try:
            code, d = self._req("GET", "/api/docker/logs/abc123", token=tok)
            self.assertEqual(code, 200)
            self.assertIn("log line", d["logs"])
        finally:
            for name, fn in saved.items():
                setattr(panel, name, fn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
