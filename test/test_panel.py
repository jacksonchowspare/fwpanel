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
        self.assertTrue(any(r["port"] == 9000 for r in d["rules"]))
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
        try:
            code, d = self._req("POST", "/api/ssh/apply", {"ssh_port": 3333}, token=token)
            self.assertEqual(code, 200, d)
            self.assertIn("临时放行", d["msg"])
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
        self.real_run = panel.subprocess.run
        panel.subprocess.run = lambda *a, **k: None

    def tearDown(self):
        panel.APP_DIR = self.old_app_dir
        panel.threading.Timer = self.real_timer
        panel.subprocess.run = self.real_run
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
        return os.path.join(src, "panel.py"), os.path.join(src, "index.html")

    def test_upgrade_success(self):
        panel.get_latest_version = lambda: "9.9.9"
        panel.download_panel_files = lambda tag, tmp: self._make_new_files("9.9.9")
        ok, msg = panel.perform_upgrade()
        self.assertTrue(ok, msg)
        with open(os.path.join(self.app_tmp, "panel.py")) as f:
            self.assertIn("9.9.9", f.read())
        self.assertTrue(os.path.exists(os.path.join(self.app_tmp, "panel.py.bak")),
                        "升级应生成备份文件")

    def test_version_compare(self):
        self.assertTrue(panel.version_gt("1.10.0", "1.9.0"))
        self.assertTrue(panel.version_gt("1.2.1", "1.2.0"))
        self.assertFalse(panel.version_gt("1.2.0", "1.2.0"))
        self.assertFalse(panel.version_gt("1.1.3", "1.2.0"))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
