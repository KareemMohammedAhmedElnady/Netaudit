"""Unit tests for NetAudit parser, checks and redaction. Run:
    python3 -m unittest discover -s tests -v   (from the repo root)
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netaudit.checks import run_audit
from netaudit.live import redact
from netaudit.parser import parse_config
from netaudit.report import render_html, render_text
from netaudit.models import AuditReport

CLEAN_ROUTER = """hostname R2
enable secret 9 hashedvalue
service password-encryption
username admin secret Sup3rSecret
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.12.2 255.255.255.0
 no shutdown
router ospf 1
 network 10.0.12.0 0.0.0.255 area 0
ip ssh version 2
line vty 0 4
 transport input ssh
 login local
end
"""


def findings_for(config):
    dev = parse_config(config)
    return run_audit([dev])


def titles(findings):
    return [f.title for f in findings]


class ParserTests(unittest.TestCase):
    def test_hostname_and_interface(self):
        dev = parse_config(CLEAN_ROUTER)
        self.assertEqual(dev.hostname, "R2")
        self.assertEqual(dev.interfaces[0].ip_address, "10.0.12.2")
        self.assertFalse(dev.interfaces[0].shutdown)

    def test_acl_entries_and_extended(self):
        dev = parse_config("hostname X\nip access-list extended ACL1\n"
                           " permit tcp any any eq 80\n permit ip any any\n")
        self.assertIn("ACL1", dev.acls)
        self.assertIn("ACL1", dev.extended_acls)
        self.assertEqual(len(dev.acls["ACL1"]), 2)

    def test_vty_access_class_tracked(self):
        dev = parse_config("hostname X\nip access-list standard VTY_FILTER\n"
                           " permit 10.0.0.0 0.255.255.255\n"
                           "line vty 0 4\n access-class VTY_FILTER in\n"
                           " transport input ssh\n password pw\n login\n")
        self.assertIn("VTY_FILTER", dev.acl_refs)

    def test_interface_level_ospf_detected(self):
        dev = parse_config("hostname X\nrouter ospf 1\n"
                           "interface GigabitEthernet0/0\n"
                           " ip ospf 1 area 0\n no shutdown\n")
        self.assertTrue(dev.ospf_on_interfaces)


class CheckTests(unittest.TestCase):
    def test_clean_router_has_no_critical(self):
        findings = findings_for(CLEAN_ROUTER)
        self.assertEqual([f for f in findings if f.severity == "critical"], [])

    def test_plaintext_enable_password_flagged(self):
        findings = findings_for("hostname R\nenable password cisco\n")
        self.assertIn("Enable password stored as plaintext/weak type-7",
                      titles(findings))

    def test_login_local_not_flagged_as_unauthenticated(self):
        findings = findings_for(CLEAN_ROUTER)
        self.assertNotIn("VTY lines without authentication", titles(findings))

    def test_telnet_only_is_critical(self):
        findings = findings_for("hostname R\nline vty 0 4\n"
                                " transport input telnet\n password pw\n login\n")
        self.assertIn("Remote access over Telnet only", titles(findings))

    def test_interface_ospf_no_false_network_warning(self):
        findings = findings_for("hostname R\nrouter ospf 1\n"
                                "interface GigabitEthernet0/0\n"
                                " ip address 10.0.0.1 255.255.255.0\n"
                                " ip ospf 1 area 0\n no shutdown\n")
        self.assertNotIn("OSPF enabled with no network statements",
                         titles(findings))

    def test_missing_network_statements_flagged(self):
        findings = findings_for("hostname R\nrouter ospf 1\n"
                                "interface Loopback0\n ip address 1.1.1.1"
                                " 255.255.255.255\n")
        self.assertIn("OSPF enabled with no network statements",
                      titles(findings))

    def test_acl_applied_on_vty_not_flagged_unapplied(self):
        findings = findings_for(
            "hostname R\nip access-list standard VTY_FILTER\n"
            " permit 10.0.0.0 0.255.255.255\n"
            "line vty 0 4\n access-class VTY_FILTER in\n"
            " transport input ssh\n password pw\n login\n")
        self.assertNotIn("ACL 'VTY_FILTER' defined but not applied",
                         titles(findings))

    def test_unapplied_acl_flagged(self):
        findings = findings_for("hostname R\nip access-list extended ORPHAN\n"
                                " permit tcp any any eq 443\n")
        self.assertIn("ACL 'ORPHAN' defined but not applied", titles(findings))

    def test_access_port_defaults_to_vlan1_is_info(self):
        findings = findings_for("hostname SW\ninterface GigabitEthernet1/0/3\n"
                                " switchport mode access\n")
        match = [f for f in findings if "defaults to VLAN 1" in f.title]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "info")

    def test_rw_snmp_community_masked_in_findings(self):
        findings = findings_for("hostname R\nsnmp-server community S3cretRW RW\n")
        rw = [f for f in findings if "read-write" in f.title]
        self.assertEqual(len(rw), 1)
        self.assertNotIn("S3cretRW", rw[0].title)

    def test_weak_snmp_community_is_critical(self):
        findings = findings_for("hostname R\nsnmp-server community public RO\n")
        crit = [f for f in findings if f.severity == "critical"
                and "public" in f.title]
        self.assertEqual(len(crit), 1)

    def test_duplicate_ip_across_devices_is_critical(self):
        a = parse_config("hostname A\ninterface Gi0/0\n"
                         " ip address 10.0.0.1 255.255.255.0\n no shutdown\n")
        b = parse_config("hostname B\ninterface Gi0/1\n"
                         " ip address 10.0.0.1 255.255.255.0\n no shutdown\n")
        findings = run_audit([a, b])
        self.assertTrue(any("Duplicate IP" in f.title
                            and f.severity == "critical" for f in findings))


class ConnectPolicyTests(unittest.TestCase):
    """_connect must fail closed when strict host key checking is unsupported."""

    def _fake_netmiko(self, connect_handler):
        import types
        fake = types.ModuleType("netmiko")
        fake.ConnectHandler = connect_handler
        sys.modules["netmiko"] = fake
        self.addCleanup(lambda: sys.modules.pop("netmiko", None))

    def test_fails_closed_without_strict_support(self):
        def ConnectHandler(device_type, host, username, password):
            raise AssertionError("should never connect")
        self._fake_netmiko(ConnectHandler)
        from netaudit.live import _connect
        with self.assertRaises(SystemExit) as ctx:
            _connect({"device_type": "cisco_ios", "host": "192.0.2.1",
                      "username": "u", "password": "p"})
        self.assertIn("host key", str(ctx.exception))

    def test_strict_checking_enabled_when_supported(self):
        captured = {}
        def ConnectHandler(device_type=None, host=None, username=None,
                           password=None, strict_host_key_checking=None,
                           **kwargs):
            captured.update(device_type=device_type, host=host,
                            username=username, password=password,
                            strict_host_key_checking=strict_host_key_checking,
                            **kwargs)
            raise RuntimeError("sentinel-stop-before-real-connection")
        self._fake_netmiko(ConnectHandler)
        from netaudit.live import _connect
        with self.assertRaises(RuntimeError):
            _connect({"device_type": "cisco_ios", "host": "192.0.2.1",
                      "username": "u", "password": "p"})
        self.assertIs(captured.get("strict_host_key_checking"), True)

    def test_password_from_environment(self):
        captured = {}
        def ConnectHandler(device_type=None, host=None, username=None,
                           password=None, strict_host_key_checking=None,
                           **kwargs):
            captured.update(device_type=device_type, host=host,
                            username=username, password=password,
                            strict_host_key_checking=strict_host_key_checking,
                            **kwargs)
            raise RuntimeError("sentinel")
        self._fake_netmiko(ConnectHandler)
        import os
        os.environ["NETAUDIT_TEST_PW"] = "env-secret"
        self.addCleanup(lambda: os.environ.pop("NETAUDIT_TEST_PW", None))
        from netaudit.live import _connect
        with self.assertRaises(RuntimeError):
            _connect({"device_type": "cisco_ios", "host": "192.0.2.1",
                      "username": "u", "password_env": "NETAUDIT_TEST_PW"})
        self.assertEqual(captured.get("password"), "env-secret")


class RedactionTests(unittest.TestCase):
    def test_redact_credentials(self):
        out = redact("snmp-server community TopSecret123 RO\n"
                     "enable secret 9 hashedvalue\n"
                     "username admin password hunter2\n"
                     "hostname R1")
        self.assertNotIn("TopSecret123", out)
        self.assertNotIn("hashedvalue", out)
        self.assertNotIn("hunter2", out)
        self.assertIn("hostname R1", out)

    def test_report_does_not_leak_rw_community(self):
        dev = parse_config("hostname R\nsnmp-server community TopSecretRW RW\n")
        report = AuditReport(devices=[dev], findings=run_audit([dev]))
        self.assertNotIn("TopSecretRW", render_text(report))
        self.assertNotIn("TopSecretRW", render_html(report))


if __name__ == "__main__":
    unittest.main()
