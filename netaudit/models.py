"""Core data models shared by the parser, checks and reports."""
from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ("critical", "warning", "info")


@dataclass
class Finding:
    severity: str            # critical | warning | info
    category: str            # security | vlan | routing | acl | hygiene
    device: str
    title: str
    detail: str = ""
    recommendation: str = ""


@dataclass
class Interface:
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    shutdown: bool = False
    switchport_mode: Optional[str] = None       # access | trunk
    access_vlan: Optional[int] = None
    acls_in: list = field(default_factory=list)   # ACL names/numbers applied inbound
    acls_out: list = field(default_factory=list)


@dataclass
class Device:
    hostname: str
    source: str = ""                       # file path or host the config came from
    raw: str = ""
    interfaces: list = field(default_factory=list)      # list[Interface]
    vlans: dict = field(default_factory=dict)           # vlan_id -> name
    acls: dict = field(default_factory=dict)            # name -> list of entry lines
    extended_acls: set = field(default_factory=set)     # names of extended ACLs
    enable_secret: bool = False
    enable_password_plain: bool = False
    password_encryption: bool = False      # service password-encryption present
    users_plain: list = field(default_factory=list)     # usernames with 'password'
    vty_transport: set = field(default_factory=set)     # telnet / ssh on vty lines
    vty_has_password: bool = False
    vty_login_local: bool = False
    snmp_communities: list = field(default_factory=list)  # (community, RO|RW)
    routing_protocols: dict = field(default_factory=dict) # proto -> config lines
    ospf_on_interfaces: bool = False    # interface-level 'ip ospf <pid> area' used
    acl_refs: set = field(default_factory=set)  # ACLs referenced outside interfaces
    has_ssh_version: bool = False


@dataclass
class AuditReport:
    devices: list = field(default_factory=list)   # list[Device]
    findings: list = field(default_factory=list)  # list[Finding]

    def counts(self):
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c
