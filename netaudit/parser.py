"""Cisco IOS-style configuration parser (text in, Device out)."""
import re
from .models import Device, Interface


def _section_lines(lines, start_idx):
    """Yield indented body lines following a section header."""
    body = []
    for line in lines[start_idx + 1:]:
        if line.startswith((" ", "\t", "!")):
            if line.strip() and line.strip() != "!":
                body.append(line.strip())
        else:
            break
    return body


def parse_config(text, source=""):
    dev = Device(hostname="unknown", source=source, raw=text)
    lines = text.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("hostname "):
            dev.hostname = stripped.split(None, 1)[1]

        elif stripped == "service password-encryption":
            dev.password_encryption = True

        elif stripped.startswith("enable secret"):
            dev.enable_secret = True

        elif re.match(r"^enable password\b", stripped):
            dev.enable_password_plain = True

        elif stripped.startswith("username "):
            # username admin password ... (vs 'secret')
            parts = stripped.split()
            if "password" in parts:
                dev.users_plain.append(parts[1])

        elif stripped.startswith("vlan "):
            m = re.match(r"^vlan (\d+)$", stripped)
            if m:
                vid = int(m.group(1))
                name = ""
                for b in _section_lines(lines, i):
                    if b.startswith("name "):
                        name = b.split(None, 1)[1]
                dev.vlans[vid] = name

        elif stripped.startswith("interface "):
            name = stripped.split(None, 1)[1]
            iface = Interface(name=name)
            for b in _section_lines(lines, i):
                if b.startswith("description "):
                    iface.description = b.split(None, 1)[1]
                elif b.startswith("ip address "):
                    p = b.split()
                    if len(p) >= 4 and p[2] != "dhcp":
                        iface.ip_address, iface.subnet_mask = p[2], p[3]
                elif b == "shutdown":
                    iface.shutdown = True
                elif b.startswith("switchport mode "):
                    iface.switchport_mode = b.split()[-1]
                elif b.startswith("switchport access vlan "):
                    iface.access_vlan = int(b.split()[-1])
                elif re.match(r"^ip ospf \d+ area ", b):
                    dev.ospf_on_interfaces = True
                elif b.startswith("ip access-group "):
                    p = b.split()
                    if len(p) >= 4:
                        (iface.acls_in if p[3] == "in" else iface.acls_out).append(p[2])
            dev.interfaces.append(iface)

        elif stripped.startswith("ip access-list "):
            # ip access-list standard|extended NAME
            p = stripped.split(None, 3)
            if len(p) == 4:
                kind, name = p[2], p[3]
                entries = _section_lines(lines, i)
                dev.acls[name] = entries
                if kind == "extended":
                    dev.extended_acls.add(name)

        elif re.match(r"^access-list \d+", stripped):
            # legacy numbered ACL, one line per entry
            p = stripped.split(None, 2)
            name = p[1]
            entry = p[2] if len(p) > 2 else ""
            dev.acls.setdefault(name, []).append(entry)
            if int(name) >= 100:
                dev.extended_acls.add(name)

        elif stripped.startswith("snmp-server community "):
            p = stripped.split()
            community = p[2]
            access = "RW" if "RW" in [x.upper() for x in p[3:]] else "RO"
            dev.snmp_communities.append((community, access))
            for extra in p[3:]:
                if extra.upper() not in ("RO", "RW"):
                    dev.acl_refs.add(extra)

        elif stripped.startswith("line vty "):
            for b in _section_lines(lines, i):
                if b.startswith("transport input "):
                    for t in b.split()[2:]:
                        dev.vty_transport.add(t)
                elif b.startswith("password "):
                    dev.vty_has_password = True
                elif b == "login local":
                    dev.vty_login_local = True
                elif b.startswith("access-class "):
                    parts = b.split()
                    if len(parts) >= 2:
                        dev.acl_refs.add(parts[1])

        elif stripped.startswith("ip ssh version"):
            dev.has_ssh_version = True

        elif stripped.startswith("ip nat ") and " list " in stripped:
            dev.acl_refs.add(stripped.split(" list ", 1)[1].split()[0])

        elif re.match(r"^router (ospf|eigrp|bgp|rip)\b", stripped):
            proto = stripped.split()[1]
            dev.routing_protocols[proto] = _section_lines(lines, i)

        i += 1

    return dev


def parse_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_config(fh.read(), source=str(path))
