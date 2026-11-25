"""Audit rules. Each rule adds Finding objects for one device or across devices."""
import ipaddress
from .models import Finding

WEAK_COMMUNITIES = {"public", "private", "cisco", "community"}


def _mask(value):
    """Mask a credential-like string for display in reports."""
    if not value:
        return "***"
    if len(value) <= 2:
        return "***"
    return value[0] + "***" + value[-1]


def check_device(dev):
    f = []
    add = lambda sev, cat, title, detail="", rec="": f.append(
        Finding(sev, cat, dev.hostname, title, detail, rec))

    # --- security ---
    if dev.enable_password_plain and not dev.enable_secret:
        add("critical", "security", "Enable password stored as plaintext/weak type-7",
            "'enable password' is used instead of 'enable secret'.",
            "Use 'enable secret <password>'.")
    if dev.enable_password_plain and dev.enable_secret and not dev.password_encryption:
        add("info", "security", "Legacy 'enable password' present alongside enable secret",
            "The fallback 'enable password' line is weak (plaintext or reversible type-7).",
            "Remove the 'enable password' line.")
    if dev.users_plain and not dev.password_encryption:
        add("warning", "security", "User passwords stored without encryption",
            "Users with 'password' (not 'secret'): " + ", ".join(dev.users_plain),
            "Use 'username <name> secret <pw>' and 'service password-encryption'.")
    if "telnet" in dev.vty_transport and "ssh" not in dev.vty_transport:
        add("critical", "security", "Remote access over Telnet only",
            "VTY lines accept Telnet; credentials cross the network unencrypted.",
            "Use 'transport input ssh' and configure an RSA key pair.")
    elif "telnet" in dev.vty_transport:
        add("warning", "security", "Telnet still allowed alongside SSH",
            "VTY lines allow both Telnet and SSH.",
            "Restrict with 'transport input ssh'.")
    if ("ssh" in dev.vty_transport) and not dev.has_ssh_version:
        add("info", "security", "SSH version not pinned",
            "No 'ip ssh version 2' found.", "Set 'ip ssh version 2'.")
    if dev.vty_transport and not dev.vty_has_password and not dev.vty_login_local:
        add("critical", "security", "VTY lines without authentication",
            "Remote-access lines have no password and no 'login local'.")
    for community, access in dev.snmp_communities:
        if community.lower() in WEAK_COMMUNITIES:
            add("critical", "security", f"Weak SNMP community string '{community}'",
                f"Access level: {access}.",
                "Use a long random community, read-only, with an ACL.")
        elif access == "RW":
            add("warning", "security",
                f"SNMP community '{_mask(community)}' is read-write",
                "Community value masked in this report.",
                "Prefer read-only unless write access is required.")

    # --- ACLs ---
    for name, entries in dev.acls.items():
        if name in dev.extended_acls:
            for e in entries:
                if "permit" in e and "any any" in e.replace("  ", " "):
                    add("critical", "acl", f"ACL '{name}' permits any-to-any",
                        f"Entry: {e}",
                        "Narrow the entry to required sources, destinations and ports.")
        refs = dev.acl_refs | {a for i in dev.interfaces
                               for a in (i.acls_in + i.acls_out)}
        if name not in refs:
            add("warning", "acl", f"ACL '{name}' defined but not applied",
                f"{len(entries)} entries.",
                "Apply it to an interface with 'ip access-group' or remove it.")

    # --- VLANs / interfaces ---
    assigned_vlans = {i.access_vlan for i in dev.interfaces if i.access_vlan}
    for vid in assigned_vlans:
        if dev.vlans and vid not in dev.vlans:
            add("warning", "vlan", f"Port assigned to undefined VLAN {vid}",
                "No 'vlan %d' definition found." % vid,
                "Create the VLAN or reassign the port.")
    for vid, vname in dev.vlans.items():
        if dev.vlans and vid not in assigned_vlans and vid != 1:
            add("info", "vlan", f"VLAN {vid} ({vname or 'unnamed'}) has no access ports",
                "", "Remove it or document why it is kept.")
    for iface in dev.interfaces:
        if not iface.description and not iface.shutdown \
                and not iface.name.startswith(("Vlan", "Loopback")):
            add("info", "hygiene", f"Interface {iface.name} has no description",
                "", "Add a 'description' for the connected device or purpose.")
        if iface.switchport_mode == "access" and not iface.access_vlan:
            add("info", "vlan",
                f"Access port {iface.name} has no explicit VLAN (defaults to VLAN 1)",
                "", "Assign an explicit VLAN if the port should not be in VLAN 1.")

    # --- routing ---
    for proto, cfg in dev.routing_protocols.items():
        networks = [l for l in cfg if l.startswith("network ")]
        if proto in ("ospf", "eigrp", "rip") and not networks:
            if proto == "ospf" and dev.ospf_on_interfaces:
                pass  # interface-level 'ip ospf ... area' is valid without networks
            else:
                add("warning", "routing",
                    f"{proto.upper()} enabled with no network statements",
                    "", "Add network statements or remove the process.")
        user_facing = [i for i in dev.interfaces
                       if i.ip_address and not i.shutdown
                       and not any(f"passive-interface {i.name}" == l for l in cfg)]
        if proto in ("ospf", "eigrp", "rip") and cfg and len(user_facing) > 2 \
                and not any(l.startswith("passive-interface") for l in cfg):
            add("info", "routing", f"No passive interfaces under {proto.upper()}",
                f"{len(user_facing)} active interfaces will send {proto.upper()} hellos.",
                "If any of these links need no adjacencies, consider "
                "'passive-interface default' plus no-passive on transit links.")
    return f


def check_fabric(devices):
    """Cross-device checks: duplicate IPs, hostname collisions."""
    f = []
    seen_ips = {}
    seen_hosts = {}
    for dev in devices:
        key = dev.hostname.lower()
        if key in seen_hosts:
            f.append(Finding("warning", "hygiene", dev.hostname,
                             "Duplicate hostname",
                             f"Also used by device loaded from {seen_hosts[key]}."))
        seen_hosts[key] = dev.source
        for iface in dev.interfaces:
            if iface.ip_address:
                if iface.ip_address in seen_ips:
                    other_dev, other_if = seen_ips[iface.ip_address]
                    f.append(Finding("critical", "routing", dev.hostname,
                                     f"Duplicate IP {iface.ip_address} on {iface.name}",
                                     f"Same address on {other_dev} {other_if}.",
                                     "Readdress one of the interfaces."))
                else:
                    seen_ips[iface.ip_address] = (dev.hostname, iface.name)

    # overlapping subnets that are not point-to-point links
    subnets = {}
    for dev in devices:
        for iface in dev.interfaces:
            if iface.ip_address and iface.subnet_mask:
                try:
                    net = ipaddress.ip_network(
                        f"{iface.ip_address}/{iface.subnet_mask}", strict=False)
                except ValueError:
                    continue
                subnets.setdefault(str(net), set()).add(dev.hostname)
    for net, hosts in subnets.items():
        if len(hosts) > 2:
            f.append(Finding("info", "routing", ", ".join(sorted(hosts)),
                             f"Shared subnet {net} spans {len(hosts)} devices"))
    return f


def run_audit(devices):
    findings = []
    for dev in devices:
        findings.extend(check_device(dev))
    findings.extend(check_fabric(devices))
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda x: (x.device, order.get(x.severity, 3), x.category))
    return findings
