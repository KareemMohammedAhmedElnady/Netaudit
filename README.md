# NetAudit

Audit, monitor and automate router and switch configurations from the command
line. Built for network engineers and students who need a free, scriptable
alternative to commercial network auditing suites.

First release: Cisco IOS-style devices. The parser is structured so other
vendors can be added.

## What it does

- **Audit (offline)** - point it at saved config files and get a report of
  findings with severity and a suggested fix:
  - security: plaintext enable/user passwords, Telnet-only remote access,
    weak or read-write SNMP communities, VTY lines without authentication
  - ACLs: `permit ip any any`, ACLs defined but never applied
  - VLANs: ports on undefined VLANs, VLANs with no ports, access ports with
    no VLAN
  - routing: protocols with no network statements, missing passive
    interfaces, duplicate IPs across devices
- **Reports** - colored text on the terminal, plus a self-contained HTML
  report you can open or share.
- **Monitor (live)** - collect running-configs over SSH, keep a baseline,
  and alert when a config changes or a device stops answering.
- **Automation (live)** - push a JSON change plan to devices, dry-run first.

## Scope and limits (read this first)

**Status: prototype / first release.**

NetAudit checks exactly this, for Cisco IOS-style configs only:

- security: plaintext/legacy enable and user passwords, Telnet-only or
  Telnet+SSH remote access, VTY lines with no authentication, SSH version
  not pinned, well-known or read-write SNMP communities
- ACLs: `permit ip any any` in extended ACLs, ACLs never referenced by an
  interface, VTY access-class, SNMP community or NAT statement
- VLANs: access ports on undefined VLANs, defined VLANs with no access
  ports, access ports with no explicit VLAN (defaults to VLAN 1)
- routing: routing processes with no network statements (interface-level
  `ip ospf ... area` is recognized and not flagged), no passive-interface
  usage, duplicate IP addresses across audited devices
- hygiene: active interfaces without descriptions

It does NOT check: live interface up/down state, CPU/memory, logs,
protocols beyond the above, non-Cisco vendors, or anything requiring
privileged show commands other than the running-config. Monitoring detects
reachability loss and running-config changes only - not performance issues.

## Security notes

- Passwords are read from environment variables; the inventory file never
  stores them.
- Live connections require strict SSH host key checking: devices must be in
  `~/.ssh/known_hosts`, and the tool refuses to connect on a netmiko version
  that cannot enforce this (it tells you to upgrade instead).
- Alert output and automation output are redacted so common credential
  lines (passwords, secrets, SNMP communities, keys) are not logged.
- Baseline config FILES still hold full device configs, including secrets.
  Protect that directory; the .gitignore keeps it out of version control.
- Automation has NO rollback. Dry-run first (`--apply` is what commits).
  A failure mid-plan can leave a device partially configured; the tool
  reports which devices applied and which failed, and you must review a
  failed device manually.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

21 tests cover the parser, audit rules, false-positive guards, credential
redaction and the fail-closed SSH policy. No devices or dependencies
required.

## Quick start (no devices needed)

```bash
python3 -m netaudit audit --configs samples/lab1 --out report.html
```

This audits the included sample lab (2 routers, 1 switch) and writes
`report.html`. The core audit uses only the Python standard library - no
installation required.

## Working with live devices

Live features need [netmiko](https://github.com/ktbyers/netmiko):

```bash
pip install netmiko
export NETAUDIT_PASSWORD='your-device-password'
```

Copy `samples/inventory.example.json` to `inventory.json` and edit the hosts.
Passwords come from environment variables (or a `password` key), never hard-
coded in the repo.

```bash
# Pull running-configs into a directory, then audit them
python3 -m netaudit collect --inventory inventory.json --out configs/
python3 -m netaudit audit --configs configs --out report.html

# Monitor: first run creates a baseline, then alerts on changes/loss
python3 -m netaudit monitor --inventory inventory.json --baseline baseline/ --interval 300
python3 -m netaudit monitor --inventory inventory.json --baseline baseline/ --once

# Automation: dry-run prints exactly what would be sent
python3 -m netaudit automate --inventory inventory.json --plan samples/plan.example.json
python3 -m netaudit automate --inventory inventory.json --plan myplan.json --apply
```

Alerts are printed and appended to `alerts.log`. The monitor sends
notifications to the terminal/log today; email or webhook alerts are a
planned addition.

## Project layout

```
netaudit/
  parser.py    config text -> Device objects
  checks.py    audit rules (per-device and cross-device)
  report.py    text + HTML report rendering
  live.py      SSH collection, monitoring, automation (netmiko)
  cli.py       command-line interface
samples/
  lab1/        sample lab configs (try the audit on these)
  inventory.example.json
  plan.example.json
```

## Contributing

Issues and pull requests are welcome. Good first contributions: new audit
rules in `checks.py`, parsers for other vendors, more tests. Please run the
test suite before submitting.

## License

MIT - see LICENSE.
