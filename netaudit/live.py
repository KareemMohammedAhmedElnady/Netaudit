"""Live-device collection, monitoring and automation.

SSH access uses netmiko (optional dependency: pip install netmiko).
Inventory is JSON: [{"name": "R1", "host": "192.0.2.1", "device_type":
"cisco_ios", "username": "admin", "password_env": "NETAUDIT_PASSWORD"}]
Passwords are read from environment variables, never stored in the file.

Security notes:
- When the installed netmiko supports it, strict host key checking is
  enabled (devices must be in ~/.ssh/known_hosts).
- Alert output and device output are redacted so common credential lines
  (passwords, secrets, SNMP communities, keys) are not written to logs.
- Baseline config FILES still contain full configs, including secrets.
  Protect the baseline directory and never commit it (see .gitignore).
"""
import difflib
import inspect
import json
import os
import re
import subprocess
import time

_SENSITIVE_KEYWORDS = ("password", "secret", "community", "private-key")


def redact(text):
    """Mask credential values on sensitive lines of config or device output."""
    out = []
    for line in text.splitlines():
        if "-----BEGIN" in line or "-----END" in line:
            out.append("<redacted key material>")
            continue
        redacted_line = line
        for kw in _SENSITIVE_KEYWORDS:
            redacted_line = re.sub(
                r"(?i)(" + re.escape(kw) + r")(\s+\S+)+",
                lambda m: m.group(1) + " <redacted>", redacted_line)
        out.append(redacted_line)
    return "\n".join(out)


def _load_inventory(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _connect(entry):
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise SystemExit("netmiko is required for live devices: pip install netmiko")
    password = None
    if entry.get("password_env"):
        password = os.environ.get(entry["password_env"])
    password = entry.get("password", password)
    kwargs = dict(device_type=entry["device_type"],
                  host=entry["host"],
                  username=entry["username"],
                  password=password)
    # Fail closed: require strict SSH host key checking support. Connecting
    # without verifying host identity would silently trust unknown hosts.
    if "strict_host_key_checking" not in inspect.signature(ConnectHandler).parameters:
        raise SystemExit(
            "This netmiko version cannot enforce SSH host key verification. "
            "Upgrade with: pip install -U netmiko "
            "and add devices to ~/.ssh/known_hosts. Refusing to connect.")
    kwargs["strict_host_key_checking"] = True
    return ConnectHandler(**kwargs)


def collect_configs(inventory_path, out_dir):
    """SSH to each device, save running-config into out_dir/<name>.cfg.

    One failing device does not abort the rest; failures are printed.
    Returns (saved_paths, failed_names).
    """
    os.makedirs(out_dir, exist_ok=True)
    saved, failed = [], []
    for entry in _load_inventory(inventory_path):
        try:
            conn = _connect(entry)
            try:
                cfg = conn.send_command("show running-config")
            finally:
                conn.disconnect()
        except Exception as exc:
            print(f"FAILED {entry['name']} ({entry['host']}): {exc}")
            failed.append(entry["name"])
            continue
        path = os.path.join(out_dir, entry["name"] + ".cfg")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(cfg)
        saved.append(path)
    return saved, failed


def _ping(host, count=2, timeout=2):
    cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout * count + 2
                              ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def monitor(inventory_path, baseline_dir, interval=300, alert_log="alerts.log",
            once=False):
    """Re-collect configs and diff against baseline; alert on changes/loss.

    Each cycle: ping every host, pull running-config, diff with the baseline
    copy. Differences (with credential lines redacted) and unreachable hosts
    are printed and appended to alert_log. Run with once=True for one check.
    """
    inventory = _load_inventory(inventory_path)
    os.makedirs(baseline_dir, exist_ok=True)
    while True:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        for entry in inventory:
            name, host = entry["name"], entry["host"]
            if not _ping(host):
                _alert(alert_log, f"{stamp} UNREACHABLE {name} ({host})")
                continue
            try:
                conn = _connect(entry)
                try:
                    cfg = conn.send_command("show running-config")
                finally:
                    conn.disconnect()
            except Exception as exc:  # auth/ssh failure: report, keep watching
                _alert(alert_log, f"{stamp} COLLECT-FAILED {name}: {exc}")
                continue
            base_path = os.path.join(baseline_dir, name + ".cfg")
            if not os.path.exists(base_path):
                with open(base_path, "w", encoding="utf-8") as fh:
                    fh.write(cfg)
                _alert(alert_log, f"{stamp} BASELINE-CREATED {name}")
                continue
            with open(base_path, "r", encoding="utf-8") as fh:
                old = fh.read().splitlines()
            if old != cfg.splitlines():
                diff = redact("\n".join(difflib.unified_diff(
                    old, cfg.splitlines(), "baseline", "current", lineterm="")))
                _alert(alert_log, f"{stamp} CONFIG-CHANGED {name}\n{diff}")
            else:
                print(f"{stamp} OK {name}")
        if once:
            return
        time.sleep(interval)


def _alert(log_path, message):
    print(message)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(message + "\n\n")


def automate(inventory_path, plan_path, dry_run=True):
    """Push a change plan. Plan JSON: [{"name": "R1", "commands": [...]}].

    dry_run=True only prints what would be sent; pass dry_run=False to apply.
    A failing device is reported and skipped; remaining devices still run.
    There is NO rollback: a failure mid-plan can leave a device partially
    configured - review it manually. Returns the number of failed devices.
    """
    inventory = {e["name"]: e for e in _load_inventory(inventory_path)}
    with open(plan_path, "r", encoding="utf-8") as fh:
        plan = json.load(fh)
    applied, failed = [], []
    for step in plan:
        name = step["name"]
        entry = inventory.get(name)
        if not entry:
            print(f"SKIP {name}: not in inventory")
            failed.append(name)
            continue
        if dry_run:
            print(f"DRY-RUN {name} ({entry['host']}):")
            for cmd in step["commands"]:
                print(f"    {cmd}")
            continue
        try:
            conn = _connect(entry)
            try:
                output = conn.send_config_set(step["commands"])
                conn.save_config()
            finally:
                conn.disconnect()
        except Exception as exc:
            print(f"FAILED {name}: {exc}")
            print(f"       Commands may be partially applied on {name}; "
                  "review the device manually.")
            failed.append(name)
            continue
        applied.append(name)
        print(f"APPLIED {name}:\n{redact(output)}")
    if not dry_run:
        print(f"Summary: {len(applied)} applied, {len(failed)} failed/skipped.")
    return len(failed)
