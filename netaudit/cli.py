"""Command-line interface: netaudit audit|collect|baseline|monitor|automate."""
import argparse
import glob
import json
import os
import sys

from . import live
from .checks import run_audit
from .models import AuditReport
from .parser import parse_file
from .report import render_html, render_text


def _load_configs(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.cfg"))
                       + glob.glob(os.path.join(path, "*.txt")))
    else:
        files = [path]
    if not files:
        sys.exit(f"No config files found at {path}")
    return [parse_file(f) for f in files]


def cmd_audit(args):
    devices = _load_configs(args.configs)
    report = AuditReport(devices=devices, findings=run_audit(devices))
    text = render_text(report)
    print(text)
    out = args.out
    if out:
        if out.endswith(".html"):
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(render_html(report))
        else:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
        print(f"Report written to {out}")
    counts = report.counts()
    return 1 if counts["critical"] else 0


def cmd_collect(args):
    saved = live.collect_configs(args.inventory, args.out)
    print("Collected:")
    for p in saved:
        print("  " + p)
    return 0


def cmd_monitor(args):
    live.monitor(args.inventory, args.baseline, interval=args.interval,
                 alert_log=args.alert_log, once=args.once)
    return 0


def cmd_automate(args):
    live.automate(args.inventory, args.plan, dry_run=not args.apply)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="netaudit",
        description="Audit, monitor and automate router/switch configurations.")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Audit config files (offline, no devices needed)")
    a.add_argument("--configs", required=True,
                   help="Config file or directory of .cfg/.txt files")
    a.add_argument("--out", help="Write report to file (.txt or .html)")
    a.set_defaults(func=cmd_audit)

    c = sub.add_parser("collect", help="Pull running-configs over SSH into a directory")
    c.add_argument("--inventory", required=True, help="Inventory JSON file")
    c.add_argument("--out", required=True, help="Output directory")
    c.set_defaults(func=cmd_collect)

    m = sub.add_parser("monitor", help="Watch devices; alert on config changes/loss")
    m.add_argument("--inventory", required=True)
    m.add_argument("--baseline", required=True,
                   help="Directory with baseline configs (created on first run)")
    m.add_argument("--interval", type=int, default=300, help="Seconds between checks")
    m.add_argument("--alert-log", default="alerts.log")
    m.add_argument("--once", action="store_true", help="Single check, then exit")
    m.set_defaults(func=cmd_monitor)

    t = sub.add_parser("automate", help="Push a JSON change plan over SSH")
    t.add_argument("--inventory", required=True)
    t.add_argument("--plan", required=True, help="Plan JSON file")
    t.add_argument("--apply", action="store_true",
                   help="Actually apply (default is dry-run printout)")
    t.set_defaults(func=cmd_automate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
