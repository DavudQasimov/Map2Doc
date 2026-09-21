#!/usr/bin/env python3
"""
Map2Doc (mdc.py)
================
A wrapper around netexec (nxc) / crackmapexec, smbclient and smbmap.
Runs SMB/AD target enumeration with the selected tools and appends a
report (.txt or .md) after EACH enumeration step, saved in the
directory the script was launched from.

Author: built for etozryx
"""

import argparse
import shutil
import subprocess
import sys
import os
import textwrap
from datetime import datetime

LINE_WIDTH = 88  # max width for wrapped output lines in reports

BANNER = r"""
   __  __             ____  ____             
  |  \/  | __ _ _ __ |___ \|  _ \  ___   ___ 
  | |\/| |/ _` | '_ \  __) | | | |/ _ \ / __|
  | |  | | (_| | |_) |/ __/| |_| | (_) | (__ 
  |_|  |_|\__,_| .__/|_____|____/ \___/ \___|
               |_|
        Universal tool for AD/SMB enumeration
        Author: Davud Qasimov
"""

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def which_first(*names):
    """Return the first binary found in PATH from the given list."""
    for n in names:
        path = shutil.which(n)
        if path:
            return n
    return None


def run_cmd(cmd_list):
    """Run an external command, return (returncode, stdout+stderr)."""
    try:
        proc = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
        )
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        return 127, f"[!] Binary not found: {cmd_list[0]}"
    except subprocess.TimeoutExpired:
        return 124, "[!] Command timed out (300s)"
    except Exception as e:
        return 1, f"[!] Execution error: {e}"


def wrap_output(text, width=LINE_WIDTH):
    """Wrap long lines in tool output so reports stay readable, without
    breaking words/paths in the middle when avoidable."""
    wrapped_lines = []
    for line in text.rstrip("\n").split("\n"):
        if not line.strip():
            wrapped_lines.append("")
            continue
        if len(line) <= width:
            wrapped_lines.append(line)
        else:
            wrapped_lines.extend(
                textwrap.wrap(
                    line,
                    width=width,
                    subsequent_indent="    ",
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
    return "\n".join(wrapped_lines)


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    def __init__(self, fmt, target, outdir=None):
        self.fmt = fmt  # "txt" or "md"
        self.target = target
        self.outdir = outdir or os.getcwd()
        self.section_count = 0
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        fname = f"map2doc_report_{safe_target}_{ts}.{fmt}"
        self.path = os.path.join(self.outdir, fname)
        self._init_file()

    def _init_file(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.path, "w", encoding="utf-8") as f:
            if self.fmt == "md":
                f.write(f"# Map2Doc Report\n\n")
                f.write("| Field  | Value |\n")
                f.write("|--------|-------|\n")
                f.write(f"| Target | `{self.target}` |\n")
                f.write(f"| Date   | {now} |\n\n")
                f.write("---\n\n")
            else:
                f.write("=" * LINE_WIDTH + "\n")
                f.write("MAP2DOC REPORT".center(LINE_WIDTH) + "\n")
                f.write("=" * LINE_WIDTH + "\n")
                f.write(f"Target : {self.target}\n")
                f.write(f"Date   : {now}\n")
                f.write("=" * LINE_WIDTH + "\n\n")

    def append_section(self, title, tool, cmd, returncode, output):
        self.section_count += 1
        n = self.section_count
        clean_output = wrap_output(output.strip()) if output.strip() else "(no output)"
        status = "OK" if returncode == 0 else f"FAILED ({returncode})"

        with open(self.path, "a", encoding="utf-8") as f:
            if self.fmt == "md":
                f.write(f"## {n}. {title}\n\n")
                f.write(f"| | |\n|---|---|\n")
                f.write(f"| **Tool** | `{tool}` |\n")
                f.write(f"| **Command** | `{' '.join(cmd)}` |\n")
                f.write(f"| **Status** | {status} |\n\n")
                f.write("```text\n")
                f.write(clean_output + "\n")
                f.write("```\n\n")
                f.write("---\n\n")
            else:
                header = f" [{n}] {title} "
                f.write(header.center(LINE_WIDTH, "-") + "\n")
                f.write(f"Tool    : {tool}\n")
                f.write(f"Command : {' '.join(cmd)}\n")
                f.write(f"Status  : {status}\n")
                f.write("-" * LINE_WIDTH + "\n")
                f.write(clean_output + "\n")
                f.write("=" * LINE_WIDTH + "\n\n")

        print(f"[+] [{n}] {title} -> report updated ({status})")


# ---------------------------------------------------------------------------
# Enumeration modules (thin wrappers around the real binaries)
# ---------------------------------------------------------------------------

def enum_netexec(target, user, password, reporter, extra_modules=None):
    """Basic SMB enumeration via netexec (or crackmapexec as fallback)."""
    nxc_bin = which_first("nxc", "netexec", "crackmapexec", "cme")
    if not nxc_bin:
        print("[!] netexec/crackmapexec not found in PATH. Skipping module.")
        return

    base_cmd = [nxc_bin, "smb", target]
    if user is not None:
        base_cmd += ["-u", user]
    if password is not None:
        base_cmd += ["-p", password]

    # 1. Basic passive scan (banner/domain/signing)
    rc, out = run_cmd(base_cmd)
    reporter.append_section("NetExec - Basic Host Information", nxc_bin, base_cmd, rc, out)

    # Trigger authenticated/null-session modules whenever credentials were
    # explicitly provided (including empty string for null session/guest),
    # not just when both are non-empty strings.
    if user is not None and password is not None:
        # 2. List shares
        shares_cmd = base_cmd + ["--shares"]
        rc, out = run_cmd(shares_cmd)
        reporter.append_section("NetExec - SMB Share Listing", nxc_bin, shares_cmd, rc, out)

        # 3. Domain users (RID-brute/LDAP if available)
        users_cmd = base_cmd + ["--users"]
        rc, out = run_cmd(users_cmd)
        reporter.append_section("NetExec - User Enumeration", nxc_bin, users_cmd, rc, out)

        # 4. Extra modules via flag (e.g. --sessions, --loggedon-users,
        #    --pass-pol). Supports optional values: "rid-brute=10000" runs
        #    "--rid-brute 10000"; plain "rid-brute" runs "--rid-brute" alone.
        for mod in (extra_modules or []):
            if "=" in mod:
                mod_name, mod_value = mod.split("=", 1)
                mod_cmd = base_cmd + [f"--{mod_name}", mod_value]
                label = mod_name
            else:
                mod_cmd = base_cmd + [f"--{mod}"]
                label = mod
            rc, out = run_cmd(mod_cmd)
            reporter.append_section(f"NetExec - Module {label}", nxc_bin, mod_cmd, rc, out)


def enum_smbclient(target, user, password, reporter):
    """List shares via smbclient -L (anonymous or with credentials)."""
    if not shutil.which("smbclient"):
        print("[!] smbclient not found in PATH. Skipping module.")
        return

    cmd = ["smbclient", "-L", f"//{target}/", "-N"] if not user else \
          ["smbclient", "-L", f"//{target}/", "-U", f"{user}%{password or ''}"]

    rc, out = run_cmd(cmd)
    reporter.append_section("smbclient - Share Listing (-L)", "smbclient", cmd, rc, out)


def enum_smbmap(target, user, password, reporter):
    """Share access permissions via smbmap."""
    if not shutil.which("smbmap"):
        print("[!] smbmap not found in PATH. Skipping module.")
        return

    cmd = ["smbmap", "-H", target]
    if user:
        cmd += ["-u", user, "-p", password or ""]

    rc, out = run_cmd(cmd)
    reporter.append_section("smbmap - Share Access Permissions", "smbmap", cmd, rc, out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="mdc.py",
        description="Map2Doc - merge netexec/smbclient/smbmap enumeration + auto-report (.txt/.md)",
    )
    p.add_argument("target", help="Target IP or hostname (e.g. 10.10.10.10 or dc01.domain.local)")
    p.add_argument("-u", "--user", help="Username", default=None)
    p.add_argument("-p", "--password", help="Password", default=None)
    p.add_argument(
        "-f", "--format",
        choices=["txt", "md"],
        default="md",
        help="Report format: txt or md (default: md)",
    )
    p.add_argument(
        "--modules",
        nargs="*",
        default=[],
        help="Extra netexec modules without '--' (e.g. sessions pass-pol "
             "loggedon-users). Use name=value for modules taking an "
             "argument, e.g. rid-brute=10000",
    )
    p.add_argument(
        "--only",
        nargs="*",
        choices=["netexec", "smbclient", "smbmap"],
        default=None,
        help="Run only the specified tools (default: all three)",
    )
    return p


def main():
    print(BANNER)
    args = build_parser().parse_args()

    tools_to_run = args.only or ["netexec", "smbclient", "smbmap"]
    reporter = Reporter(fmt=args.format, target=args.target)

    print("-" * 60)
    print(f" Target  : {args.target}")
    print(f" Report  : {reporter.path}")
    print(f" Tools   : {', '.join(tools_to_run)}")
    print("-" * 60 + "\n")

    if "netexec" in tools_to_run:
        enum_netexec(args.target, args.user, args.password, reporter, args.modules)

    if "smbclient" in tools_to_run:
        enum_smbclient(args.target, args.user, args.password, reporter)

    if "smbmap" in tools_to_run:
        enum_smbmap(args.target, args.user, args.password, reporter)

    print()
    print("-" * 60)
    print(f" Done. Final report: {reporter.path}")
    print("-" * 60)


if __name__ == "__main__":
    if os.geteuid() == 0:
        print("[!] Warning: running as root. Continuing...")
    main()
