"""
PersiScan v0.4 — Linux Persistence & Suspicious Startup Scanner
Professional-style CLI tool for detecting autostart / persistence mechanisms on Kali/Debian-based systems.

Features:
- Colored output (green=low, yellow=moderate, red=high/alert)
- Summary & verbose modes
- JSON export
- Basic remediation hints

Usage:
  sudo persiscan               # default summary view
  sudo persiscan --verbose     # full detailed report
  sudo persiscan --json out.json
  sudo persiscan --remove 7
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
from termcolor import colored

# ────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────

TOOL_NAME = "PersiScan"
VERSION   = "0.4"

KNOWN_GOOD_PATHS = [
    Path('/etc/xdg/autostart'),
    Path('/etc/cron.d'),
    Path('/etc/cron.hourly'), Path('/etc/cron.daily'),
    Path('/etc/cron.weekly'), Path('/etc/cron.monthly'),
    Path('/usr/lib'), Path('/usr/sbin'), Path('/usr/bin'),
    Path('/lib/systemd/system'), Path('/usr/libexec'),
    Path('/lib/systemd/system/debug-shell.service'),
]

HIGH_RISK_PATHS = [
    Path('/tmp'), Path('/var/tmp'), Path('/dev/shm'),
    Path.home() / 'Downloads', Path.home() / '.cache',
]

HIGH_RISK_EXTS = {'.sh', '.py', '.pl', '.rb', '.bat', '.vbs', '.js', '.exe'}

SUSPICIOUS_KWS = [
    'backdoor', 'persistence', 'rootkit', 'inject', 'malware',
    'c2', 'reverse shell', 'bind shell', 'nc -e', 'nc -l',
    'socat', 'curl http', 'wget http', 'bash -i', 'python -c',
    'powershell', 'msfvenom', 'empire', 'covenant'
]

CRON_IGNORE_PREFIXES = [
    'set -', 'exit ', 'return ', 'fi', 'else', 'then', 'if [',
    'PATH=', 'SHELL=', 'MAILTO=', ': ${', 'true', 'false'
]

# ────────────────────────────────────────────────

class PersiScan:
    def __init__(self, verbose=False, json_output=None):
        self.verbose = verbose
        self.json_output = json_output
        self.inventory = []
        self.next_id = 0

    def log(self, msg, color='white'):
        if self.verbose:
            print(colored(f"[DEBUG] {msg}", color), file=sys.stderr)

    def enumerate(self):
        if os.geteuid() != 0:
            print(colored("Warning: Running without root privileges — some system locations skipped", 'yellow'))

        self._enum_autostart()
        self._enum_cron()
        self._enum_systemd()
        self._enum_rc_local()
        self._enum_profile_hooks()
        self._enum_ld_preload()

        self.log(f"Collected {len(self.inventory)} persistence entries", 'cyan')

    def _add_item(self, name, path, category, enabled=True, extra=None):
        item = {
            'id': self.next_id,
            'name': name,
            'path': path,
            'category': category,
            'enabled': enabled,
            'score': 0,
            'reasons': [],
            'hash': self._get_hash(path) if Path(path).is_file() else None,
            'extra': extra or {}
        }
        self.inventory.append(item)
        self.next_id += 1

    def _get_hash(self, path):
        try:
            with open(path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None

    # ─── Enumeration methods ────────────────────────────────────────

    def _enum_autostart(self):
        for directory in [Path.home() / '.config/autostart', Path('/etc/xdg/autostart')]:
            if directory.exists():
                for file in directory.glob('*.desktop'):
                    self._add_item(file.stem, str(file), 'autostart')

    def _enum_cron(self):
        # User crontab
        try:
            out = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL, text=True)
            jobs = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith('#')]
            if jobs:
                self._add_item('user-crontab', 'crontab -l', 'cron', extra={'jobs': jobs})
        except:
            pass

        # System locations — one entry per file
        locations = [
            Path('/etc/crontab'),
            Path('/etc/cron.d'),
            Path('/etc/cron.hourly'), Path('/etc/cron.daily'),
            Path('/etc/cron.weekly'), Path('/etc/cron.monthly')
        ]

        for loc in locations:
            if not loc.exists():
                continue

            if loc.is_file():
                try:
                    content = loc.read_text()
                    jobs = [l.strip() for l in content.splitlines()
                            if l.strip() and not l.startswith('#') and not any(l.startswith(p) for p in CRON_IGNORE_PREFIXES)]
                    if jobs:
                        self._add_item(f"cron-{loc.name}", str(loc), 'cron', extra={'jobs': jobs})
                except Exception as e:
                    self.log(f"Cannot read {loc}: {e}", 'red')
            elif loc.is_dir():
                for file in loc.iterdir():
                    if file.is_file():
                        try:
                            content = file.read_text()
                            jobs = [l.strip() for l in content.splitlines()
                                    if l.strip() and not l.startswith('#') and not any(l.startswith(p) for p in CRON_IGNORE_PREFIXES)]
                            if jobs:
                                self._add_item(f"cron-{loc.name}-{file.name}", str(file), 'cron', extra={'jobs': jobs})
                        except Exception as e:
                            self.log(f"Cannot read {file}: {e}", 'red')

    def _enum_systemd(self):
        for scope, flag in [('user', '--user'), ('system', '--system')]:
            try:
                cmd = ['systemctl', flag, 'list-unit-files', '--type=service,timer']
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    if '.service' in line or '.timer' in line:
                        name = line.split()[0]
                        enabled = 'enabled' in line.lower()
                        self._add_item(name, f"systemd-{scope}:{name}", f'systemd-{scope}', enabled)
            except:
                pass

    def _enum_rc_local(self):
        p = Path('/etc/rc.local')
        if p.is_file():
            self._add_item('rc.local', str(p), 'rc-local')

    def _enum_profile_hooks(self):
        for p in [Path.home()/'.bashrc', Path.home()/'.profile', Path('/etc/profile')]:
            if p.is_file():
                try:
                    txt = p.read_text().lower()
                    if any(kw in txt for kw in ['/tmp/', 'curl ', 'wget ', 'bash -i', 'nc ', 'socat ']):
                        self._add_item(f"hook-{p.name}", str(p), 'profile-hook')
                except:
                    pass

    def _enum_ld_preload(self):
        p = Path('/etc/ld.so.preload')
        if p.is_file():
            self._add_item('ld.so.preload', str(p), 'ld-preload')

    # ─── Scoring ────────────────────────────────────────────────────

    def score(self):
        now = datetime.now()
        for item in self.inventory:
            score = 0
            reasons = []
            p = Path(item['path'])

            # Trusted locations → discount
            if any(str(p).startswith(str(g)) for g in KNOWN_GOOD_PATHS):
                score -= 5
                reasons.append("trusted-location")

            # Suspicious locations → boost
            if any(str(p).startswith(str(h.expanduser())) for h in HIGH_RISK_PATHS):
                score += 6
                reasons.append("suspicious-location")

            # Risky file extension
            if p.suffix.lower() in HIGH_RISK_EXTS:
                score += 4
                reasons.append("risky-extension")

            # Suspicious keywords
            text = (
                item['name'].lower() + " " +
                str(p).lower() + " " +
                " ".join(item.get('extra', {}).get('jobs', []))
            )
            hits = [kw for kw in SUSPICIOUS_KWS if kw in text]
            if hits:
                score += min(8, len(hits) * 3)
                reasons.append(f"suspicious: {', '.join(hits)}")

            # Recently modified (last 14 days)
            try:
                mtime = datetime.fromtimestamp(p.stat().st_mtime)
                if mtime > now - timedelta(days=14):
                    score += 3
                    reasons.append("recently-modified")
            except:
                pass

            item['score'] = max(0, min(10, score))
            item['reasons'] = list(set(reasons))  # remove duplicates

    # ─── Reporting ──────────────────────────────────────────────────

    def report(self):
        high = [i for i in self.inventory if i['score'] >= 7]
        mod  = [i for i in self.inventory if 4 <= i['score'] <= 6]
        low  = [i for i in self.inventory if i['score'] < 4]

        print(colored(f"\n{TOOL_NAME} v{VERSION} Report", 'cyan', attrs=['bold']))
        print(colored(f"{'═' * 60}", 'cyan'))
        print(f"Scan time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total items: {len(self.inventory)}")
        print(f"High risk  : {colored(len(high), 'red', attrs=['bold'])}")
        print(f"Moderate   : {colored(len(mod),  'yellow')}")
        print(f"Low risk   : {colored(len(low),   'green')}")
        print(colored(f"{'═' * 60}", 'cyan'))

        def print_section(title, items, color):
            if not items:
                print(colored(f"{title}: None", color))
                return
            print(colored(f"{title} ({len(items)}):", color, attrs=['bold']))
            for it in sorted(items, key=lambda x: -x['score']):
                score_str = f"{it['score']}/10"
                if it['score'] >= 7:
                    score_str = colored(score_str, 'red', attrs=['bold'])
                elif it['score'] >= 4:
                    score_str = colored(score_str, 'yellow')
                else:
                    score_str = colored(score_str, 'green')

                print(f"  [{it['id']:3d}]  {score_str}  {it['name']}  ({it['category']})")
                print(f"      → {it['path']}")
                if it['reasons']:
                    print(f"      reasons: {', '.join(it['reasons'])}")
                if it.get('extra', {}).get('jobs'):
                    print("      jobs/commands:")
                    for job in it['extra']['jobs'][:3]:
                        print(f"        {job}")
                    if len(it['extra']['jobs']) > 3:
                        print(f"        ... +{len(it['extra']['jobs'])-3} more")
                print()

        if self.verbose:
            print_section("Low risk (0–3)", low, 'green')
        print_section("Moderate risk (4–6)", mod, 'yellow')
        print_section("High risk (7–10)", high, 'red')

        if not high and not mod:
            print(colored("\n→ No suspicious persistence mechanisms detected.", 'green', attrs=['bold']))
        if high:
            print(colored("\nALERT — Potential persistence mechanisms found!", 'red', attrs=['bold']))
            print("Recommended next steps:")
            print("  • Review items above carefully")
            print("  • Use --remove <ID> to attempt disable/remove")
            print("  • Cross-check with lynis, rkhunter, chkrootkit")

        if self.json_output:
            data = {
                'tool': TOOL_NAME,
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'total_items': len(self.inventory),
                'high': len(high),
                'moderate': len(mod),
                'low': len(low),
                'entries': self.inventory
            }
            with open(self.json_output, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            print(colored(f"\nJSON report saved → {self.json_output}", 'cyan'))

    def run(self):
        self.enumerate()
        self.score()
        self.report()

def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — Advanced Linux persistence scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--verbose', '-v', action='store_true',
                        help="show low-risk items and more details")
    parser.add_argument('--json', '-j', metavar='FILE',
                        help="export full JSON report")
    parser.add_argument('--remove', type=int, metavar='ID',
                        help="attempt to disable/remove entry by ID")
    args = parser.parse_args()

    scanner = PersiScan(verbose=args.verbose, json_output=args.json)

    if args.remove is not None:
        scanner.enumerate()
        scanner.score()
        # Placeholder — real removal logic can be added later
        print(f"Remove request for ID {args.remove} — not yet implemented.")
    else:
        scanner.run()

if __name__ == "__main__":
    main()
