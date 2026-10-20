#!/usr/bin/env python3
"""
mailaudit - check a domain's email authentication (SPF, DKIM, DMARC).

Looks up MX, SPF, DMARC, common DKIM selectors, MTA-STS and TLS-RPT for
a domain and flags the misconfigurations that let attackers spoof it.
DNS is resolved over HTTPS (Cloudflare, falling back to Google), so it
works the same on Windows, macOS and Linux with no extra packages.

Standard library only. Python 3.8+.
"""

import argparse
import base64
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "1.0.0"

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"

RESOLVERS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
TYPES = {"A": 1, "MX": 15, "TXT": 16, "CNAME": 5}

# Selectors used by the big mail providers and sending services.
COMMON_SELECTORS = (
    "default", "dkim", "mail", "email", "k1", "k2", "k3", "s1", "s2",
    "selector1", "selector2",            # Microsoft 365
    "google", "20230601", "20221208", "20210112", "20161025",  # Google
    "protonmail", "protonmail2", "protonmail3",
    "fm1", "fm2", "fm3",                 # Fastmail
    "zoho", "zmail",
    "mxvault", "smtp", "mandrill", "mailjet", "sendgrid", "s1024", "s2048",
    "everlytickey1", "everlytickey2", "dk", "key1", "key2", "sig1",
)

SPF_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists", "redirect")


def ssl_context(verify=True):
    """Default TLS context. python.org builds for macOS ship without CA certificates,
    so when none are loaded there, borrow the system roots from the macOS keychain."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if sys.platform == "darwin" and not ctx.cert_store_stats().get("x509_ca"):
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=30).stdout
            if pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError, ValueError):
            pass
    return ctx


SSL_CTX = ssl_context()


class DNSError(Exception):
    pass


def doh_query(name, rtype, timeout=8):
    """Resolve name/rtype over DNS-over-HTTPS. Returns list of answer strings."""
    last = None
    for base in RESOLVERS:
        url = base + "?" + urllib.parse.urlencode({"name": name, "type": rtype})
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                data = json.load(resp)
        except (urllib.error.URLError, OSError, ValueError) as err:
            last = err
            continue
        if data.get("Status") not in (0, 3):  # NOERROR, NXDOMAIN
            last = DNSError(f"DNS status {data.get('Status')} for {name}")
            continue
        want = TYPES[rtype]
        return [a["data"] for a in data.get("Answer", []) if a.get("type") == want]
    raise DNSError(f"could not resolve {name} {rtype}: {last}")


def txt_join(data):
    """Turn a TXT answer like '"v=spf1 ..." "more"' into one string."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if not parts:
        return data.strip()
    return "".join(p.replace('\\"', '"') for p in parts)


class Auditor:
    def __init__(self, domain, resolve=doh_query):
        self.domain = domain.strip().strip(".").lower()
        self.resolve = resolve
        self.results = []

    def add(self, check, status, detail, value=None):
        self.results.append({"check": check, "status": status, "detail": detail, "value": value})

    def txt(self, name):
        return [txt_join(r) for r in self.resolve(name, "TXT")]

    # ---- MX ---------------------------------------------------------------
    def check_mx(self):
        mx = self.resolve(self.domain, "MX")
        hosts = sorted(mx, key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 99)
        if not hosts or hosts == ["0 ."]:
            self.add("MX", INFO, "No mail servers; domain doesn't receive email. "
                     "It should still publish 'v=spf1 -all' and DMARC p=reject.")
            return False
        names = ", ".join(h.split()[-1].rstrip(".") for h in hosts)
        self.add("MX", PASS, f"{len(hosts)} record(s): {names}")
        return True

    # ---- SPF --------------------------------------------------------------
    def count_spf_lookups(self, record, seen, depth=0):
        """Count DNS-querying mechanisms, following includes/redirects."""
        count = 0
        for term in record.split()[1:]:
            term = term.lstrip("+-~?").lower()
            mech = re.split(r"[:=/]", term, maxsplit=1)[0]
            if mech not in SPF_LOOKUP_MECHS:
                continue
            count += 1
            if mech in ("include", "redirect") and depth < 10:
                target = re.split(r"[:=]", term, maxsplit=1)[1] if re.search(r"[:=]", term) else ""
                if target and target not in seen:
                    seen.add(target)
                    try:
                        sub = [r for r in self.txt(target) if r.lower().startswith("v=spf1")]
                    except DNSError:
                        sub = []
                    if sub:
                        count += self.count_spf_lookups(sub[0], seen, depth + 1)
        return count

    def check_spf(self):
        records = [r for r in self.txt(self.domain) if r.lower().startswith("v=spf1")]
        if not records:
            self.add("SPF", FAIL, "No SPF record; anyone can send as this domain")
            return
        if len(records) > 1:
            self.add("SPF", FAIL, f"{len(records)} SPF records; receivers treat this as an error. Merge them.",
                     " | ".join(records))
            return
        rec = records[0]
        terms = rec.lower().split()
        all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
        redirect = any(t.startswith("redirect=") for t in terms)
        if all_term in ("-all",):
            self.add("SPF policy", PASS, "Hard fail (-all) for unlisted senders", rec)
        elif all_term == "~all":
            self.add("SPF policy", PASS, "Soft fail (~all); fine when DMARC is enforcing", rec)
        elif all_term == "?all":
            self.add("SPF policy", WARN, "Neutral (?all) gives no protection; use ~all or -all", rec)
        elif all_term in ("+all", "all"):
            self.add("SPF policy", FAIL, "+all authorizes every server on the internet", rec)
        elif redirect:
            self.add("SPF policy", INFO, "Policy comes from a redirect= target", rec)
        else:
            self.add("SPF policy", WARN, "No 'all' mechanism; unlisted senders default to neutral", rec)

        if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
            self.add("SPF ptr", WARN, "Uses the deprecated ptr mechanism (slow, unreliable)")

        lookups = self.count_spf_lookups(rec, {self.domain})
        if lookups > 10:
            self.add("SPF lookups", FAIL, f"{lookups} DNS lookups; over the limit of 10, so SPF will permerror")
        elif lookups >= 8:
            self.add("SPF lookups", WARN, f"{lookups} of 10 DNS lookups used; close to the limit")
        else:
            self.add("SPF lookups", PASS, f"{lookups} of 10 DNS lookups used")

    # ---- DMARC ------------------------------------------------------------
    def check_dmarc(self):
        records = [r for r in self.txt(f"_dmarc.{self.domain}") if r.lower().startswith("v=dmarc1")]
        if not records:
            self.add("DMARC", FAIL, "No DMARC record; spoofed mail isn't rejected and you get no reports")
            return
        if len(records) > 1:
            self.add("DMARC", FAIL, "Multiple DMARC records; receivers will ignore them", " | ".join(records))
            return
        rec = records[0]
        tags = {}
        for part in rec.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        policy = tags.get("p", "").lower()
        if policy == "reject":
            self.add("DMARC policy", PASS, "p=reject; spoofed mail is refused", rec)
        elif policy == "quarantine":
            self.add("DMARC policy", PASS, "p=quarantine; spoofed mail goes to spam", rec)
        elif policy == "none":
            self.add("DMARC policy", WARN, "p=none is monitoring only; nothing is blocked", rec)
        else:
            self.add("DMARC policy", FAIL, f"Invalid or missing p= tag ({policy or 'none set'})", rec)

        sp = tags.get("sp", "").lower()
        if sp == "none" and policy in ("reject", "quarantine"):
            self.add("DMARC subdomains", WARN, "sp=none leaves subdomains spoofable")

        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100
        if pct < 100 and policy in ("reject", "quarantine"):
            self.add("DMARC pct", WARN, f"pct={pct}; policy only applies to {pct}% of failing mail")

        if "rua" in tags:
            self.add("DMARC reports", PASS, f"Aggregate reports go to {tags['rua']}")
        else:
            self.add("DMARC reports", WARN, "No rua= address; you won't see who is sending as you")

    # ---- DKIM -------------------------------------------------------------
    def check_dkim(self, extra_selectors=()):
        selectors = list(dict.fromkeys(list(extra_selectors) + list(COMMON_SELECTORS)))
        found = []
        for sel in selectors:
            name = f"{sel}._domainkey.{self.domain}"
            try:
                recs = self.txt(name)
            except DNSError:
                continue
            recs = [r for r in recs if "p=" in r.lower() or r.lower().startswith("v=dkim1")]
            if recs:
                found.append((sel, recs[0]))
        if not found:
            self.add("DKIM", WARN, f"No key found on {len(selectors)} common selectors "
                     "(it may use a custom one; pass it with -s)")
            return
        for sel, rec in found:
            status, detail = dkim_key_strength(rec)
            self.add(f"DKIM {sel}", status, detail, rec[:90] + ("..." if len(rec) > 90 else ""))

    # ---- Transport --------------------------------------------------------
    def check_transport(self):
        sts = [r for r in self.txt(f"_mta-sts.{self.domain}") if r.lower().startswith("v=stsv1")]
        self.add("MTA-STS", PASS if sts else INFO,
                 "Published; senders must use TLS" if sts else "Not published (optional; enforces TLS to your MX)")
        rpt = [r for r in self.txt(f"_smtp._tls.{self.domain}") if r.lower().startswith("v=tlsrptv1")]
        self.add("TLS-RPT", PASS if rpt else INFO,
                 "Published" if rpt else "Not published (optional; reports TLS delivery failures)")

    def run(self, selectors=(), skip_dkim=False):
        receives = self.check_mx()
        self.check_spf()
        self.check_dmarc()
        if not skip_dkim and (receives or selectors):
            self.check_dkim(selectors)
        if receives:
            self.check_transport()
        return {
            "domain": self.domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "results": self.results,
        }


def dkim_key_strength(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    key = tags.get("p", "")
    if not key:
        return WARN, "Key revoked (empty p=)"
    ktype = tags.get("k", "rsa").lower()
    if ktype == "ed25519":
        return PASS, "Ed25519 key"
    try:
        der = base64.b64decode(key + "=" * (-len(key) % 4))
    except ValueError:
        return WARN, "Key isn't valid base64"
    # SubjectPublicKeyInfo size tracks the modulus closely enough to classify
    bits = 1024 if len(der) < 200 else 2048 if len(der) < 400 else 4096
    if bits < 2048:
        return WARN, "RSA ~1024-bit key; rotate to 2048-bit"
    return PASS, f"RSA ~{bits}-bit key"


def color(status, enabled):
    if not enabled:
        return status
    return f"\033[{ {PASS: '32', WARN: '33', FAIL: '31', INFO: '36'}[status] }m{status}\033[0m"


def print_report(report, use_color, verbose):
    print(report["domain"])
    width = max(len(r["check"]) for r in report["results"])
    for r in report["results"]:
        print(f"  [{color(r['status'], use_color)}] {r['check']:<{width}}  {r['detail']}")
        if verbose and r["value"]:
            print(f"         {'':<{width}}  {r['value']}")
    counts = {s: sum(1 for r in report["results"] if r["status"] == s) for s in (PASS, WARN, FAIL)}
    print(f"\n[*] {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="mailaudit",
                                description="Check a domain's SPF, DKIM and DMARC setup.")
    p.add_argument("domains", nargs="*", help="domain(s) to audit")
    p.add_argument("-i", "--input", metavar="FILE", help="read domains from a file, one per line")
    p.add_argument("-s", "--selector", action="append", default=[],
                   help="extra DKIM selector to check (repeatable)")
    p.add_argument("--no-dkim", action="store_true", help="skip DKIM selector probing")
    p.add_argument("-f", "--format", choices=("table", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write JSON results to a file")
    p.add_argument("-v", "--verbose", action="store_true", help="show raw DNS records")
    p.add_argument("--no-color", action="store_true", help="plain output without colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    domains = list(args.domains)
    if args.input:
        try:
            with open(args.input, encoding="utf-8") as fh:
                domains += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as err:
            print(f"[!] {err}", file=sys.stderr)
            return 2
    if not domains:
        print("[!] Give at least one domain or use --input.", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    reports = []
    for i, d in enumerate(domains):
        d = re.sub(r"^\w+://", "", d).split("/")[0]
        try:
            report = Auditor(d).run(args.selector, args.no_dkim)
        except DNSError as err:
            print(f"[!] {d}: {err}", file=sys.stderr)
            continue
        reports.append(report)
        if args.format == "table":
            if i:
                print()
            print_report(report, use_color, args.verbose)

    if args.format == "json" or args.output:
        data = json.dumps(reports if len(reports) != 1 else reports[0], indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
            print(f"[*] Wrote {args.output}", file=sys.stderr)
        else:
            print(data)

    if not reports:
        return 2
    return 1 if any(r["status"] == FAIL for rep in reports for r in rep["results"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
