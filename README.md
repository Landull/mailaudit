# mailaudit

A small, dependency-free command-line tool that checks a domain's email authentication: the records that decide whether someone can spoof email from it.

- **SPF**: missing or duplicate records, `+all` / `?all`, deprecated `ptr`, and the **10 DNS lookup limit** (follows includes)
- **DMARC**: policy strength, subdomain policy, `pct`, and whether reports are being collected
- **DKIM**: probes 30+ common selectors (Microsoft 365, Google, Proton, Fastmail, SendGrid...) and flags **1024-bit keys**
- **MX, MTA-STS and TLS-RPT** for the full picture
- DNS is resolved over HTTPS, so it works the same on Windows, macOS and Linux

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# Audit a domain
python mailaudit.py example.com

# Check a DKIM selector the domain uses that isn't in the built-in list
python mailaudit.py example.com -s mycorp2024

# Show the raw records
python mailaudit.py example.com -v

# A list of client domains, as JSON
python mailaudit.py -i domains.txt -o mail.json
```

### Example output

```
$ python mailaudit.py example.com
example.com
  [PASS] MX              2 record(s): mx1.example.com, mx2.example.com
  [PASS] SPF policy      Soft fail (~all); fine when DMARC is enforcing
  [PASS] SPF lookups     4 of 10 DNS lookups used
  [WARN] DMARC policy    p=none is monitoring only; nothing is blocked
  [WARN] DMARC reports   No rua= address; you won't see who is sending as you
  [WARN] DKIM selector1  RSA ~1024-bit key; rotate to 2048-bit
  [PASS] DKIM google     RSA ~2048-bit key
  [INFO] MTA-STS         Not published (optional; enforces TLS to your MX)
  [INFO] TLS-RPT         Not published (optional; reports TLS delivery failures)

[*] 4 pass, 3 warn, 0 fail
```

## Options

| Flag | Description |
|---|---|
| `-i, --input FILE` | Read domains from a file, one per line |
| `-s, --selector SELECTOR` | Extra DKIM selector to check (repeatable) |
| `--no-dkim` | Skip DKIM selector probing |
| `-f, --format` | Output format (`table` / `json`) |
| `-o, --output FILE` | Write JSON results to a file |
| `-v, --verbose` | Show raw DNS records |
| `--no-color` | Plain output without colors |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No failing checks |
| `1` | At least one check failed |
| `2` | Bad input, or DNS couldn't be resolved |

## Notes

DKIM selectors can't be listed from DNS, so a "no key found" warning only means none of the common selectors matched. Look at the `DKIM-Signature: s=` value in a real email header from the domain and pass it with `-s`.

Domains that don't send email at all should still publish `v=spf1 -all` and a DMARC `p=reject` record, otherwise they're easy to spoof.

Lookups go to Cloudflare's DNS-over-HTTPS service (falling back to Google's), so the domain names you check are visible to that resolver.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s auditkit.
