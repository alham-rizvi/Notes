# 2. HTTP Security Headers & TLS/SSL Misconfig

**What it is:** missing/weak security headers and weak TLS configuration. Doesn't need any dynamic functionality \u2014 applies to every page on a static site.

### Test checklist
- [ ] HSTS present, `max-age` \u2265 31536000, `includeSubDomains`, ideally `preload`
- [ ] CSP present and not `unsafe-inline`/`unsafe-eval` heavy
- [ ] X-Frame-Options or CSP `frame-ancestors` set (clickjacking)
- [ ] X-Content-Type-Options: nosniff present
- [ ] Referrer-Policy set to something other than default `strict-origin-when-cross-origin` missing entirely
- [ ] Cookies (if any) have Secure, HttpOnly, SameSite=Lax/Strict
- [ ] TLS: no SSLv2/v3/TLS1.0/1.1, no weak ciphers (RC4, export ciphers), cert not expired, cert chain complete, no self-signed in prod
- [ ] HTTP\u2192HTTPS redirect enforced on every page, not just homepage
- [ ] Mixed content (HTTP resources loaded on an HTTPS page)
- [ ] HTTP TRACE/TRACK method enabled (XST attack vector)

### Linux (Kali)
```
curl -I https://target.com
nmap --script http-security-headers,ssl-enum-ciphers,ssl-cert,ssl-date -p 443 target.com
testssl.sh --quiet target.com          # full TLS audit: protocols, ciphers, cert, vulns (Heartbleed, POODLE, etc.)
sslscan target.com
# TRACE method check
curl -X TRACE https://target.com -v
# Mixed content: crawl and grep
katana -u https://target.com -silent | xargs -I{} curl -s {} | grep -oE 'http://[^"'\'' ]+' 
```

### Windows
```
(Invoke-WebRequest https://target.com -UseBasicParsing).Headers
curl.exe -X TRACE https://target.com -v
# TLS cert inspection
$req = [System.Net.HttpWebRequest]::Create("https://target.com")
$req.GetResponse() | Out-Null
$cert = $req.ServicePoint.Certificate
$cert | Format-List *
# OpenSSL via Git Bash (ships with Git for Windows):
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 | openssl x509 -noout -dates
```

**Impact framing:** missing HSTS/weak TLS = medium-high (MITM/downgrade); missing CSP/X-Frame-Options = medium (XSS/clickjacking enabler); cookie flags missing = low-medium depending on cookie sensitivity.

## Advanced / Deeper Checks

### Full TLS audit, not just presence/absence
```
# testssl.sh with everything on (slower, far more thorough than a quick -I check)
testssl.sh --full --severity LOW target.com
testssl.sh --vulnerable target.com          # checks Heartbleed, POODLE, BEAST, CRIME, FREAK, Logjam, ROBOT, etc. in one pass

# Qualys SSL Labs equivalent via API (gives an A-F grade with reasoning, useful for report evidence)
curl -s "https://api.ssllabs.com/api/v3/analyze?host=target.com&all=done" | jq
```

### CAA record check (often skipped \u2014 controls which CAs can even issue certs for the domain)
```
dig caa target.com                          # Kali
Resolve-DnsName target.com -Type CAA        # Windows
```
Missing CAA = not a vuln by itself, but worth noting as a hardening gap in the report.

### HSTS preload list check (confirms whether the browser enforces HTTPS even on first visit)
```
curl -s "https://hstspreload.org/api/v2/status?domain=target.com" | jq
```

### Certificate Transparency monitoring as an ongoing recon source
Every new cert issued for `*.target.com` shows up in CT logs in near real time \u2014 for a long engagement, re-running the crt.sh query periodically catches newly spun-up (and often under-tested) subdomains before the team even links to them.

### Request smuggling hints (worth a note even on an otherwise static site, if it sits behind a reverse proxy/CDN)
```
# Quick CL.TE / TE.CL discrepancy probe (needs a raw socket tool, not curl, for accurate Content-Length/Transfer-Encoding control)
# Kali: use Burp Suite's HTTP Request Smuggler extension, or smuggler.py
python3 smuggler.py -u https://target.com
```
```
# Windows: smuggler.py runs the same via python.exe; Burp Suite extension is identical cross-platform
```
Flag this as a lead for deeper manual testing rather than a confirmed finding \u2014 smuggling needs careful differential timing analysis to confirm safely.

**Resources:** testssl.sh docs, Qualys SSL Labs API docs, PortSwigger's HTTP Request Smuggling research and labs, hstspreload.org.
