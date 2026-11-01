# Static Website Pentest Cheatsheet \u2014 Recon & Enumeration
Windows + Kali Linux commands, no-auth static site scope

Scope assumption: no login/auth, mostly static pages. Focus is recon, info disclosure, misconfig, and low-hanging fruit \u2014 plus checks for any dynamic bits (forms, search, contact, JS-driven features) that sneak into otherwise static sites.

## 1. Recon & Subdomain Enumeration

**Kali/Linux**
```
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com
assetfinder --subs-only target.com
crt.sh: curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
sublist3r -d target.com
dnsx -l subs.txt -resp
httpx -l subs.txt -title -status-code -tech-detect -o alive.txt
```

**Windows (PowerShell / native)**
```
Resolve-DnsName target.com -Type ANY
Resolve-DnsName -Name www.target.com -Server 8.8.8.8
nslookup -type=ANY target.com
Test-NetConnection target.com -Port 443
# crt.sh works the same via Invoke-RestMethod:
Invoke-RestMethod "https://crt.sh/?q=%25.target.com&output=json" | Select-Object -ExpandProperty name_value | Sort-Object -Unique
```
Easiest path on Windows: run the Kali tools (subfinder, httpx, amass) through WSL2 \u2014 install once (`wsl --install`), then just use the Linux commands above inside it. Saves rewriting every tool.

## 2. DNS / WHOIS / Network Info

**Kali**
```
whois target.com
dig target.com ANY
dig target.com MX
dig target.com TXT
dig axfr target.com @ns1.target.com   # zone transfer check
traceroute target.com
```

**Windows**
```
nslookup -type=TXT target.com
nslookup -type=MX target.com
tracert target.com
Get-WhoIs target.com   # if module installed, else use web whois
```

## 3. Technology Fingerprinting

**Kali**
```
whatweb target.com
wappalyzer (browser extension, cross-platform)
nmap -sV -p- target.com
nmap --script http-headers,http-title,http-server-header target.com
curl -I target.com
```

**Windows**
```
(Invoke-WebRequest -Uri https://target.com -UseBasicParsing).Headers
curl.exe -I target.com     # ships with modern Windows
```
Always check response headers for `Server`, `X-Powered-By`, `X-Generator` \u2014 quick framework/CMS giveaways.

## 4. Low-Hanging Fruit \u2014 Sensitive Files & Exposure

Manually try (works from any browser or curl/Invoke-WebRequest):
```
/robots.txt
/sitemap.xml
/.git/config          -> if exposed: git-dumper / GitTools to pull the whole repo
/.env
/.DS_Store
/backup.zip, /backup.sql, /db.sql, /site.zip
/wp-config.php.bak, /config.php.bak
/.well-known/security.txt
/admin, /administrator, /phpmyadmin, /wp-admin
/.htaccess, /web.config
/crossdomain.xml, /clientaccesspolicy.xml
/README.md, /CHANGELOG.md (version fingerprinting)
```

**Kali automation**
```
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,bak,zip,env,sql,git
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
dirsearch -u https://target.com
if .git exposed: git-dumper https://target.com/.git/ ./git-dump
```

**Windows**
```
# gobuster/ffuf run fine natively if Go-built binaries are downloaded, or via WSL
# Quick manual check loop in PowerShell:
$paths = "robots.txt",".git/config",".env","backup.zip","web.config"
foreach ($p in $paths) {
  $r = Invoke-WebRequest -Uri "https://target.com/$p" -UseBasicParsing -ErrorAction SilentlyContinue
  if ($r.StatusCode -eq 200) { "$p -> FOUND" }
}
```

## 5. Directory / Content Discovery

**Kali**
```
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403
waybackurls target.com > wayback.txt     # historical URLs, often reveal removed/forgotten pages
gau target.com                            # GetAllUrls, same idea, more sources
photon -u https://target.com -o output   # crawler + endpoint/secret finder
```

**Windows**
Same binaries (gobuster, ffuf, gau, waybackurls are all Go tools \u2014 single .exe, run natively on Windows too, no WSL required):
```
gobuster.exe dir -u https://target.com -w wordlist.txt
```

## 6. HTTP Headers & Security Misconfig Checks

Check for presence/absence of:
```
Strict-Transport-Security
Content-Security-Policy
X-Frame-Options (clickjacking)
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
Set-Cookie flags: Secure, HttpOnly, SameSite
```

**Kali**
```
curl -I https://target.com
nmap --script http-security-headers target.com
testssl.sh target.com          # full TLS/SSL config audit
sslscan target.com
```

**Windows**
```
(Invoke-WebRequest https://target.com).Headers
# TLS check:
openssl s_client -connect target.com:443   # openssl ships with Git Bash on Windows
```

Clickjacking quick manual test: build a simple HTML page with an `<iframe src="https://target.com">` and see if it loads \u2014 if no X-Frame-Options/CSP frame-ancestors, it's a finding.

## 7. CORS Misconfiguration

```
curl -H "Origin: https://evil.com" -I https://target.com/api/endpoint
# Look for: Access-Control-Allow-Origin: https://evil.com (reflected) or *
#           combined with Access-Control-Allow-Credentials: true -> high severity
```
Windows equivalent via Invoke-WebRequest with custom header works the same way.

## 8. Input-Based Testing (even "static" sites often have these)

Check any search box, contact form, comment field, URL parameters:
```
XSS probes: "><script>alert(1)</script>   |  '"><img src=x onerror=alert(1)>
SQLi probes: '  | " | ' OR '1'='1  | sleep-based: ' OR SLEEP(5)--
Open redirect: ?redirect=https://evil.com, ?next=, ?url=
SSRF (if any "fetch URL"/image-proxy feature): point param to http://169.254.169.254/
Host header injection: curl -H "Host: evil.com" https://target.com
```
Use Burp Suite or OWASP ZAP (both cross-platform, same GUI on Windows and Kali) to intercept and fuzz these systematically rather than doing it all by hand.

## 9. JS File Analysis (common source of leaks on static sites)

```
# Pull every JS file and grep for secrets/endpoints
cat alive.txt | hakrawler
subjs -i alive.txt | tee js_files.txt
for f in $(cat js_files.txt); do curl -s $f; done | grep -Ei "api[_-]?key|secret|token|aws_|firebase"
# or use a dedicated tool:
secretfinder -i https://target.com/app.js -o cli
linkfinder -i https://target.com/app.js -o cli
```
Windows: same tools (Python-based) run fine via `pip install` + normal `python` invocation, no WSL needed for these.

## 10. Scanners to Run for Broad Coverage

```
nikto -h https://target.com
nuclei -u https://target.com -t cves/ -t exposures/ -t misconfiguration/
wpscan --url https://target.com   # if WordPress
```
nuclei is the highest-value single tool here for a static-site low-hanging-fruit sweep \u2014 covers exposed panels, default creds, known CVEs, misconfig templates in one pass. Runs identically on Windows if Go is installed, or via WSL.

## 11. Screenshotting Everything (quick visual triage across many subdomains)

```
eyewitness --web -f alive.txt -d screenshots/
aquatone -scan alive.txt
```

## 12. Report Checklist (map findings to this before writing up)

- [ ] Subdomain takeover candidates (dangling CNAMEs)
- [ ] Missing/weak security headers
- [ ] TLS/SSL misconfig (weak ciphers, expired cert, no HSTS)
- [ ] Exposed .git / .env / backups / config files
- [ ] Directory listing enabled
- [ ] Clickjacking (no frame protection)
- [ ] CORS misconfig
- [ ] Information disclosure in JS files (keys, internal endpoints)
- [ ] Outdated CMS/plugin versions (via whatweb/wappalyzer)
- [ ] Open redirect / host header injection
- [ ] Cookie flags missing (if any cookies set at all)
- [ ] robots.txt/sitemap.xml revealing hidden paths
- [ ] Wayback/gau URLs pointing to removed-but-still-live endpoints

## Notes
- For a true no-auth static site, the highest-yield categories are usually: exposed files/.git, missing headers, subdomain takeover, and JS-leaked secrets \u2014 prioritize those first before deep manual input testing.
- Keep all raw tool output saved per-subdomain (e.g. `recon/<subdomain>/`) so nothing has to be re-run when writing the report.

## 13. Full Headers Cheatsheet (Request + Response)

**Dump everything in one shot**
```
# Kali
curl -sv https://target.com 2>&1 | grep -E "^[<>]"
curl -s -D - https://target.com -o /dev/null
httpx -u https://target.com -irh          # dump all response headers

# Windows
(Invoke-WebRequest -Uri https://target.com -UseBasicParsing).Headers | Format-Table
curl.exe -sv https://target.com
```

**Response headers to check \u2014 security**
```
Strict-Transport-Security      (missing/short max-age = downgrade risk)
Content-Security-Policy        (missing/weak = XSS/clickjacking risk)
X-Frame-Options                (missing = clickjacking)
X-Content-Type-Options         (missing = MIME sniffing)
Referrer-Policy                (missing/leaky = referrer leakage)
Permissions-Policy              (missing = broad feature access)
Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy / Cross-Origin-Resource-Policy
Access-Control-Allow-Origin / -Credentials (CORS, see dedicated file)
Set-Cookie: check Secure, HttpOnly, SameSite on every cookie
```

**Response headers to check \u2014 info disclosure**
```
Server                 (web server + version)
X-Powered-By           (language/framework + version)
X-AspNet-Version / X-AspNetMvc-Version
X-Generator            (CMS)
X-Drupal-Cache, X-Varnish, X-Cache  (caching layer fingerprint)
Via                    (proxy chain disclosure)
ETag                   (sometimes leaks inode/file info on old Apache)
```

**Caching headers (test for cache poisoning / sensitive data caching)**
```
Cache-Control, Expires, Pragma, Vary, Age, X-Cache, Surrogate-Control
# Test cache poisoning by sending unkeyed headers and checking if they get cached:
curl -H "X-Forwarded-Host: evil.com" -I https://target.com
```

**Request headers worth fuzzing/sending**
```
X-Forwarded-For, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL   (access-control bypass, SSRF, routing confusion)
Host   (host header injection / password reset poisoning if any dynamic feature exists)
Origin (CORS testing)
User-Agent / Referer (sometimes logged/reflected unsanitized \u2014 check for stored XSS in logs/analytics dashboards)
Range   (test for partial-content handling issues on static file servers)
```

**Quick full-header diff across subdomains (spot the odd one out)**
```
# Kali
for s in $(cat alive.txt); do echo "== $s =="; curl -s -D - -o /dev/null $s; done > all_headers.txt

# Windows
Get-Content alive.txt | ForEach-Object { "== $_ =="; (Invoke-WebRequest -Uri $_ -UseBasicParsing).Headers }
```

## 14. Advanced Recon \u2014 Beyond the Basics

This is where real engagements separate from CTF-style recon. Most low-hanging fruit on a "hardened" static site is found here, not in the obvious wordlists.

### Favicon hashing (finds related infra, forgotten subdomains, and origin IPs hiding behind a CDN)
```
# Kali \u2014 get the mmh3 hash of the favicon, then pivot via Shodan/Censys
curl -s https://target.com/favicon.ico -o favicon.ico
python3 -c "import mmh3, base64, codecs; data=open('favicon.ico','rb').read(); print(mmh3.hash(base64.encodebytes(data)))"
# Search engines (web UI or API):
#   Shodan:  http.favicon.hash:<hash>
#   Censys:  services.http.response.favicons.hashes:<hash>
shodan search "http.favicon.hash:<hash>"
```
```
# Windows \u2014 same script, Python runs natively
python decode_favicon.py
```
This is the single best technique for finding the **real origin IP behind a CDN/WAF** \u2014 if the origin serves the same favicon and isn't behind Cloudflare, you can bypass the WAF entirely by hitting the IP directly with the right `Host` header.

### ASN / BGP / IP-range recon (finds forgotten infra outside the CDN)
```
# Kali
whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+"
amass intel -org "Target Inc"            # pulls ASNs/netblocks from org name
amass intel -asn 12345
# bgp.he.net (web) \u2014 manually pivot from ASN to netblocks to reverse-DNS
masscan -p80,443 $(cat netblocks.txt) --rate 1000 -oL masscan_out.txt
```
```
# Windows \u2014 masscan/amass are Go/C binaries with native Windows builds; whois via web or Get-WhoIs module
```

### Certificate Transparency \u2014 beyond the basic crt.sh call
```
# Pull issuer + SAN entries, not just names, and catch recently issued certs (fresh infra, often under-tested)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[] | "\(.name_value) \(.not_before)"' | sort -u
# ctfr / certspotter for alternate CT sources
python3 ctfr.py -d target.com -o certs.txt
```

### GitHub / GitLab dorking (developer mistakes leak more than any scanner finds)
```
# Kali \u2014 gh CLI + GitDorker
gh search code --query="org:targetorg api_key"
gh search code --query="target.com password"
python3 GitDorker.py -tf target_dorks.txt -q target.com -d
trufflehog github --org=targetorg
gitleaks detect --source=./cloned-repo
```
Key dork patterns: `"target.com" password`, `"target.com" api_key`, `"target.com" BEGIN RSA PRIVATE KEY`, `filename:.env target.com`, `filename:id_rsa`.
```
# Windows \u2014 gh.exe, trufflehog.exe, gitleaks.exe all run natively; Python scripts via normal python.exe
```

### Wayback Machine / Common Crawl for historical attack surface
```
waybackurls target.com | tee wayback_all.txt
gau --subs target.com
cat wayback_all.txt | grep -E "\.(json|xml|bak|old|zip|sql|conf|config)$"   # old leftover files that were once live
# Common Crawl index (huge additional dataset gau/waybackurls sometimes miss):
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.target.com&output=json" | jq -r .url
```

### WAF / CDN fingerprinting (tells you what you're up against before testing)
```
wafw00f https://target.com
nmap -p443 --script http-waf-detect,http-waf-fingerprint target.com
```
```
# Windows: wafw00f is Python, runs natively
python wafw00f.py https://target.com
```

### Full automated recon pipelines (what real pentesters actually run, not one tool at a time)
```
# BBOT \u2014 modern all-in-one recon framework, often outperforms running subfinder/amass/httpx separately
bbot -t target.com -f subdomain-enum -rf passive
# ReconFTW / ProjectDiscovery's recon chain are the other common choices
reconftw.sh -d target.com -r
```

**Resources this is drawn from:** Intigriti's Shodan/Censys and "overlooked recon" research blogs, bug-bounty recon playbooks (BBOT, GitDorker, favicon hashing methodology), and the standard subfinder/amass/httpx/ProjectDiscovery toolchain documentation.
