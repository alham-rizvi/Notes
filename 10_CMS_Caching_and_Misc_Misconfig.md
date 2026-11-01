# 10. CMS, Caching & Misc Misconfig

## CMS-Specific Checks (if whatweb/wappalyzer identified one)
```
# WordPress
wpscan --url https://target.com --enumerate vp,vt,u    # vulnerable plugins/themes, users
curl https://target.com/wp-json/wp/v2/users              # often leaks usernames even unauthenticated

# Joomla
joomscan -u https://target.com

# Drupal
droopescan scan drupal -u https://target.com
```
Windows: all three are Python-based, run natively with `python <tool>.py ...` the same flags.

## Caching / CDN Issues
- [ ] Web cache deception: append `/nonexistent.css` to a sensitive dynamic path and see if the response gets cached and served to others
- [ ] Cache poisoning via unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`) \u2014 see Headers file
- [ ] Stale/expired SSL cert being served from CDN edge vs origin

```
# Kali
curl -s -D - "https://target.com/account/settings/nonexistent.js" -o /dev/null | grep -i "x-cache\|cache-control"

# Windows
(Invoke-WebRequest "https://target.com/account/settings/nonexistent.js" -UseBasicParsing).Headers | Select X-Cache,Cache-Control
```

## Rate Limiting / Brute-Force Protection
Even on a static+contact-form site, check if the contact form / newsletter signup can be spammed (no CAPTCHA, no rate limit) \u2014 enables mail-relay abuse or DoS of the mail queue.
```
# Kali \u2014 fire N requests and see if any get blocked/throttled
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/contact -d "email=test$i@test.com"; done

# Windows
1..50 | ForEach-Object { (Invoke-WebRequest -Uri https://target.com/contact -Method Post -Body @{email="test$_@test.com"} -UseBasicParsing).StatusCode }
```

## Email Security (SPF / DKIM / DMARC)
Already partly covered in Subdomain Takeover file \u2014 full check here:
```
# Kali
dig txt target.com | grep spf
dig txt default._domainkey.target.com     # DKIM selector names vary, try common ones: default, google, selector1
dig txt _dmarc.target.com

# Windows
Resolve-DnsName target.com -Type TXT
Resolve-DnsName _dmarc.target.com -Type TXT
```
Weak SPF (`~all` instead of `-all`, or missing) + no DMARC = domain can be spoofed for phishing.

## Misc Low-Hanging Items
- [ ] Favicon/default install pages left behind (reveals server software defaults)
- [ ] Exposed `phpinfo()` page
- [ ] Autocomplete not disabled on any sensitive form field
- [ ] Verbose `Allow:` header via `OPTIONS` request revealing unused/dangerous HTTP methods
```
curl -X OPTIONS https://target.com -v          # Kali
(Invoke-WebRequest -Uri https://target.com -Method Options -UseBasicParsing).Headers  # Windows
```

**Impact framing:** CMS user enumeration = low-medium; cache deception/poisoning = medium-high depending on what gets cached; missing rate limiting on contact form = low (abuse potential); weak SPF/DMARC = medium (phishing/spoofing enabler).

## Advanced / Deeper Coverage

### WPScan with an API token (free tier) \u2014 turns version fingerprinting into actual CVE matches
```
wpscan --url https://target.com --api-token YOUR_TOKEN --enumerate vp,vt,u,cb,dbe
# vp/vt = vulnerable plugins/themes matched against WPVulnDB, cb = config backups, dbe = db exports
wpscan --url https://target.com --enumerate ap,at     # all plugins/themes (slower, more complete than vp/vt alone which only flags known-vulnerable ones)
```

### GraphQL-specific checks (if any API behind the static front-end turns out to be GraphQL)
```
# Introspection often left enabled in prod \u2014 dumps the entire schema including "hidden" fields/mutations
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}'
# Automated:
graphql-cop -t https://target.com/graphql
clairvoyance -o schema.json https://target.com/graphql   # reconstructs schema even with introspection DISABLED, via field-name brute force
```

### HTTP/2 downgrade smuggling (newer request-smuggling variant relevant behind modern CDNs)
```
# Most CDNs translate HTTP/2 from the client to HTTP/1.1 to the origin \u2014 desync bugs live in that translation layer
# Burp Suite's HTTP/2 support + the "HTTP Request Smuggler" extension automate detection; manual testing needs raw h2 frame control, not curl
```

### Cache deception \u2014 a more systematic test than the single curl example earlier
```
# Kali \u2014 try multiple static-looking extensions appended to dynamic/sensitive paths
for ext in .css .js .jpg .png .ico; do
  curl -s -D - "https://target.com/account/profile$ext" -o /dev/null | grep -i "x-cache\|cache-control\|age:"
done
# If cached (X-Cache: HIT, Age > 0) and it still returned the real account page content, the response is now served to anyone hitting that same path
```

### Subresource Integrity (SRI) gaps on third-party scripts
```
# Any <script src="https://cdn..."> without integrity="sha384-..." means a compromised CDN silently serves malicious JS to every visitor
grep -oE '<script[^>]+src="https?://[^"]+"[^>]*>' downloaded_page.html | grep -v integrity
```

### Rate limiting bypass angles (worth checking before concluding "no rate limit")
```
# Try rotating these headers \u2014 some rate limiters key off them instead of the real source IP
curl -H "X-Forwarded-For: 1.2.3.$RANDOM" -X POST https://target.com/contact ...
curl -H "X-Real-IP: 1.2.3.$RANDOM" -X POST https://target.com/contact ...
# Case/encoding variation on the endpoint path itself can also reset counters keyed by exact path string:
curl -X POST https://target.com/Contact ...
curl -X POST "https://target.com/contact/" ...
```

**Resources:** WPScan + WPVulnDB, `graphql-cop` and `clairvoyance` for GraphQL-specific testing, PortSwigger HTTP Request Smuggling research (including HTTP/2 desync variants), PayloadsAllTheThings Web Cache Deception and Rate Limit Bypass sections.

---

## A note on methodology, not just payloads
The difference between CTF-quality testing and job-ready testing isn't a bigger payload list \u2014 it's process: fingerprint the stack and WAF *before* picking payloads, test one flaw class deliberately at a time instead of spraying everything, confirm impact with a real PoC (not just "the header looks wrong"), and always have an out-of-band confirmation path (Collaborator/interactsh) ready for blind cases. Every "Advanced" section across these files is built around that same loop: fingerprint -> narrow the hypothesis -> targeted bypass -> confirm impact -> document with exact reproduction steps.
