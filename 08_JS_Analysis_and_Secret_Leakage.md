# 8. JS File Analysis & Secret Leakage

**What it is:** static sites ship all their logic as client-side JS bundles \u2014 these frequently contain hardcoded API keys, internal endpoint paths, old admin routes, and comments meant for developers only.

### Test checklist
- [ ] Every `.js` file referenced by the site, including source maps (`.js.map`) if exposed \u2014 these often unminify straight back to original source with comments
- [ ] Hardcoded API keys: AWS, Firebase, Stripe, Google Maps, Mailgun, Algolia, Sentry DSNs
- [ ] Internal/hidden API endpoints not linked from the UI
- [ ] Commented-out code revealing old features, test accounts, debug flags
- [ ] Hardcoded internal hostnames/IPs
- [ ] Third-party script integrity \u2014 any `<script src="http://...">` (not https) or missing Subresource Integrity (SRI) on CDN scripts

### Linux (Kali)
```
# Collect every JS URL referenced by the site
katana -u https://target.com -jc -silent | grep "\.js$" > js_files.txt
subjs -i alive.txt >> js_files.txt
sort -u js_files.txt -o js_files.txt

# Scan each for secrets/endpoints
while read js; do
  echo "== $js =="
  curl -s "$js" | grep -Eio "(api[_-]?key|secret|token|password|aws_access|firebase)[\"']?\s*[:=]\s*[\"'][a-z0-9_\-]{10,}[\"']"
done < js_files.txt

# Dedicated tools
secretfinder -i https://target.com/app.js -o cli
linkfinder -i https://target.com/app.js -o cli -d          # -d follows & deminifies
trufflehog filesystem ./downloaded_js/

# Check for exposed source maps
for js in $(cat js_files.txt); do curl -s -o /dev/null -w "%{http_code} $js.map\n" "$js.map"; done
```

### Windows
```
# secretfinder/linkfinder/trufflehog are Python/Go \u2014 run natively:
python SecretFinder.py -i https://target.com/app.js -o cli
trufflehog.exe filesystem .\downloaded_js\

# Manual grep equivalent (PowerShell)
Get-Content js_files.txt | ForEach-Object {
  $content = (Invoke-WebRequest -Uri $_ -UseBasicParsing).Content
  if ($content -match "api[_-]?key|secret|token|aws_access") { "$_  -> possible secret" }
}
```

**Impact framing:** live/working API key or credential found = critical to high depending on scope of access; internal endpoint disclosure = medium (expands attack surface); dev comments/debug flags = low-informational.

## Advanced / Deeper Coverage

### Reconstructing original source from minified JS (makes secret-hunting and endpoint-hunting far more effective)
```
# If source maps (.js.map) are exposed, you can rebuild the ENTIRE original file structure with comments
npx source-map-explorer app.js app.js.map            # visualizes what's in the bundle
node -e "require('source-map').SourceMapConsumer..." # or use a dedicated unpacker:
npx un-source-map app.js.map -o ./restored-src/
```
If no `.js.map` is exposed, run the bundle through a beautifier/deobfuscator before grepping \u2014 minified code hides secrets in single-letter variable names that regex can miss:
```
js-beautify app.min.js > app.beautified.js
```

### Turning discovered endpoints into a real attack surface with API-aware fuzzing
```
# kiterunner understands API route patterns (path params, versioning) far better than gobuster/ffuf for JS-derived endpoints
kr scan https://target.com -w routes-large.kite -x 20
# Feed it the endpoints you extracted from JS as a wordlist seed too:
kr brute https://target.com -w extracted_endpoints.txt
```

### Regex patterns worth adding beyond the basics (catches more key formats)
```
AWS:        AKIA[0-9A-Z]{16}
Google API: AIza[0-9A-Za-z\-_]{35}
Slack:      xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,34}
Stripe:     sk_live_[0-9a-zA-Z]{24}
JWT:        eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+          # decode at jwt.io or jwt_tool, check for alg:none or weak signing key
Generic high-entropy string: [a-zA-Z0-9_\-]{32,45}  (combine with trufflehog's entropy scanner for fewer false positives)
```
```
# Kali \u2014 trufflehog's entropy + regex engine catches far more than a single grep pass
trufflehog filesystem ./downloaded_js --json | jq
```

### Decoding JWTs found in JS (common even on "static" sites that call a backend API)
```
# Kali
jwt_tool <token> -M at           # 'alg:none' and weak-secret attack modes
# Windows: jwt_tool is Python, runs identically via python.exe
```

**Resources:** `source-map-explorer` / `un-source-map` for bundle reconstruction, `kiterunner` (purpose-built for API route discovery from JS), `jwt_tool` for JWT attack automation, trufflehog's entropy-based secret detection engine.
