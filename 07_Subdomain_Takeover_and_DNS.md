# 7. Subdomain Takeover & DNS Misconfig

**What it is:** a subdomain's CNAME points to a third-party service (GitHub Pages, Heroku, AWS S3/CloudFront, Netlify, Azure, etc.) that no longer has anything registered at that name \u2014 attacker claims it on the provider and now serves content on your subdomain.

### Test checklist
- [ ] Every subdomain from recon: check its DNS record type (CNAME vs A)
- [ ] CNAME pointing to a cloud service \u2014 does the target respond with a "not found / no such app" / "bucket does not exist" page?
- [ ] Dangling NS records (subdomain delegated to nameservers no longer controlled)
- [ ] SPF record issues: overly permissive `include:` or `+all` (email spoofing)
- [ ] Missing DMARC record (email spoofing / phishing risk)
- [ ] DNSSEC not enabled (not a takeover vector, but note for completeness)
- [ ] Zone transfer (AXFR) allowed from untrusted IPs

### Linux (Kali)
```
# Dedicated takeover scanners (check against fingerprint DB of 60+ services)
subjack -w subs.txt -t 50 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l subs.txt -t subdomain-takeover/

# Manual CNAME check
for s in $(cat subs.txt); do echo "$s: $(dig cname $s +short)"; done

# Zone transfer test
dig axfr target.com @ns1.target.com

# SPF/DMARC
dig txt target.com | grep spf
dig txt _dmarc.target.com
```

### Windows
```
# subjack/nuclei are Go binaries, run natively:
subjack.exe -w subs.txt -t 50 -timeout 30 -ssl
nuclei.exe -l subs.txt -t subdomain-takeover/

# Manual CNAME check
Get-Content subs.txt | ForEach-Object { "$_ : " + (Resolve-DnsName $_ -Type CNAME -ErrorAction SilentlyContinue).NameHost }

# SPF/DMARC
Resolve-DnsName target.com -Type TXT
Resolve-DnsName _dmarc.target.com -Type TXT
```

**Confirming a takeover candidate:** visit the subdomain in a browser \u2014 typical giveaway messages: "There isn't a GitHub Pages site here", "NoSuchBucket", "No such app", "project not found". Never actually register the resource without explicit written authorization \u2014 flag it in the report instead.

**Impact framing:** confirmed subdomain takeover = critical/high (full content control + can be used for cookie theft on shared parent domain, phishing); missing DMARC/loose SPF = medium (email spoofing).

## Advanced / Deeper Coverage

### Use the actual fingerprint database, don't guess from memory
The community-maintained `can-i-take-over-xyz` project tracks 70+ services with their exact "vulnerable" response signature, whether they're currently exploitable, and required conditions:
```
# Kali \u2014 clone it and grep for the service your dangling CNAME points to
git clone https://github.com/EdOverflow/can-i-take-over-xyz.git
grep -i "github.io" can-i-take-over-xyz/README.md
```
Check this before concluding "not exploitable" \u2014 providers change their vulnerability status over time (e.g. many were fixed after mass disclosure campaigns), and the fingerprint text matters more than just "it 404s".

### Beyond CNAME: other dangling-resource takeover classes
```
# MX record pointing to a decommissioned mail provider -> email takeover for the domain
dig mx target.com

# NS record delegation to a nameserver you no longer control (full DNS takeover, more severe than a single-subdomain CNAME issue)
dig ns target.com
whois <the nameserver domain>   # check if IT'S expired/unregistered

// Elastic Beanstalk / Heroku / Vercel / Netlify / Fastly / Pantheon all have their own dangling-resource takeover patterns beyond plain CNAME-to-cloud-bucket
```

### Automating takeover hunting across the full subdomain list with current fingerprints
```
# Kali
nuclei -l subs.txt -t http/takeovers/ -c 50
dnsReaper scan file --file subs.txt         # newer tool, actively maintained fingerprint set, often more current than subjack
```
```
# Windows: nuclei.exe runs natively; dnsReaper is Python, runs via python.exe
```

### SPF/DMARC deeper analysis (beyond "is it missing")
```
# Check for overly permissive includes that themselves point to expired infra
dig txt target.com | grep spf
# resolve each include: mechanism and check if THAT domain/IP range is still controlled by a legitimate party

# DMARC policy strength matters, not just presence
dig txt _dmarc.target.com
# p=none -> monitoring only, spoofing still works; p=quarantine/reject -> actually enforced
```

**Resources:** EdOverflow's `can-i-take-over-xyz` (the canonical fingerprint list), `dnsReaper` (actively maintained alternative to subjack), PortSwigger's subdomain takeover topic page.
