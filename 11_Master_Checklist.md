# Master Checklist \u2014 Report Mapping

Run through recon first, then work the vulnerability files in order. Tick these off as you confirm/rule out each; use this as the skeleton for the final report (Finding / Severity / Evidence / Recommendation).

## Recon (prerequisite for everything else)
- [ ] Subdomains enumerated and alive-checked
- [ ] DNS / WHOIS / zone transfer checked
- [ ] Tech stack fingerprinted per host
- [ ] Full headers captured for every host
- [ ] Content discovery run (dirbusting + wayback/gau)

## Findings by severity (fill in as you go)
### Critical
- [ ] Exposed .git / full source or credential leak
- [ ] Confirmed SQLi / SSTI / command injection
- [ ] SSRF reaching cloud metadata or internal services
- [ ] Unrestricted file upload \u2192 RCE
- [ ] Confirmed subdomain takeover

### High
- [ ] Exposed .env / backups / sensitive config
- [ ] CORS misconfig with credentials
- [ ] Stored XSS
- [ ] Live API key/credential in JS bundle
- [ ] Confirmed LFI reading sensitive files

### Medium
- [ ] Missing/weak CSP, HSTS, or other security headers
- [ ] Reflected/DOM XSS
- [ ] Host header injection affecting generated links
- [ ] Open redirect
- [ ] Weak SPF / missing DMARC
- [ ] Cache poisoning/deception

### Low / Informational
- [ ] Directory listing (non-sensitive content)
- [ ] Verbose server/version headers
- [ ] Missing rate limiting on contact forms
- [ ] Clickjacking with no sensitive actions behind it
- [ ] Dev comments / debug flags in source

## Per-finding template
```
Title:
Severity:
Affected URL(s):
Description:
Steps to Reproduce:
  1.
  2.
Tool/Command used:
Impact:
Recommendation:
References (CWE/CVE/OWASP):
```

Keep all raw command output saved per-subdomain (e.g. `recon/<subdomain>/`) while testing so you can paste exact evidence into each finding without re-running anything.
