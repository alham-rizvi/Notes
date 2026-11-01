# Resources & References

Where the "Advanced" sections in every file are grounded. Bookmark these \u2014 they're updated far more often than any static cheatsheet, including this one.

## Primary cheat sheets / methodology
- **PortSwigger Web Security Academy** \u2014 portswigger.net/web-security \u2014 free labs for every vuln class covered here, plus the canonical XSS cheat sheet, SQLi cheat sheet, SSRF/open redirect material, and URL validation bypass cheat sheet.
- **PayloadsAllTheThings** (swisskyrepo, GitHub) \u2014 the single most complete payload/bypass repository across every vuln category, organized by technology.
- **HackTricks** (book.hacktricks.xyz) \u2014 deep methodology pages per vuln class, especially strong on CORS, LFI/RFI, file upload bypasses, and cloud-specific attack paths.
- **OWASP Testing Guide (WSTG)** \u2014 owasp.org/www-project-web-security-testing-guide \u2014 the formal, structured methodology that maps directly onto a professional pentest report's structure.
- **OWASP Top 10** \u2014 for mapping findings to recognized categories in the final report.

## Recon & OSINT
- **can-i-take-over-xyz** (EdOverflow, GitHub) \u2014 canonical subdomain takeover fingerprint database.
- **Intigriti Research Blog** \u2014 blog.intigriti.com \u2014 "overlooked recon techniques," Shodan/Censys usage, favicon hashing methodology.
- **ProjectDiscovery docs** (subfinder, httpx, nuclei, katana) \u2014 docs.projectdiscovery.io \u2014 the toolchain most of the recon commands in this doc are built on.
- **SecLists** (danielmiessler, GitHub) \u2014 the standard wordlist collection referenced throughout (directories, files, LFI, SQLi, XSS, usernames).

## Tool documentation worth reading end-to-end (not just --help)
- sqlmap README + `sqlmap/tamper/` source \u2014 the tamper script list is far longer than what's covered here.
- nuclei templates repo (projectdiscovery/nuclei-templates) \u2014 browse by category to see what's auto-detectable vs what needs manual testing.
- Burp Suite documentation on Intruder payload processing \u2014 the brute-force-the-allow-list methodology in the XSS file depends on this.

## Staying current
WAF vendors and frameworks patch bypasses regularly \u2014 a technique that works today may not in six months, and new ones appear constantly. Before a job/engagement:
1. Check portswigger.net/research for the latest published techniques.
2. Check the target's identified WAF vendor's changelog/advisories if publicly available.
3. Re-run `wafw00f`/fingerprinting at the start of every engagement \u2014 don't assume last time's findings still apply.

## Legal / scope reminder
Everything in this document assumes written authorization to test the target. Confirm scope (in-scope subdomains, excluded paths, rules of engagement around DoS-adjacent tests like rate-limit fuzzing or mass directory brute-forcing) before running anything here against a real target.
