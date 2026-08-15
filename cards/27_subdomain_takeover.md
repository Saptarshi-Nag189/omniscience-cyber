# Subdomain Takeover & Dangling DNS

*Keywords: subdomain takeover, dangling DNS, CNAME takeover, dangling record, NXDOMAIN, unclaimed S3 bucket, GitHub Pages takeover, Heroku Azure takeover, fingerprint, can I register this, orphaned cloud resource, DNS misconfiguration, nuclei takeover templates.*

## What subdomain takeover is and where it comes from

A subdomain takeover happens when a DNS record (usually a `CNAME`) points to a third-party service (cloud storage, a PaaS app, a CDN, a SaaS) that has been de-provisioned but never removed from DNS. Because the target's DNS still delegates the subdomain to that provider, an attacker who registers the now-unclaimed resource on that provider **serves content on the target's subdomain** — enabling convincing phishing, cookie theft for `*.target.com`-scoped cookies, CORS/OAuth trust abuse, and bypass of same-site protections. The root cause is a **dangling DNS record**: infra was torn down, the DNS entry wasn't.

## Detection — fingerprint, don't hijack

Enumerate the target's subdomains (see the recon card: `subfinder`, `amass`, CT logs via `crt.sh`), resolve each, and look for records pointing to third-party services that return a **takeover fingerprint** — provider "no such bucket/app/site" pages, e.g. S3 `NoSuchBucket`, GitHub Pages `There isn't a GitHub Pages site here`, Heroku `No such app`, Azure `404 Web Site not found`, Fastly/Shopify/Cloudfront unclaimed messages. Tools: `nuclei -t http/takeovers/`, `subjack`, `nuclei` with takeover templates. **Proof discipline for an authorized test**: confirming the fingerprint (dangling CNAME + provider's unclaimed response) is normally sufficient evidence. If your rules of engagement authorize claiming the resource to fully prove it, host only a **benign, clearly-marked PoC page** (e.g. a timestamped `pentest-poc.txt` with your engagement ID), never phishing content or anything that captures real user data, and hand the resource back / report immediately. When in doubt, report the dangling record without claiming — and never claim a resource outside the authorized scope.

## Subdomain-takeover CVSS and remediation

A takeover of a subdomain that shares cookies/OAuth/CORS trust with the main app (enables session theft / auth abuse): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` ≈ 8–9 (scope change — it crosses into the parent domain's trust); a takeover of an isolated marketing subdomain with no shared trust: Medium (phishing/brand). Root cause: a DNS record outliving the resource it points to. Remediation: remove/parking DNS records as part of every decommission (make it a teardown checklist item and enforce in IaC); prefer records tied to resources you provably still own; periodically scan your own DNS for dangling `CNAME`/`A`/`NS`/`MX` records; and where a provider supports it, use domain-verification/ownership tokens so an unclaimed resource can't be seized.
