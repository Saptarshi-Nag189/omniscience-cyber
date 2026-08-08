# Malicious File Upload

*Keywords: file upload, upload bypass, upload a shell, webshell, double extension, .php.jpg, null byte upload, content-type spoof, magic bytes, unrestricted file upload, image upload RCE, XXE via upload, path traversal upload, avatar CV video upload, polyglot file.*

## Why file upload is high-value

Any endpoint that accepts a file (profile photo, CV, document, form attachment, bulk import) is a rich attack surface: a weak upload can yield RCE (upload a webshell), stored XSS (upload HTML/SVG served inline), XXE (malicious DOCX/XML), SSRF/LFI (via file parsers), path traversal (overwrite files), or DoS (zip/XML bombs). In a target application, an import/attachment feature that lets you place an executable or script in a web-served path is Critical. Test every upload, and test what happens on *retrieval* too (how the file is served back).

## Upload filter bypasses to test

Servers usually filter by extension and/or Content-Type — both are bypassable. Test: (1) **Double extension** — `shell.php.jpg` or `shell.jpg.php` (beats naive `\.jpg` regexes / mis-ordered checks). (2) **Null byte** — `shell.php%00.jpg` (truncates to `.php` on vulnerable parsers). (3) **Content-Type spoof** — set `Content-Type: image/png` on a `.php` payload (never trust the header). (4) **Magic-byte prefix** — prepend real image magic bytes (`GIF89a;<?php ...>`) to pass content sniffing while staying executable (polyglot). (5) **Case/alt extensions** — `.pHp`, `.php5`, `.phtml`, `.asp;.jpg`, `.svg` (XSS), `.html`, `.xhtml`. (6) **Trailing chars** — `shell.php.`, `shell.php%20`, `shell.php::$DATA` (Windows). (7) **Path in filename** — `../../shell.php` to escape the upload dir. Confirm impact minimally: upload a benign marker (`<?php echo 'PWN123'; ?>` returning PWN123, or an SVG with `alert(document.domain)`), prove execution, then STOP — no real webshell activity, no destructive overwrite.

## Where the bug actually lives + related threats

The dangerous combination is: upload accepted with a controllable extension/content **AND** the file lands in a web-served, executable path **AND** it's retrievable. Break any link and it's mitigated. Also test: files served with `Content-Disposition: inline` (SVG/HTML → stored XSS in the app origin); uploads processed by an image/PDF/XML library (ImageTragick, XXE via DOCX/SVG, SSRF via a URL the parser fetches); public retrieval leaking *other* users' uploaded files (an IDOR on the download endpoint — test with authz_matrix.py); zip/XML bombs (billion-laughs) — probe carefully, do not actually DoS.

## File-upload CVSS and remediation

Webshell → RCE (authenticated low-priv): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 8.8 High; unauthenticated → `PR:N` = 9.8 Critical. Stored XSS via SVG/HTML upload hitting other users: ~High (see XSS card). IDOR download of other users' files: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5. Root cause: trusting client-supplied filename/extension/Content-Type and storing uploads in a web-executable, directly-retrievable location. Remediation: allowlist safe extensions AND validate real content; rename to an app-generated id; store outside the webroot (or on a separate origin/bucket) and serve via a handler that sets a non-executable content type + `Content-Disposition: attachment`; size/char limits; scan; require auth + object-level authz on both upload and download.
