# Path Traversal / Local File Inclusion (LFI)

*Keywords: path traversal, directory traversal, LFI, local file inclusion, RFI, ../, dot dot slash, ..%2f, file read, arbitrary file download, ?file= ?page= ?template=, /etc/passwd, php filter wrapper, log poisoning, zip phar wrapper, null byte, absolute path, download endpoint.*

## What path traversal / LFI is and where to find it

Path traversal is supplying `../` sequences (or absolute paths) to escape an intended directory and read/write files outside it. LFI is the include-flavored version: the app *includes/executes* a user-named file (classic PHP `include($_GET['page'])`), which can escalate from file read to code execution. Look at any parameter that names a file, path, template, or resource: `?file=`, `?page=`, `?template=`, `?doc=`, `?download=`, `?lang=`, `?path=`, image/attachment/report download endpoints, "export as", and locale/theme selectors. A download endpoint that takes a filename is the prototypical target.

## Path-traversal detection and impact-limited proof

Confirm by climbing to a known file: `../../../../etc/passwd` (Linux) or `..\..\..\..\windows\win.ini` (Windows); read **one** benign, non-secret file (`/etc/hostname`, `win.ini`) to prove traversal without exposing sensitive data in bulk. If the app appends an extension (e.g. `.php`), older stacks allow a null byte `%00` truncation or a long path `../file%00.png`; modern ones need a different sink. For **LFI→RCE** proof on an in-scope host, the cleanest low-impact routes: **PHP wrappers** to read source without executing — `php://filter/convert.base64-encode/resource=index.php` returns the file base64'd (great for source disclosure, no code run); `data://`/`expect://` for execution only if you must demonstrate RCE, then run one benign command. **Log poisoning** (inject PHP into a User-Agent, then include the log) also proves RCE — use sparingly and non-destructively. Never write/overwrite files on a live target.

## Traversal filter bypasses

If `../` is filtered, try: **URL/double encoding** — `..%2f`, `%2e%2e%2f`, `..%252f`; **over-long / mixed** — `....//`, `..././`, `.../.../`; **backslashes** on Windows/some parsers — `..%5c`; **absolute path** if the app only strips traversal but not roots — `/etc/passwd`, `C:\...`; **UTF-8 overlong** — `%c0%ae%c0%ae/`; **strip-once bugs** — `....//` becomes `../` after a single `../`→`` replacement. If an allowlisted prefix is prepended, try a leading `....//` past it or a wrapper. For LFI where a suffix is appended and null byte fails, look for `zip://`/`phar://` (upload an archive, then include it) — but keep any upload benign and in-scope.

## Path traversal / LFI CVSS and remediation

Arbitrary file read (unauthenticated): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5; LFI reaching RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical; authenticated-only read: drop PR to L → 6.5. Root cause: user input used to build a filesystem path (or an `include`) without canonicalization or an allowlist. Remediation: never pass user input to file APIs directly — map an opaque ID to a server-side filename via a lookup table; if a path is unavoidable, canonicalize (`realpath`) and verify the result stays within the intended base directory *after* resolving; reject traversal sequences and absolute paths; disable dangerous PHP wrappers (`allow_url_include=Off`) and never `include` user input; run with least-privilege filesystem access.
