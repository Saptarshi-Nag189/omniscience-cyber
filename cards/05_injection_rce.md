# Command Injection, SSTI, XXE, Deserialization → RCE

*Keywords: remote code execution, RCE, command injection, OS command, shell injection, SSTI, server side template injection, {{7*7}}, XXE, XML external entity, insecure deserialization, pickle, gadget chain, run commands on server, code execution.*

## OS command injection

Command injection is user input reaching a shell. Detect by appending separators and observing side effects WITHOUT running destructive commands: `; sleep 5`, `| sleep 5`, `` `sleep 5` ``, `$(sleep 5)`, `& ping -c 3 127.0.0.1`, newline `%0a`. A reproducible time delay is a safe, impact-limited PoC — do not run `rm`, do not read `/etc/shadow`, do not pivot (rules prohibit lateral movement). Confirm the injection point (filename, host/ip field, export/convert features, PDF/image processors). Windows variants: `& timeout 5`, `| whoami`. Blind OOB confirmation only if you control an in-scope collaborator; otherwise time-based is enough for the report.

## Server-Side Template Injection (SSTI)

SSTI happens when input is embedded in a server-side template. Detect with the polyglot `${{<%[%'"}}%\` (breaks most engines) then the math probe `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` — a rendered `49` confirms it. Fingerprint the engine (Jinja2/Twig/Freemarker/Velocity/ERB) by which syntax evaluates, then escalate ONLY to prove impact (e.g. Jinja2 `{{config}}` to show data exposure). SSTI commonly yields RCE; for the PoC, demonstrate template evaluation and, if RCE, a benign command (`id`) — nothing destructive. Look in: profile fields rendered in emails, PDF/report generators, error pages, any "customize" feature.

## XXE and insecure deserialization

XXE: XML parsers that resolve external entities. Test XML upload/API bodies with `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><root>&e;</root>` — reflection of file contents proves it (read a benign file like `/etc/hostname`, not secrets). Blind XXE via OOB to an in-scope listener. Impact: file read, SSRF, sometimes RCE/DoS (do not DoS). Insecure deserialization: attacker-controlled serialized objects (Java `ac ed 00 05`, PHP `O:`, Python pickle, .NET) reaching a deserializer enable RCE via gadget chains. Detect by identifying deserialization sinks (cookies, view-state, cache, message queues) and testing with a benign marker; prove code execution minimally.

## Injection-to-RCE CVSS and remediation

RCE (command injection / SSTI / deserialization) unauthenticated: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical; authenticated low-priv RCE `PR:L` = 8.8 High; if it escapes the app context (scope change) use `S:C` to push higher. XXE file read: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5, higher if SSRF/RCE. Root cause: untrusted input reaching a dangerous interpreter (shell, template engine, XML/deserializer) without sanitization. Remediation: avoid shells (use exec with arg arrays), sandbox/allowlist template inputs, disable external entities, never deserialize untrusted data (use signed/whitelisted formats or plain JSON).
