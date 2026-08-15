# Insecure Deserialization — Object Injection to RCE

*Keywords: insecure deserialization, object injection, pickle, PHP unserialize, Java serialized object, ysoserial, gadget chain, .NET BinaryFormatter, Node.js node-serialize, Ruby Marshal, magic methods __wakeup __destruct, rO0AB, phpggc, serialized cookie, viewstate.*

## What insecure deserialization is and where to find it

Deserialization turns bytes back into an in-memory object. It's insecure when untrusted, attacker-controlled bytes are deserialized by a language runtime that will instantiate arbitrary classes and run their lifecycle methods (magic methods / gadgets) — leading to object injection, auth bypass, or RCE. Hunt for serialized blobs in anything a client sends back: cookies and hidden fields, `Authorization`/session tokens, cache/`ViewState`, message-queue payloads, and API bodies. Recognizable markers: **Java** `rO0AB...` (base64 of `0xACED0005`), **PHP** `O:8:"UserName":...` / `a:2:{...}`, **Python pickle** `\x80\x04...` or base64 starting `gAS`, **.NET** `AAEAAAD/////`, **Ruby** `\x04\x08`, **Node** `{"rce":"_$$ND_FUNC$$_..."}`.

## Deserialization detection — safe, non-destructive proof

First confirm the blob is actually deserialized server-side (not just compared): tamper one byte and watch for a deserialization-specific error/stacktrace vs. a generic 403. Then prove impact with the **least destructive** gadget: a property-oriented change (flip `isAdmin`/`role` in a PHP/Java object to prove object injection and privilege change) is a strong, low-risk PoC. For RCE-class proof, generate a gadget chain that runs a single benign, observable command — a DNS/HTTP callback to an in-scope listener (`ysoserial ... 'nslookup you.collab'`) is the cleanest: it proves code execution without touching data. Avoid file-writing or destructive gadgets on production; a callback or `id` is enough.

## Deserialization gadget tooling by stack

**Java** — `ysoserial` picks a gadget chain from libraries on the classpath (`CommonsCollections`, `Spring`, `URLDNS` for a pure-detection callback that needs no RCE gadget): `java -jar ysoserial.jar URLDNS "http://<in-scope-collab>" | base64`. Start with `URLDNS`/`JRMPClient` to *detect* before attempting `CommonsCollections` RCE. **PHP** — `phpggc` builds chains from framework gadgets (`Laravel/RCE`, `Monolog/RCE`); or hand-craft an object whose `__wakeup`/`__destruct` reaches a sink. **.NET** — `ysoserial.net` for `BinaryFormatter`/`Json.NET TypeNameHandling`/`ViewState` (needs the machineKey). **Python** — a pickle `__reduce__` returning `(os.system,('id',))`; only against an endpoint that pickles untrusted input. **Node** — `node-serialize` IIFE payload. Match the tool to the confirmed stack; don't spray chains blindly at production.

## Deserialization CVSS and remediation

Untrusted-input deserialization reaching RCE: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical; object injection limited to privilege/logic tampering (no code exec): `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` ≈ 8.1. Root cause: native deserialization of attacker-controlled data with no type restriction. Remediation: **do not deserialize untrusted input** — use a data-only format (JSON/protobuf) with strict schemas and no polymorphic type resolution; if native serialization is unavoidable, sign+verify blobs (HMAC) so tampering is rejected, and use a strict class allowlist (`ObjectInputFilter` in Java, disable `TypeNameHandling` in .NET, avoid `pickle`/`Marshal.load` on untrusted data); keep libraries patched (gadget chains live in dependencies) and run with least privilege.
