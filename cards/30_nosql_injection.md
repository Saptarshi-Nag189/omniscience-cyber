# NoSQL Injection (MongoDB & friends)

*Keywords: NoSQL injection, MongoDB injection, $ne $gt $regex $where operator injection, JSON operator injection, auth bypass NoSQL, $ne null, mongo, couchdb, redis, JavaScript $where, blind NoSQL, operator injection, nosqlmap.*

## What NoSQL injection is and where it hits

NoSQL injection is untrusted input reaching a NoSQL query in a way that changes its structure — most commonly by injecting **query operators** into a document query, or injecting **JavaScript** into a server-side evaluation (`$where`, `mapReduce`). MongoDB is the usual target but the class covers CouchDB, Redis, and others. The classic sink is a login or search handler that passes request JSON straight into a query: `db.users.find({user: req.body.user, pass: req.body.pass})`. If the app doesn't cast inputs to strings, an attacker sends objects instead of strings and rewrites the query logic. Look at any JSON API, login, search/filter, and sort parameter where the value ends up inside a Mongo/Couch query.

## NoSQL detection — operator & auth-bypass PoC (impact-limited)

**Auth bypass** is the flagship PoC. If the endpoint takes JSON, replace a string with an operator object:
```json
{"user": "admin", "pass": {"$ne": null}}      // password "not equal to null" → matches
{"user": {"$gt": ""}, "pass": {"$gt": ""}}    // both "greater than empty" → first user
```
A successful login without knowing the password proves it. In URL-encoded form, the same is `user=admin&pass[$ne]=x` (many parsers turn `pass[$ne]` into a nested object). **`$regex`** enables blind extraction: `{"pass": {"$regex": "^a"}}` — a different response for a matching prefix lets you infer a value character-by-character (extract just enough to prove impact, e.g. confirm the first 1–2 chars, not the whole credential). **`$where` / JavaScript** injection: `'; return true; var x='` or `1; sleep(3000)` yields boolean/time-based blind like SQLi. Prove with a login bypass or a single-record differential — don't dump the collection.

## NoSQL variants, encodings, and tooling

Send the payload in the content type the app parses: JSON body operators (`$ne`, `$gt`, `$in`, `$regex`, `$where`), the `param[$op]=` bracket form for `application/x-www-form-urlencoded`, and operators in `sort`/`filter` query params. For time-based blind where responses aren't reflected, use `$where: "sleep(3000)"` (Mongo with server-side JS enabled) and measure delay. **nosqlmap** can automate detection, but the manual operator payloads above are cleaner and lower-impact for a report. Distinguish NoSQLi from SQLi by fingerprinting the stack (Node/Express + Mongo is the tell) — a `{"$ne":1}` that changes behavior where `' OR 1=1` doesn't points to NoSQL. Keep every probe on the in-scope host and stop at proof.

## NoSQL-injection CVSS and remediation

Unauthenticated NoSQLi giving auth bypass / cross-user data read: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1; `$where` JavaScript injection reaching server-side code execution → Critical. Root cause: user input used as a query *object/operator* (or as evaluated JS) instead of a bound scalar value. Remediation: cast/validate every input to its expected type before it reaches the query (a password must be a string, never an object); reject request keys beginning with `$` or containing `.`; use the driver's typed query builders / parameterization rather than passing raw request bodies into `find`; disable server-side JavaScript (`$where`, `mapReduce`, `--noscripting`) unless essential; apply least-privilege DB roles and schema validation.
