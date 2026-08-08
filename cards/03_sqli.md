# SQL Injection — Detection, PoC discipline, Scoring

*Keywords: SQL injection, SQLi, database injection, blind SQLi, time-based, boolean-based, error-based, UNION, sqlmap, inject into query parameter, auth bypass with SQL, ' OR '1'='1, dump database, DBMS, parameterized query, prepared statement.*

## Detecting SQLi without dumping the database

SQLi is user input concatenated into a SQL query. Detection order that stays PoC-only (no mass exfiltration, per rules of engagement): (1) Error-based — inject `'`, `"`, `\`, `')`, and watch for SQL errors / 500s. (2) Boolean-based blind — compare `id=1 AND 1=1` vs `id=1 AND 1=2`; a content difference proves injection. (3) Time-based blind — `id=1' AND SLEEP(3)-- -` (MySQL) / `pg_sleep(3)` (Postgres) / `WAITFOR DELAY '0:0:3'` (MSSQL); a reproducible 3s delay is strong proof WITHOUT reading data. Prefer boolean/time proof over UNION dumps so you demonstrate impact without touching real records — this satisfies "PoC limited to demonstrating impact."

## SQLi with sqlmap, throttled and scoped

If manual proof is ambiguous, `sqlmap` confirms safely when throttled: `sqlmap -u "https://<in-scope-host>/x?id=1" --cookie="SESSION=..." --level 2 --risk 1 --delay 0.5 --technique=BT --batch`. Use `--technique=BT` (boolean+time) to avoid heavy UNION queries, `--delay` to avoid any DoS-like load, and stop at `--current-user`/`--current-db`/`--dbs` to prove access — do NOT `--dump` real tables. Keep the target strictly on the scope allowlist. Never run sqlmap against anything not explicitly in scope; out-of-scope = a rules violation.

## SQLi injection points and payload notes

Test every input reflected into a query: query params, POST body fields, JSON values, HTTP headers used in queries (`X-Forwarded-For`, `User-Agent`, `Referer`), cookies, and ORDER BY / LIMIT clauses (often non-parameterizable). Auth bypass classic: `admin'-- -` or `' OR '1'='1'-- -` in username. For blind, DBMS fingerprint via version functions: `@@version` (MySQL/MSSQL), `version()` (Postgres). Second-order SQLi: input stored then used unsafely later (e.g. a profile field used in an admin report) — test by planting a payload then triggering the downstream query.

## SQLi CVSS and remediation

Authenticated SQLi exposing DB contents: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5; unauthenticated + full DB read/write: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical. If it enables auth bypass or RCE via stacked queries/`xp_cmdshell`, argue Critical. Root cause: untrusted input concatenated into SQL instead of being bound as a parameter. Remediation: parameterized queries / prepared statements everywhere; ORM with bound params; allowlist for identifiers that cannot be parameterized (column/table names in ORDER BY); least-privilege DB account; do not surface raw DB errors to clients.
