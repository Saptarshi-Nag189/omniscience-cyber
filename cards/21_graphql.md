# GraphQL API Security Testing

*Keywords: GraphQL, introspection, __schema, __type, query batching, alias overloading, deep nesting DoS, field suggestion, GraphQL IDOR, mutation authz, injection through resolver, apollo, graphiql, persisted queries, /graphql endpoint.*

## What to test on a GraphQL endpoint

GraphQL exposes one endpoint (`/graphql`, `/api/graphql`, `/v1/graphql`) that speaks a typed query language, which shifts the bug classes: authorization is per-resolver (easy to miss on nested fields), a single query can fan out to many objects (IDOR/BOLA at scale), and classic injections still live *behind* resolvers (SQLi/NoSQLi/command). First map the surface: attempt **introspection** to dump the whole schema (`{__schema{types{name fields{name}}}}` or a full introspection query) — if enabled, you get every query, mutation, type, and field for free. If introspection is disabled, use **field-suggestion** (send a slightly wrong field; many servers reply "Did you mean ...") and tools like Clairvoyance to reconstruct the schema.

## GraphQL authz / IDOR / injection testing (impact-limited)

The highest-yield bug is **broken object/field authorization**: request an object by ID that belongs to another user (`{ user(id:"<other>"){ email ssn } }`), or read a sensitive field a low-priv role shouldn't see — GraphQL often authorizes the top query but not each nested field, so `me{ orders{ user{ email } } }` can leak across tenants. Prove with **one** other-user record, not a bulk sweep. Test **mutations** for missing authz (can a normal user call `deleteUser`/`makeAdmin`?) and **mass-assignment** (pass extra input fields like `role:"admin"` a mutation forgot to allowlist). Injection reaches the resolver: put SQLi/NoSQLi/SSRF payloads in **arguments and variables** (`{ search(filter:"' OR 1=1-- -") }`), not just the query string. Use variables to keep PoCs clean and reproducible.

## GraphQL-specific abuse: batching, nesting, cost

GraphQL adds attack surface generic REST doesn't: **alias-based batching** runs many operations in one request — `q1:login(...) q2:login(...) ...` can defeat naive per-request rate limits on login/OTP (demonstrate the rate-limit gap with a small batch, do **not** launch a real credential-stuffing flood — that's DoS-like and usually out of scope). **Query batching arrays** (`[{query...},{query...}]`) similarly. **Deeply nested queries** (`a{b{a{b...}}}`) can exhaust the server — this is a DoS, so *report the missing depth/cost limit as a finding* rather than actually crashing a live target. Note whether **persisted queries** / an operation allowlist are enforced; their absence plus introspection is itself worth reporting.

## GraphQL CVSS and remediation

Cross-tenant data read via broken field authz (authenticated low-priv reading another user's PII): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5; an unauthenticated mutation causing privileged state change: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` ≈ 8.2; injection through a resolver reaching the DB → score as the underlying SQLi/RCE. Root cause(s): introspection left on in production, authorization enforced at the query root instead of every resolver/field, no input allowlist on mutation fields, and no query cost/depth limiting. Remediation: disable introspection and field suggestions in prod; enforce authorization in every resolver (object- and field-level), ideally centrally; allowlist mutation inputs (no mass assignment); add query depth/complexity limits and per-operation rate limiting; use persisted/allowlisted queries; and sanitize/parameterize inside resolvers just like any other API.
