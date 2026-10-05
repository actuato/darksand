# `policy/` (Go) — status: unbuilt reference

This tree is **not built or tested**: there is no `go.mod`, its imports
(`github.com/darksand/darksand/{coordinator,internal,middleware,security}`)
do not exist in this repo, and no CI job compiles it. The live policy plane
is the Rust service in `crates/darksand-policy` (SQLite, Ed25519-signed
lifecycle commands, nonce replay protection).

Known defects if anyone revives it (from code review, unverified by build):

* `RegisterFleetRoutes` (`api/routes_fleet.go`) attaches no auth middleware;
  the `X-API-Key` the Rust fleet agent sends is never read.
* `register_fleet_agent` is called with 8 args including `public_key`, but the
  migration defines 7 params and no `public_key` column; `SELECT public_key`
  would fail.
* `tenant_crypto_keys` / `decision_nonces` (used by `security/fleet_crypto.go`)
  are created by no migration.
* `checkAndRecordNonce` counts `(nonce, decision_id)` pairs instead of prior
  use — the replay contract is inverted vs migrations 041/042.
* Hardcoded dashboard values (`PolicyHash`, violation types); string-built SQL
  intervals; the Postgres test reads a nonexistent `../database/migrations`
  path and always skips without a DSN.

Revival requires, in order: a `go.mod` with resolvable imports, migrations
for the missing tables, the 8-vs-7-arg contract fix, nonce logic aligned with
041/042, auth middleware on fleet routes, and a CI job that builds it.
Until then, treat this directory as design reference only.
