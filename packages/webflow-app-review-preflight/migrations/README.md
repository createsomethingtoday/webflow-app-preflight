# D1 migrations

Applied in filename order by `wrangler d1 migrations apply webflow-app-review-preflight`.
Wrangler tracks applied migrations **by filename only** in the `d1_migrations`
table; it does not checksum file contents.

## Rollback posture

There are no down migrations. Every migration is forward-only:

- **Additive changes only.** New tables, columns, indexes, and triggers.
  Applied schema is never rewritten; tightened rules are layered on top
  (e.g. migration 0008 adds triggers rather than editing the 0003 CHECK
  constraint).
- **Idempotency.** All `CREATE TABLE` / `CREATE INDEX` / `CREATE TRIGGER`
  statements use `IF NOT EXISTS` (or `DROP ... IF EXISTS` first) so a
  partially applied migration can be re-run safely. The exception is
  `ALTER TABLE ... ADD COLUMN` (0006, 0007): SQLite has no
  `ADD COLUMN IF NOT EXISTS`. If one of those migrations partially applied,
  remove the statements that already succeeded before re-running, or apply
  the remaining statements manually and record the migration as applied.
- **Recovery.** To undo a change, write a new forward migration. Never edit
  the semantics of a migration that may already be applied in production;
  editing is safe only for comments and for adding `IF NOT EXISTS` guards.
- **`PRAGMA foreign_keys = ON`** is declared at the top of every migration
  so foreign-key enforcement is consistent regardless of which migration
  runs first in a session.
