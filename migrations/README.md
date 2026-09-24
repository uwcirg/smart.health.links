# Database Migrations

This folder is the source of truth for the SQLite schema. On every boot, `initializeDb()` in [`db.ts`](../db.ts) applies any `.sql` file here that hasn't run yet, in filename order, and records it in a `schema_migrations` table so it never runs twice.

## Adding a migration

1. Create a new file named `NNNN_short_description.sql`, where `NNNN` is the next number after the highest existing prefix (e.g. `0002_add_shlink_label_index.sql`). Zero-pad to 4 digits so filenames sort correctly.
2. Write plain SQL statements, separated by a **blank line** between statements.
3. Prefer additive, idempotent DDL: `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN`. SQLite's `ALTER TABLE` support is limited (no `DROP COLUMN`, no modifying column types/constraints), so a destructive or type-changing change needs a rename-recreate-copy-drop pattern: rename the table, recreate it with the new definition, `INSERT ... SELECT` the data across, then drop the old renamed table.
4. If a statement is expected to fail under some conditions (e.g. an index that may already exist under a different mechanism), include the literal string `ok_to_fail` somewhere in that statement (a SQL comment works) so the runner swallows the error instead of aborting the migration.
5. Each migration file runs inside a single transaction, so partial application isn't possible: either every statement in the file succeeds and the file is recorded, or none of it is kept.
6. Never edit or delete a migration file that has already been applied anywhere (including your own local `db/vaxx.db`), since the runner only tracks *whether* a filename ran, not its contents. If a past migration was wrong, fix it forward with a new migration.
7. Test locally by deleting your local `db/vaxx.db` (or running the test suite, which truncates its own DB) and confirming the app boots cleanly from scratch, then confirm it also boots cleanly against an existing DB that already has earlier migrations applied.

## Inspecting the current schema

Because the schema is the cumulative result of every file in this folder, dump it directly from a fully-migrated database to see the final schema content:

```sh
sqlite3 db/vaxx.db .schema
```

or, without the `sqlite3` CLI installed, via Deno (`deno eval` has implicit access to all permissions):

```sh
deno eval "import { sqlite } from './deps.ts'; const db = new sqlite.DB('./db/vaxx.db'); for (const [sql] of db.query(\"select sql from sqlite_master where sql is not null\")) console.log(sql + ';\n');"
```

To check which migrations a given database has applied:

```sh
sqlite3 db/vaxx.db "select id, applied_at from schema_migrations order by id;"
```
