/**
 * One-time data migration: encrypts any `shlink_access.config_passcode` values
 * still stored as plaintext from before PASSCODE_ENCRYPTION_KEY was introduced.
 *
 * Safe to re-run: for each row, it first tries to decrypt the stored value with
 * the current key; if that succeeds, the row is already encrypted and is left
 * alone. Only rows that fail to decrypt (i.e. are still plaintext) get encrypted.
 *
 * Run manually once per environment, after PASSCODE_ENCRYPTION_KEY is set and
 * before/alongside deploying the code that expects config_passcode to be
 * encrypted. This is not part of the automatic migrations/ runner, since it
 * needs the app's encryption key, not just SQL.
 *
 * Usage: deno run --allow-env --allow-read=".","./db" --allow-write="./db" migrations/scripts/backfill-encrypt-passcodes.ts
 */
import { sqlite } from '../../deps.ts';
import { encryptSecret, decryptSecret } from '../../secrets.ts';
import env from '../../config.ts';

const { DB } = sqlite;

const dir = env.DIR || '.';
const db = new DB(dir + '/db/vaxx.db');

const rows = db.queryEntries<{ id: string; config_passcode: string | null }>(
  `SELECT id, config_passcode FROM shlink_access WHERE config_passcode IS NOT NULL`,
);

let encrypted = 0;
let alreadyEncrypted = 0;

for (const row of rows) {
  try {
    await decryptSecret(row.config_passcode!);
    alreadyEncrypted++;
    continue;
  } catch {
    // Not valid ciphertext under the current key; treat as legacy plaintext.
  }
  const ciphertext = await encryptSecret(row.config_passcode!);
  db.query(`UPDATE shlink_access SET config_passcode=:ciphertext WHERE id=:id`, {
    ciphertext,
    id: row.id,
  });
  encrypted++;
}

console.log(`Backfill complete: ${encrypted} passcodes encrypted, ${alreadyEncrypted} already encrypted.`);
