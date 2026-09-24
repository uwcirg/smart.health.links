/**
 * Rotates PASSCODE_ENCRYPTION_KEY: decrypts every `shlink_access.config_passcode`
 * with the old key and re-encrypts it with the new key.
 *
 * This is NOT the same as backfill-encrypt-passcodes.ts. That script's
 * "already encrypted, skip" check decrypts with the *current* key, so running
 * it after a key rotation (without this script) would misread every row still
 * on the old key as plaintext and re-encrypt the ciphertext blob itself under
 * the new key, permanently losing the real passcode. Use this script instead
 * whenever the key changes.
 *
 * Safe to re-run: for each row, it first tries to decrypt with the *new* key;
 * if that succeeds, the row has already been rotated and is left alone. Only
 * rows still on the old key get rotated. A row that decrypts under neither key
 * is left untouched and reported, rather than guessed at.
 *
 * Deploy sequence:
 *   1. Generate a new key.
 *   2. Run this script with OLD_PASSCODE_ENCRYPTION_KEY set to the key
 *      currently in server.env, and NEW_PASSCODE_ENCRYPTION_KEY set to the
 *      new one. The app keeps running against the old key while this runs.
 *   3. Only once this completes with 0 failures, update PASSCODE_ENCRYPTION_KEY
 *      in server.env/secrets storage to the new key and restart the app.
 *
 * Usage: deno run --allow-env --allow-read=".","./db" --allow-write="./db" migrations/scripts/rotate-passcode-encryption-key.ts
 */
import { sqlite } from '../../deps.ts';
import { importKey, encryptWithKey, decryptWithKey } from '../../secrets.ts';
import env from '../../config.ts';

const { DB } = sqlite;

const oldKeyMaterial = Deno.env.get('OLD_PASSCODE_ENCRYPTION_KEY');
const newKeyMaterial = Deno.env.get('NEW_PASSCODE_ENCRYPTION_KEY');
if (!oldKeyMaterial || !newKeyMaterial) {
  console.error('Set both OLD_PASSCODE_ENCRYPTION_KEY and NEW_PASSCODE_ENCRYPTION_KEY to run this script.');
  Deno.exit(1);
}
if (oldKeyMaterial === newKeyMaterial) {
  console.error('OLD_PASSCODE_ENCRYPTION_KEY and NEW_PASSCODE_ENCRYPTION_KEY are identical; nothing to rotate.');
  Deno.exit(1);
}

const oldKey = await importKey(oldKeyMaterial);
const newKey = await importKey(newKeyMaterial);

const dir = env.DIR || '.';
const db = new DB(dir + '/db/vaxx.db');

const rows = db.queryEntries<{ id: string; config_passcode: string | null }>(
  `SELECT id, config_passcode FROM shlink_access WHERE config_passcode IS NOT NULL`,
);

let rotated = 0;
let alreadyOnNewKey = 0;
let failed = 0;

for (const row of rows) {
  try {
    await decryptWithKey(row.config_passcode!, newKey);
    alreadyOnNewKey++;
    continue;
  } catch {
    // Not valid ciphertext under the new key yet; proceed to rotate it below.
  }

  let plaintext: string;
  try {
    plaintext = await decryptWithKey(row.config_passcode!, oldKey);
  } catch (e) {
    console.error(`Could not decrypt config_passcode for shlink_access.id=${row.id} with either key; leaving it untouched.`, e);
    failed++;
    continue;
  }

  const ciphertext = await encryptWithKey(plaintext, newKey);
  db.query(`UPDATE shlink_access SET config_passcode=:ciphertext WHERE id=:id`, {
    ciphertext,
    id: row.id,
  });
  rotated++;
}

console.log(`Rotation complete: ${rotated} rotated, ${alreadyOnNewKey} already on new key, ${failed} failed (left untouched).`);
if (failed > 0) {
  console.error(`${failed} row(s) could not be decrypted with either key. Investigate before removing the old key from anywhere.`);
  Deno.exit(1);
}
