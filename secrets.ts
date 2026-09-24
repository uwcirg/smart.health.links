import { base64url } from './deps.ts';
import env from './config.ts';

const IV_BYTES = 12; // 96-bit IV, recommended size for AES-GCM

/** Imports a base64url-encoded 32-byte key for AES-256-GCM use. Exported so
 * one-off scripts (e.g. key rotation) can import an explicit key rather than
 * the single key configured via PASSCODE_ENCRYPTION_KEY. */
export async function importKey(base64urlKey: string): Promise<CryptoKey> {
  const rawKey = base64url.decode(base64urlKey);
  if (rawKey.length !== 32) {
    throw new Error('Encryption key must decode to 32 bytes (AES-256)');
  }
  return await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

let configuredKeyPromise: Promise<CryptoKey> | undefined;

function getConfiguredKey(): Promise<CryptoKey> {
  if (!configuredKeyPromise) {
    if (!env.PASSCODE_ENCRYPTION_KEY) {
      throw new Error('PASSCODE_ENCRYPTION_KEY is not configured');
    }
    configuredKeyPromise = importKey(env.PASSCODE_ENCRYPTION_KEY);
  }
  return configuredKeyPromise;
}

export async function encryptWithKey(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)),
  );
  const combined = new Uint8Array(iv.length + ciphertext.length);
  combined.set(iv);
  combined.set(ciphertext, iv.length);
  return base64url.encode(combined.buffer);
}

export async function decryptWithKey(encoded: string, key: CryptoKey): Promise<string> {
  const combined = new Uint8Array(base64url.decode(encoded));
  const iv = combined.slice(0, IV_BYTES);
  const ciphertext = combined.slice(IV_BYTES);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

/** Encrypts a secret (e.g. a passcode) for storage at rest, using the
 * configured PASSCODE_ENCRYPTION_KEY. Reversible: the decrypted value must be
 * shown back to the resource's owner, so this is encryption, not hashing.
 * Confidentiality depends entirely on protecting PASSCODE_ENCRYPTION_KEY. */
export async function encryptSecret(plaintext: string): Promise<string> {
  return await encryptWithKey(plaintext, await getConfiguredKey());
}

export async function decryptSecret(encoded: string): Promise<string> {
  return await decryptWithKey(encoded, await getConfiguredKey());
}

/** Constant-time string comparison, for comparing a decrypted secret against
 * user input without leaking how many leading characters matched via timing. */
export function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}
