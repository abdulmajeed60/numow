// Encrypt the dashboard data for the standalone site.
// Usage: NUMOW_SITE_PASSWORD=... node encrypt.mjs <export-dir> <out-file>
// <export-dir> holds the ArtifactData exports: config/*.json, meta/*.json, weeks/*.json, overrides/*.json
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const [dir, out] = process.argv.slice(2);
const pw = process.env.NUMOW_SITE_PASSWORD;
if (!dir || !out || !pw) { console.error('usage: NUMOW_SITE_PASSWORD=... node encrypt.mjs <export-dir> <out-file>'); process.exit(2); }

const docs = {};
for (const coll of ['config', 'meta', 'weeks', 'overrides']) {
  const d = path.join(dir, coll);
  if (!fs.existsSync(d)) continue;
  for (const f of fs.readdirSync(d).filter((x) => x.endsWith('.json'))) {
    const raw = JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'));
    const body = raw && raw.data && typeof raw.data === 'object' && !Array.isArray(raw.data) && (raw.id || raw.version) ? raw.data : raw;
    docs[coll + '/' + f.slice(0, -5)] = body;
  }
}
for (const need of ['config/roster', 'config/settings']) if (!docs[need]) { console.error('missing ' + need); process.exit(3); }
const weeks = Object.keys(docs).filter((k) => k.startsWith('weeks/')).length;
if (weeks === 0) { console.error('no weeks exported'); process.exit(3); }
if (docs['config/settings'].sync) delete docs['config/settings'].sync.triggerId;

const plain = new TextEncoder().encode(JSON.stringify({ exportedAt: new Date().toISOString(), docs }));
// Keep the salt of the previous publish so pages already unlocked can keep decrypting new data.
let salt = null;
try { const prev = JSON.parse(fs.readFileSync(out, 'utf8')); if (prev && prev.salt && process.env.NUMOW_NEW_SALT !== '1') salt = new Uint8Array(Buffer.from(prev.salt, 'base64')); } catch (e) { /* first publish */ }
if (!salt || salt.length !== 16) salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const iter = 600000;
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
const b64 = (u) => Buffer.from(u).toString('base64');
fs.writeFileSync(out, JSON.stringify({ v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) }));
console.log(`encrypted ${Object.keys(docs).length} docs (${weeks} weeks) -> ${out}`);
