// Crack the key-derivation function: secret -> 32-byte AES-256 key.
//
// The AES key is KDF(ECDH shared secret). The cipher object stores a 32-byte
// block A||B at cipher_obj+0x28, right before the key at +0x48 — likely the
// shared secret kept resident. This slides a 32-byte "secret" window over all
// captured memory blobs and tries a battery of KDFs against the known key.
// If any KDF(window) == key, the derivation (and the secret's location) is
// found — and the plugin can replicate it with no further RE.
//
// Usage:
//   node tools/crack-kdf.mjs [key-hex] [blob.bin ...]
//   key   defaults to the Path C recovered key
//   blobs default to /tmp/stick-pathC-blob-*.bin

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const DEFAULT_KEY =
  '531e1b9f097be5de5785f5bf86473da34839fabb76676e95c0e4b808b42f8ac0';
// hardcoded 33-byte secret deobfuscated from the binary (memory note)
const HC = Buffer.from(
  '527a5b46c56f3a5e670b4f0e338727d9' +
  '4737ec0fc4af0dba93a51d93965191d0' + '8f', 'hex');

let [, , maybeKey, ...blobArgs] = process.argv;
let keyHex = DEFAULT_KEY;
if (maybeKey && /^[0-9a-fA-F]{64}$/.test(maybeKey)) keyHex = maybeKey;
else if (maybeKey) blobArgs.unshift(maybeKey);
const KEY = Buffer.from(keyHex, 'hex');

let blobs = blobArgs;
if (blobs.length === 0) {
  blobs = fs.readdirSync('/tmp')
    .filter(f => /^stick-pathC-blob-.*\.bin$/.test(f))
    .map(f => '/tmp/' + f);
}
if (blobs.length === 0) { console.error('no blobs found'); process.exit(1); }

const sha256 = b => crypto.createHash('sha256').update(b).digest();
const sha512 = b => crypto.createHash('sha512').update(b).digest();
const sha1   = b => crypto.createHash('sha1').update(b).digest();
const md5    = b => crypto.createHash('md5').update(b).digest();
const blake2b = b => crypto.createHash('blake2b512').update(b).digest();
const blake2s = b => crypto.createHash('blake2s256').update(b).digest();
const hmac = (k, m) => crypto.createHmac('sha256', k).update(m).digest();
const cat = (...xs) => Buffer.concat(xs);
const rev = b => Buffer.from(b).reverse();
const xor = (a, b) => { const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) o[i] = a[i % a.length] ^ b[i % b.length]; return o; };
function ecb(keyB, data) {
  const c = crypto.createCipheriv('aes-256-ecb', keyB, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

const HC32 = HC.subarray(0, 32);
const HC16a = HC.subarray(0, 16);
const HC16b = HC.subarray(16, 32);

// each KDF maps a candidate secret W (32 bytes) -> a 32-byte key
const KDFS = [
  ['identity',              W => W],
  ['sha256(W)',             W => sha256(W)],
  ['sha256(sha256(W))',     W => sha256(sha256(W))],
  ['sha512(W)[:32]',        W => sha512(W).subarray(0, 32)],
  ['blake2b(W)[:32]',       W => blake2b(W).subarray(0, 32)],
  ['blake2s(W)',            W => blake2s(W)],
  ['md5(W)|md5(revW)',      W => cat(md5(W), md5(rev(W)))],
  ['sha256(W|HC33)',        W => sha256(cat(W, HC))],
  ['sha256(HC33|W)',        W => sha256(cat(HC, W))],
  ['sha256(W|HC32)',        W => sha256(cat(W, HC32))],
  ['sha256(HC32|W)',        W => sha256(cat(HC32, W))],
  ['sha512(W|HC33)[:32]',   W => sha512(cat(W, HC)).subarray(0, 32)],
  ['sha512(HC33|W)[:32]',   W => sha512(cat(HC, W)).subarray(0, 32)],
  ['hmac(HC33,W)',          W => hmac(HC, W)],
  ['hmac(W,HC33)',          W => hmac(W, HC)],
  ['hmac(HC32,W)',          W => hmac(HC32, W)],
  ['hmac(W,HC32)',          W => hmac(W, HC32)],
  ['hmac(W,W)',             W => hmac(W, W)],
  ['W xor HC32',            W => xor(W, HC32)],
  ['sha256(W xor HC32)',    W => sha256(xor(W, HC32))],
  ['sha256(W|W)',           W => sha256(cat(W, W))],
  ['aes256ecb(HC32,W)',     W => ecb(HC32, W)],
  ['aes256ecb(W,HC32)',     W => ecb(W, HC32)],
  ['sha256(W|HC16a)',       W => sha256(cat(W, HC16a))],
  ['sha256(W|HC16b)',       W => sha256(cat(W, HC16b))],
  ['sha256(sha1(W)|sha1(HC32))', W => sha256(cat(sha1(W), sha1(HC32)))],
];

const want = KEY.toString('hex');
let tried = 0, hit = false;

for (const path of blobs) {
  let buf;
  try { buf = fs.readFileSync(path); } catch { continue; }
  const name = path.split('/').pop();
  for (let o = 0; o + 32 <= buf.length; o++) {
    const W = buf.subarray(o, o + 32);
    for (const [kname, fn] of KDFS) {
      tried++;
      let out;
      try { out = fn(W); } catch { continue; }
      if (out && out.length >= 32 && out.subarray(0, 32).toString('hex') === want) {
        hit = true;
        console.log(`\n*** KDF MATCH ***`);
        console.log(`  key      = ${want}`);
        console.log(`  KDF      = ${kname}`);
        console.log(`  secret W = ${W.toString('hex')}`);
        console.log(`  location = ${name} + 0x${o.toString(16)}`);
      }
    }
  }
}

console.log(`\ntried ${tried} (window, KDF) combinations across ${blobs.length} blob(s)`);
if (!hit) {
  console.log('no KDF in the battery maps any 32-byte window to the key.');
  console.log('Next: capture a handshake + memory dump in one session, recover');
  console.log('client_priv, compute the real X25519 shared secret, and either');
  console.log('extend this battery or trace the KDF function directly.');
  process.exit(3);
}
