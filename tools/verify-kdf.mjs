// Verify the recovered KDF against a real session — no hardware needed.
//
// Inputs (all from one captured session, 2026-05-21 20:48-20:51):
//   • the ephemeral private `d`  — Path D lldb watchpoint dumped the stack at
//     key-install time; d = FUN_100107650's local_48 = rsi-blob[0x40:0x60].
//   • the installed AES key      — Path D log + rsi-blob[0x00:0x20].
//   • the handshake pcap         — the TCP/2431 0x0F exchange of that session.
//
// The KDF claim:  key = LE( X(d·S) XOR X(d·Q) )
//   S = hardcoded static point, Q = Stick's pubkey from the handshake.
// We have d and key; we extract Q from the pcap and recompute. If the
// recomputed key equals the dumped key, the KDF is proven end-to-end.
//
// Usage: node tools/verify-kdf.mjs [rsi-blob] [pcap]

import fs from 'node:fs';
import { P256, STATIC_POINT_COMPRESSED } from './derive-dmx-key.mjs';

const RSI_BLOB = process.argv[2] || '/tmp/stick-pathD-blob-rsi_0x30a968b50.bin';
const PCAP     = process.argv[3] || 'tools/captures/handshake-20260521-204953.pcap';
const KNOWN_KEY = '01bb3e12b9f2081ee0a0100fcd4f1ad3e716b453b9c1a69c41ce63e9af8ad087';

// ── P-256 affine arithmetic (independent bigint impl) ───────────────────────
const { p, a, b, Gx, Gy } = P256;
const mod = (x) => ((x % p) + p) % p;
const inv = (x) => modpow(mod(x), p - 2n, p);
function modpow(base, e, m) {
  let r = 1n; base %= m;
  while (e > 0n) { if (e & 1n) r = r * base % m; base = base * base % m; e >>= 1n; }
  return r;
}
const onCurve = (P) => P && mod(P.y * P.y) === mod(P.x * P.x * P.x + a * P.x + b);
function dbl(P) {
  if (!P) return null;
  const l = mod((3n * P.x * P.x + a) * inv(2n * P.y));
  const x = mod(l * l - 2n * P.x);
  return { x, y: mod(l * (P.x - x) - P.y) };
}
function add(P, Q) {
  if (!P) return Q; if (!Q) return P;
  if (P.x === Q.x) return P.y === Q.y ? dbl(P) : null;
  const l = mod((Q.y - P.y) * inv(Q.x - P.x));
  const x = mod(l * l - P.x - Q.x);
  return { x, y: mod(l * (P.x - x) - P.y) };
}
function mul(k, P) {
  let R = null;
  for (let i = 255n; i >= 0n; i--) { R = dbl(R); if ((k >> i) & 1n) R = add(R, P); }
  return R;
}

// ── helpers ─────────────────────────────────────────────────────────────────
const G = { x: Gx, y: Gy };
const beHex = (v) => v.toString(16).padStart(64, '0');
const toLE = (v) => Buffer.from(beHex(v), 'hex').reverse();   // 32-byte LE limbs
const fromLE = (buf) => BigInt('0x' + Buffer.from(buf).reverse().toString('hex'));

function recoverY(x, evenParity) {
  const rhs = mod(x * x * x + a * x + b);
  let y = modpow(rhs, (p + 1n) / 4n, p);
  if (mod(y * y) !== rhs) return null;       // x not on the curve
  if ((y & 1n) !== (evenParity ? 0n : 1n)) y = p - y;
  return y;
}

// static point S — SEC1-decompress the raw 33-byte compressed point
const Sx = BigInt('0x' + STATIC_POINT_COMPRESSED.subarray(1, 33).toString('hex'));
const S = { x: Sx, y: recoverY(Sx, (STATIC_POINT_COMPRESSED[0] & 1) === 0) };

console.log('Stick-DE3 KDF — end-to-end verification\n');
let pass = true;
const t = (name, ok) => { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`); pass &&= ok; };

t('static point S is on P-256', onCurve(S));
t('generator G is on P-256', onCurve(G));

// ── load d, the ephemeral private ───────────────────────────────────────────
const blob = fs.readFileSync(RSI_BLOB);
const dumpedKey = blob.subarray(0, 32);
const d = fromLE(blob.subarray(0x40, 0x60));   // local_48, stored little-endian
t('dumped key matches Path D log', dumpedKey.toString('hex') === KNOWN_KEY);
console.log(`    d         = ${beHex(d)}`);
t('d is a valid scalar (0 < d < n)', d > 0n && d < P256.n);

// ── our public key = d·G ────────────────────────────────────────────────────
const ourPub = mul(d, G);
t('d·G is on P-256', onCurve(ourPub));
console.log(`    our pub.x = ${beHex(ourPub.x)}`);

// ── scan the pcap for every valid 64-byte P-256 point (X‖Y) ──────────────────
const pcap = fs.readFileSync(PCAP);
function scanPoints(endian) {
  const hits = [];
  for (let o = 0; o + 64 <= pcap.length; o++) {
    const xb = pcap.subarray(o, o + 32), yb = pcap.subarray(o + 32, o + 64);
    const x = endian === 'le' ? fromLE(xb) : BigInt('0x' + xb.toString('hex'));
    if (x === 0n || x >= p) continue;
    const y = endian === 'le' ? fromLE(yb) : BigInt('0x' + yb.toString('hex'));
    if (y === 0n || y >= p) continue;
    if (onCurve({ x, y })) hits.push({ o, x, y, endian });
  }
  return hits;
}
let hits = scanPoints('le');
let wireEndian = 'little-endian';
if (!hits.some((h) => h.x === ourPub.x)) {
  const be = scanPoints('be');
  if (be.some((h) => h.x === ourPub.x)) { hits = be; wireEndian = 'big-endian'; }
}
t('our pubkey d·G is present in the handshake pcap', hits.some((h) => h.x === ourPub.x));
console.log(`    wire point encoding = ${wireEndian}`);
console.log(`    valid P-256 points found in pcap: ${hits.length}`);

// ── candidate Stick pubkeys = pcap points that aren't ours ──────────────────
const candidates = hits.filter((h) => h.x !== ourPub.x);

// ── recompute the key for each candidate Q ──────────────────────────────────
function deriveKey(Q) {
  const xdS = toLE(mul(d, S).x);
  const xdQ = toLE(mul(d, Q).x);
  const k = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k[i] = xdS[i] ^ xdQ[i];
  return k;
}
let matchedQ = null;
for (const Q of candidates) {
  if (deriveKey(Q).toString('hex') === KNOWN_KEY) { matchedQ = Q; break; }
}
t('a pcap pubkey Q reproduces the exact installed key', matchedQ !== null);

if (matchedQ) {
  console.log(`\n  Stick pubkey Q (from pcap @ offset 0x${matchedQ.o.toString(16)}):`);
  console.log(`    Q.x = ${beHex(matchedQ.x)}`);
  console.log(`    Q.y = ${beHex(matchedQ.y)}`);
  console.log(`\n  key = LE( X(d·S) XOR X(d·Q) )`);
  console.log(`    recomputed = ${deriveKey(matchedQ).toString('hex')}`);
  console.log(`    installed  = ${KNOWN_KEY}`);
}

console.log(`\n${pass && matchedQ ? '✅ KDF VERIFIED END-TO-END — recovery is correct'
                                  : '❌ verification failed'}`);
process.exit(pass && matchedQ ? 0 : 1);
