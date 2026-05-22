// Stick-DE3 DMX cipher — per-session AES-256 key derivation (KDF).
//
// ════════════════════════════════════════════════════════════════════════
// RECOVERED 2026-05-21 by pure static RE (Ghidra) of the 2024-03-21 ESA2
// HardwareManager. This is the LAST blocker for a standalone plugin: it lets
// the plugin derive its own per-session key without the Hardware Manager.
//
// Call chain (ESA2 file addrs):
//   on_listWidgetDevice_itemSelectionChanged
//    → FUN_100178030 → FUN_100107650  (the KDF)
//        ├ vt[0x28] FUN_1001c0a50  opcode 0x10  — query Stick crypto state
//        ├ FUN_1004032b0           — generate ephemeral P-256 keypair
//        ├ vt[0x20] FUN_1001c0650  opcode 0x0F  — exchange public keys
//        ├ vt[0x38] FUN_100180e90  — return hardcoded static point (33B)
//        ├ FUN_100402ab0           — SEC1 decompress the static point
//        ├ FUN_1003ff3c0  ×2       — P-256 scalar multiply
//        └ FUN_1003f5740 / FUN_1003f4530 — install 32B key at cipher+0x48/+0x68
//
// THE KDF (FUN_100107650), in full:
//   1. d   = random scalar mod n            (ephemeral private key)
//   2. our = d · G                          (our ephemeral public key)
//   3. send `our`, receive Stick pubkey `Q` (opcode 0x0F handshake)
//   4. S   = decompress(STATIC_POINT_33B)   (hardcoded, baked into the app)
//   5. AES-256 key = X(d · S)  XOR  X(d · Q)
//
//   It is a TWO-DH construction: one DH against a fixed/pre-shared key `S`
//   (authenticates the app) and one against the Stick's per-session key `Q`
//   (gives forward secrecy). The Stick computes the identical key as
//   X(s·our) XOR X(e·our), where s,e are its static/ephemeral privates —
//   the two agree by ECDH symmetry.
//
// CURVE: NIST P-256 / secp256r1 / prime256v1. Confirmed three ways from the
// binary: prime p, order n, and base point G all byte-match P-256, and the
// curve `b` constant 5ac635d8…27d2604b is added during point decompression.
//
// ENDIANNESS: the Stick stores/wires every 256-bit coordinate as
// little-endian limbs (byte 0 = least-significant). Node's `crypto` works in
// big-endian (SEC1), so we byte-reverse at every boundary. The installed AES
// key is the little-endian form of  X(d·S) XOR X(d·Q).
//
//   ✓ VERIFIED end-to-end (2026-05-21): this derivation reproduces the exact
//   AES-256 key installed in a real captured session — checked against an
//   lldb-dumped ephemeral `d` + the Stick pubkey from the handshake pcap.
//   See tools/verify-kdf.mjs.
// ════════════════════════════════════════════════════════════════════════
//
// Usage:  node tools/derive-dmx-key.mjs            (runs the self-test)

import crypto from 'node:crypto';

// ── P-256 domain parameters (standard; matched against the binary) ──────────
export const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn, // -3 mod p
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

// ── The hardcoded static public point S, recovered from the binary ──────────
// A 33-byte SEC1-compressed P-256 point stored VERBATIM at file offset
// 0x7b0490 (vmaddr 0x1007b0490). prefix 0x03 => odd Y. vt[0x38] hands this
// raw buffer straight to the SEC1 decompressor. (An earlier RE pass XOR-masked
// these bytes with 0x51,0x52,… — that produced a different value used
// elsewhere in the app; it is NOT the KDF static point. The raw bytes below
// are the ones that reproduce a real session's key — see verify-kdf.mjs.)
export const STATIC_POINT_COMPRESSED = Buffer.from(
  '0328081290396d063e5114526ed978b926558f6ba1c96ad2facf76fffb3ffea0fe', 'hex');
export const STATIC_POINT_X = STATIC_POINT_COMPRESSED.subarray(1, 33).toString('hex');

// ── helpers ─────────────────────────────────────────────────────────────────
const rev = (b) => Buffer.from(b).reverse();
const pad32 = (b) => (b.length >= 32 ? b.subarray(b.length - 32) : Buffer.concat([Buffer.alloc(32 - b.length), b]));

/** SEC1-decompress a 33-byte compressed point to a 65-byte uncompressed point. */
export function decompressPoint(compressed33) {
  const { p, a, b } = P256;
  const prefix = compressed33[0];
  const x = BigInt('0x' + compressed33.subarray(1, 33).toString('hex'));
  const rhs = (((x * x % p) * x % p) + a * x % p + b) % p;
  let y = modpow(rhs, (p + 1n) / 4n, p);          // p ≡ 3 (mod 4)
  if ((y * y) % p !== rhs) throw new Error('static point X is not on P-256');
  if ((y & 1n) !== BigInt(prefix & 1)) y = p - y; // pick parity from prefix bit0
  const hex = (v) => v.toString(16).padStart(64, '0');
  return Buffer.from('04' + hex(x) + hex(y), 'hex');
}

function modpow(base, exp, mod) {
  let r = 1n; base %= mod;
  while (exp > 0n) { if (exp & 1n) r = r * base % mod; base = base * base % mod; exp >>= 1n; }
  return r;
}

// ── wire encoding for the opcode-0x0F public-key exchange ────────────────────
// On the wire each point is 64 bytes: X (little-endian) ‖ Y (little-endian).

/** uncompressed SEC1 point (65B, 0x04‖Xbe‖Ybe) → 64-byte little-endian wire form */
export function pointToWire(uncompressed65) {
  const xbe = uncompressed65.subarray(1, 33);
  const ybe = uncompressed65.subarray(33, 65);
  return Buffer.concat([rev(xbe), rev(ybe)]);
}

/** 64-byte little-endian wire point → uncompressed SEC1 point (65B) for node crypto */
export function wireToPoint(wire64) {
  const xbe = rev(wire64.subarray(0, 32));
  const ybe = rev(wire64.subarray(32, 64));
  return Buffer.concat([Buffer.from([0x04]), xbe, ybe]);
}

// ── the KDF ─────────────────────────────────────────────────────────────────

/** Create the ephemeral P-256 keypair (step 1–2 of the KDF). */
export function makeEphemeral() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

/**
 * Derive the per-session AES-256 key.
 *   key = LE( X(d·S)  XOR  X(d·Q) )
 * @param ecdh         our ephemeral ECDH object (the private scalar d)
 * @param stickPub65   the Stick's public key Q, uncompressed (65B, 0x04‖X‖Y)
 * @returns 32-byte Buffer — the AES-256 key as the Stick installs it
 */
export function deriveDmxKey(ecdh, stickPub65) {
  const S = decompressPoint(STATIC_POINT_COMPRESSED);
  const x1 = pad32(ecdh.computeSecret(S));          // X(d·S), big-endian
  const x2 = pad32(ecdh.computeSecret(stickPub65)); // X(d·Q), big-endian
  const xorBE = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) xorBE[i] = x1[i] ^ x2[i];
  return rev(xorBE); // Stick stores the key in little-endian limb order
}

// ── self-test ────────────────────────────────────────────────────────────────
function selfTest() {
  let ok = true;
  const check = (name, cond) => { console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`); ok &&= cond; };

  console.log('Stick-DE3 DMX key-derivation — self-test\n');

  // 1. static point is valid on P-256
  const S = decompressPoint(STATIC_POINT_COMPRESSED);
  check('static point S decompresses & lies on P-256', S.length === 65 && S[0] === 0x04);

  // 2. ECDH symmetry: client and Stick derive the SAME key.
  //    The real S has an unknown private; model it with a generated keypair.
  const staticKp = crypto.createECDH('prime256v1'); staticKp.generateKeys();   // (s, S)
  const stickEph = crypto.createECDH('prime256v1'); stickEph.generateKeys();   // (e, Q)
  const Spub = staticKp.getPublicKey(null, 'uncompressed');
  const Qpub = stickEph.getPublicKey(null, 'uncompressed');

  const client = makeEphemeral();                       // (d, our)
  const ourPub = client.getPublicKey(null, 'uncompressed');

  // client side: X(d·S) XOR X(d·Q)
  const clientKey = (() => {
    const x1 = pad32(client.computeSecret(Spub));
    const x2 = pad32(client.computeSecret(Qpub));
    const o = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) o[i] = x1[i] ^ x2[i];
    return rev(o);
  })();
  // stick side: X(s·our) XOR X(e·our)
  const stickKey = (() => {
    const x1 = pad32(staticKp.computeSecret(ourPub));
    const x2 = pad32(stickEph.computeSecret(ourPub));
    const o = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) o[i] = x1[i] ^ x2[i];
    return rev(o);
  })();
  check('client & Stick derive identical key (ECDH symmetry)', clientKey.equals(stickKey));
  check('derived key is 32 bytes (AES-256)', clientKey.length === 32);

  // 3. wire round-trip
  const wire = pointToWire(Qpub);
  check('point ⇄ wire round-trips', wireToPoint(wire).equals(Qpub) && wire.length === 64);

  // 4. exercise deriveDmxKey() with the REAL static point
  const k = deriveDmxKey(makeEphemeral(), Qpub);
  check('deriveDmxKey() runs with real S, yields 32B', k.length === 32);

  console.log(`\n${ok ? 'ALL TESTS PASSED' : 'TESTS FAILED'}`);
  process.exit(ok ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) selfTest();
