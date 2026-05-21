// Test the hypothesis: the hardcoded 33-byte secret is the client's static
// X25519 private key (32 bytes + 1 flag/version byte). If so, the client
// public key sent in msg#3 should equal X25519(priv, base_point).

import * as crypto from 'node:crypto';

const HARDCODED = Buffer.from('527a5b46c56f3a5e670b4f0e338727d94737ec0fc4af0dba93a51d93965191d08f', 'hex');

// From captured handshake msg#2 (Stick→Client, opcode 0x47, bytes +0x16..+0x36)
const STICK_PUB = Buffer.from('966cb0a9667596d27c12abd2fe36ba95e390558bd9d072d5158cf7d7e1cea6d2', 'hex');

// From captured handshake msg#3 (Client→Stick, opcode 0x48, bytes +0x52..+0x72)
const CLIENT_PUB = Buffer.from('973a20b248501227162a0ad004836a015d76ade1c2186e20965ccb3d259d7ba0', 'hex');

console.log('HARDCODED (33B):');
console.log(' ', HARDCODED.toString('hex'));
console.log('  first 32B (candidate priv key):', HARDCODED.subarray(0, 32).toString('hex'));
console.log('  byte 33 (flag?):                0x' + HARDCODED[32].toString(16));
console.log();
console.log('STICK pubkey from msg#2:   ', STICK_PUB.toString('hex'));
console.log('CLIENT pubkey from msg#3:  ', CLIENT_PUB.toString('hex'));
console.log();

// Test 1: derive pubkey from hardcoded priv using X25519
// Node's crypto module: X25519 keys must be PKCS8 DER. Manual key gen.
function derivePub_x25519(priv32) {
  // Node 16+ supports X25519 via crypto.createPrivateKey with raw key import.
  const privKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),  // PKCS8 X25519 header
      priv32,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  // Export public via key derivation
  const pubKey = crypto.createPublicKey(privKey);
  const der = pubKey.export({ format: 'der', type: 'spki' });
  // Last 32 bytes of SPKI DER = raw public key
  return der.subarray(der.length - 32);
}

console.log('=== Test 1: X25519 — derive pub from hardcoded priv ===');
try {
  const pub = derivePub_x25519(HARDCODED.subarray(0, 32));
  console.log('  derived pub:   ', pub.toString('hex'));
  console.log('  client pub:    ', CLIENT_PUB.toString('hex'));
  console.log('  MATCH?         ', pub.equals(CLIENT_PUB) ? '✓ YES — X25519 confirmed' : '✗ NO');
  if (pub.equals(CLIENT_PUB)) {
    // Compute shared secret
    const sharedKey = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey({
        key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'), HARDCODED.subarray(0,32)]),
        format: 'der', type: 'pkcs8',
      }),
      publicKey: crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b656e032100','hex'), STICK_PUB]),
        format: 'der', type: 'spki',
      }),
    });
    console.log('\n=== SHARED SECRET (X25519 ECDH) ===');
    console.log('  shared:        ', sharedKey.toString('hex'));
    console.log('  SHA-256(shared)[:16] (candidate AES key):',
                crypto.createHash('sha256').update(sharedKey).digest().subarray(0, 16).toString('hex'));
    console.log('  raw shared[:16] (candidate AES key):     ', sharedKey.subarray(0, 16).toString('hex'));
  }
} catch (e) {
  console.log('  error:', e.message);
}

console.log();
console.log('=== Test 2: same with reverse byte order ===');
try {
  const priv = Buffer.from(HARDCODED.subarray(0, 32)).reverse();
  const pub = derivePub_x25519(priv);
  console.log('  derived pub:   ', pub.toString('hex'));
  console.log('  match client?: ', pub.equals(CLIENT_PUB) ? '✓ YES' : '✗ no');
} catch (e) {
  console.log('  error:', e.message);
}

console.log();
console.log('If Test 1 matches, the static-RE hardcoded secret IS the client priv key.');
console.log('From there, every session: shared = X25519(hardcoded_priv, stick_pub_from_msg2),');
console.log('then AES key = some_hash(shared) [TBD: SHA-256[:16], HKDF, raw[:16]…].');
console.log("If neither matches, ECC is on a different curve (P-256, Curve448) or priv");
console.log("isn't the hardcoded secret.");
