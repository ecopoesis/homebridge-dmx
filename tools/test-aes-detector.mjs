// Self-test for the AES-128 key-schedule detector used by Path A.
//
// Validates the detector in BOTH scan-aes-schedule.mjs (JS) and
// lldb-pathA-scan.py (Python) against the FIPS-197 Appendix A.1 known
// answer, plus an independent key-expansion generator and a negative case.
//
//   node tools/test-aes-detector.mjs

import { execFileSync } from 'node:child_process';
import { scheduleKey, SBOX, RCON } from './scan-aes-schedule.mjs';

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else      { fail++; console.log(`  FAIL ${name}`); }
}

// FIPS-197 Appendix A.1: key expansion for this 128-bit key.
const KEY = '2b7e151628aed2a6abf7158809cf4f3c';
// The full 176-byte forward key schedule (w[0]..w[43]) from FIPS-197 A.1.
const FIPS_SCHEDULE =
  '2b7e151628aed2a6abf7158809cf4f3c' + 'a0fafe1788542cb123a339392a6c7605' +
  'f2c295f27a96b9435935807a7359f67f' + '3d80477d4716fe3e1e237e446d7a883b' +
  'ef44a541a8525b7fb671253bdb0bad00' + 'd4d1c6f87c839d87caf2b8bc11f915bc' +
  '6d88a37a110b3efddbf98641ca0093fd' + '4e54f70e5f5fc9f384a64fb24ea6dc4f' +
  'ead27321b58dbad2312bf5607f8d292f' + 'ac7766f319fadc2128d12941575c006e' +
  'd014f9a8c9ee2589e13f0cc8b6630ca6';

// --- independent AES-128 key-expansion generator -------------------------
function expandKey128(key) {
  const out = Buffer.alloc(176);
  key.copy(out, 0);
  for (let i = 4; i < 44; i++) {
    const prev = out.subarray(4 * (i - 1), 4 * i);
    let t = [prev[0], prev[1], prev[2], prev[3]];
    if (i % 4 === 0) {
      t = [t[1], t[2], t[3], t[0]];               // RotWord
      t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]; // SubWord
      t[0] ^= RCON[i / 4 - 1];                    // Rcon
    }
    for (let k = 0; k < 4; k++)
      out[4 * i + k] = out[4 * (i - 4) + k] ^ t[k];
  }
  return out;
}

const keyBuf = Buffer.from(KEY, 'hex');
const fipsBuf = Buffer.from(FIPS_SCHEDULE, 'hex');

console.log('FIPS-197 length check:');
check('176-byte schedule vector', fipsBuf.length === 176);

console.log('\nindependent generator vs FIPS-197 known answer:');
const gen = expandKey128(keyBuf);
check('expandKey128(key) === FIPS-197 schedule', gen.equals(fipsBuf));

console.log('\nJS detector (scheduleKey):');
const k1 = scheduleKey(fipsBuf, 0);
check('recovers key from FIPS-197 schedule @ offset 0',
      k1 != null && k1.toString('hex') === KEY);

// embedded at a non-zero offset inside a larger buffer of noise
const wrap = Buffer.concat([Buffer.alloc(32, 0xAB), fipsBuf, Buffer.alloc(48, 0xCD)]);
let foundOff = -1, foundKey = null;
for (let o = 0; o + 176 <= wrap.length; o++) {
  const kk = scheduleKey(wrap, o);
  if (kk) { foundOff = o; foundKey = kk; }
}
check('finds schedule embedded at offset 32',
      foundOff === 32 && foundKey && foundKey.toString('hex') === KEY);

console.log('\nnegative case (random data must NOT match):');
const noise = Buffer.alloc(4096);
for (let i = 0; i < noise.length; i++) noise[i] = (i * 2654435761) & 0xff;
let falsePos = 0;
for (let o = 0; o + 176 <= noise.length; o++) if (scheduleKey(noise, o)) falsePos++;
check('zero false positives on 4 KiB of pseudo-random data', falsePos === 0);

console.log('\nPython detector (lldb-pathA-scan.py: aes128_schedule_check):');
try {
  const pyScript = `
import importlib.util
spec = importlib.util.spec_from_file_location("p", "tools/lldb_pathA_scan.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
k = m.aes128_schedule_check(bytes.fromhex("${FIPS_SCHEDULE}"))
print(k.hex() if k else "NONE")
bad = m.aes128_schedule_check(bytes([(i*7)&0xff for i in range(176)]))
print("NONE" if bad is None else bad.hex())
`;
  const out = execFileSync('python3', ['-c', pyScript], { encoding: 'utf8' }).trim().split('\n');
  check('Python recovers key from FIPS-197 schedule', out[0] === KEY);
  check('Python rejects non-schedule data', out[1] === 'NONE');
} catch (e) {
  fail++;
  console.log(`  FAIL python parity test: ${e.message}`);
}

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
