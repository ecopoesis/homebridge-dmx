import * as crypto from 'crypto';

const frameHex =
  '53746963 6b5f3341 19009600 00000000' +
  '00000000 00026400 a683d3d3 ca57966b' +
  '9eff43dc 8db5464f c0afc785 5bb424ad' +
  'fdb6a0ee 24df6433 cc952097 e1784c09' +
  'cd3c7b8b 83d5bdd3 ba136145 d4ff845a' +
  '23bd8d28 d218a5df 4c784c8b caee7100' +
  '0d586311 0e45051b edf184d4 23447235' +
  '1ee2acbd 21eb8db0 76c54d53 f45b3706' +
  '00445512 79ccf175 793483d9 98b6e1cb' +
  '47733211 1e602f0e aa460c71 7bfc62b8' +
  '9cc446b7 3db8a8bf 016de03b 8eed3e30' +
  'f9da8771 d263483e 4060b081 181edcd0' +
  '4ebc3994 48d5b784 0d42355a 32851c65' +
  '7ef9375f 841a93a1 8b3e3355 8c4f4cb6' +
  'a5d7824f ca89c958 97e787f0 ac0c7fcc' +
  '4ee08dcb 0e10eb40 43f35441 6bca415d' +
  '2a56502a 6c590b6b f7efe715 cba281ff' +
  'd0a123e7 c19d9fab 6a0f9d0c 285f3d58' +
  'ed34ac7d 0b555d78 9027f807 7b311b6a' +
  '9f0d4f1c 485c1742 84dc0c32 48e370d6' +
  '35cae307 bc5a7f9a f46132fc 15116b2a' +
  '9ef095bd b18d244a b15d9b3f 599250cd' +
  '72afb805 e987b4a0 45f8d417 2b3590a3' +
  '6b594f4a ed96fd0f e1bf3501 d1fb9df9' +
  '119a35a3 8195a827 0f064df5 1f629e0c' +
  'cb8ec788 28b31b78 005dd41a e40520b8' +
  '5905a399 7dbb18ba 49372652 7b34fba4' +
  'fd206b5d a6dab5ab e3ef6cb5 efbd4de8' +
  '3cbd6439 d41b45cf 77a5158a 901b68f6' +
  '99a2a8cb 7919b848 a5dd0b4d 40cbe049' +
  '6e500d65 ae1bc5d2 4fcf5b14 dbfc8f3d' +
  '44ceb25a 4f6a1685 ecc5467c 2d6c62c0' +
  'd4e079f2 25362b08 4f31924b e4eef009' +
  '37f7dc2b c03f0358 b7207ded 659d6388' +
  'b3261cb1 0774cafb 214c63db 95e9ad41' +
  '5ecb2455 7d54eb1c 9c03a27d 154e68b0';
const frame = Buffer.from(frameHex.replace(/ /g, ''), 'hex');
console.log(`Frame size: ${frame.length} bytes`);

const ciphertext = frame.subarray(32); // 544 bytes

const serial = '685678';
const password = '%$uy}g!B';

// AES-128 → all keys MUST be 16 bytes
const sha16 = (s: string | Buffer) => crypto.createHash('sha256').update(s).digest().subarray(0, 16);
const md5 = (s: string | Buffer) => crypto.createHash('md5').update(s).digest(); // 16 bytes
const pad16 = (s: string) => Buffer.concat([Buffer.from(s), Buffer.alloc(16)]).subarray(0, 16);

const keys: { name: string; key: Buffer }[] = [
  { name: 'NIST128 test (00-0f)', key: Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex') },
  { name: 'MD5(password)', key: md5(password) },
  { name: 'MD5(serial)', key: md5(serial) },
  { name: 'MD5(serial+password)', key: md5(serial + password) },
  { name: 'MD5(password+serial)', key: md5(password + serial) },
  { name: 'MD5(serial+":"+password)', key: md5(serial + ':' + password) },
  { name: 'MD5(password+":"+serial)', key: md5(password + ':' + serial) },
  { name: 'SHA256(password)[:16]', key: sha16(password) },
  { name: 'SHA256(serial)[:16]', key: sha16(serial) },
  { name: 'SHA256(serial+password)[:16]', key: sha16(serial + password) },
  { name: 'SHA256(password+serial)[:16]', key: sha16(password + serial) },
  { name: 'password padded16', key: pad16(password) },
  { name: 'serial padded16', key: pad16(serial) },
  { name: 'password+serial padded16', key: pad16(password + serial) },
  { name: 'MD5(serial_hex)', key: md5(Buffer.from('685678', 'hex')) },
  { name: 'SHA256(serial_hex)[:16]', key: sha16(Buffer.from('685678', 'hex')) },
];

// IV strategies
function tryDecrypt(key: Buffer, iv: Buffer, label: string) {
  try {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Check if result looks like valid plaintext
    // DMX data should be at offset 32 within plaintext (512 bytes)
    // Most bytes should be 0 for an idle universe
    const dmxRegion = plain.subarray(32);
    let zeroCount = 0;
    for (let i = 0; i < dmxRegion.length; i++) {
      if (dmxRegion[i] === 0) zeroCount++;
    }
    const zeroPct = Math.round(100 * zeroCount / dmxRegion.length);

    // Show first 64 bytes of plaintext
    console.log(`\n${label}:`);
    console.log(`  zeros in DMX region: ${zeroCount}/${dmxRegion.length} (${zeroPct}%)`);
    console.log(`  first 64 bytes: ${plain.subarray(0, 64).toString('hex')}`);
    if (zeroPct > 80) {
      console.log(`  *** LIKELY VALID! ***`);
      console.log(`  full plaintext:`);
      for (let i = 0; i < plain.length; i += 32) {
        console.log(`    ${i.toString(16).padStart(4, '0')}: ${plain.subarray(i, Math.min(i + 32, plain.length)).toString('hex')}`);
      }
    }
  } catch (e: any) {
    console.log(`  ${label}: ERROR ${e.message}`);
  }
}

for (const { name, key } of keys) {
  const headerBytes = frame.subarray(24, 32); // bytes 24-31 from frame

  // Try various IVs
  tryDecrypt(key, Buffer.alloc(16), `${name} + IV=zeros`);
  tryDecrypt(key, Buffer.concat([headerBytes, Buffer.alloc(8)]), `${name} + IV=bytes24-31+zeros`);
  tryDecrypt(key, Buffer.concat([Buffer.alloc(8), headerBytes]), `${name} + IV=zeros+bytes24-31`);

  // IV from frame header fields
  const ivFromHeader = Buffer.alloc(16);
  frame.copy(ivFromHeader, 0, 8, 24); // bytes 8-23
  tryDecrypt(key, ivFromHeader, `${name} + IV=bytes8-23`);

  // IV = first 16 bytes of encrypted region (then decrypt remaining 528)
  const iv16 = ciphertext.subarray(0, 16);
  try {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv16);
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(ciphertext.subarray(16)), decipher.final()]);
    let zeroCount = 0;
    for (let i = 32; i < plain.length; i++) if (plain[i] === 0) zeroCount++;
    const zeroPct = Math.round(100 * zeroCount / (plain.length - 32));
    console.log(`\n${name} + IV=first16cipher (decrypt remaining 528):`);
    console.log(`  zeros: ${zeroCount}/${plain.length - 32} (${zeroPct}%)`);
    console.log(`  first 64: ${plain.subarray(0, 64).toString('hex')}`);
    if (zeroPct > 80) console.log(`  *** LIKELY VALID! ***`);
  } catch {}

  // Counter-based IV
  const seq = frame.readUInt16LE(10);
  const ivSeq = Buffer.alloc(16);
  ivSeq.writeUInt16LE(seq, 0);
  tryDecrypt(key, ivSeq, `${name} + IV=seq(${seq})`);

  ivSeq.fill(0);
  ivSeq.writeUInt32BE(seq, 12);
  tryDecrypt(key, ivSeq, `${name} + IV=seq_be(${seq})`);
}

console.log('\nDone.');
