import * as net from 'net';
import * as dgram from 'dgram';
import * as crypto from 'crypto';

const STICK_HOST = '192.168.96.2';
const STICK_PORT = 2431;
const MAGIC_CLIENT = Buffer.from('LSAG_ALL');
const MAGIC_STICK = Buffer.from('Stick_3A');

function hexDump(label: string, buf: Buffer, maxLen = 128) {
  console.log(`\n--- ${label} (${buf.length} bytes) ---`);
  const len = Math.min(buf.length, maxLen);
  for (let i = 0; i < len; i += 16) {
    const hex = [];
    for (let j = 0; j < 16; j++) {
      if (i + j < len) hex.push(buf[i + j].toString(16).padStart(2, '0'));
      else hex.push('  ');
    }
    console.log(`  ${i.toString(16).padStart(4, '0')}  ${hex.join(' ')}`);
  }
}

class StickConnection {
  private sock: net.Socket;
  private recvBuf = Buffer.alloc(0);
  private resolveRead: ((buf: Buffer) => void) | null = null;
  private readTarget = 0;
  buffered = 0;

  constructor() {
    this.sock = new net.Socket();
    this.sock.on('data', (data) => {
      this.recvBuf = Buffer.concat([this.recvBuf, data]);
      this.buffered = this.recvBuf.length;
      this.checkRead();
    });
  }

  private checkRead() {
    if (this.resolveRead && this.recvBuf.length >= this.readTarget) {
      const result = this.recvBuf.subarray(0, this.readTarget);
      this.recvBuf = this.recvBuf.subarray(this.readTarget);
      this.buffered = this.recvBuf.length;
      const resolve = this.resolveRead;
      this.resolveRead = null;
      resolve(result);
    }
  }

  read(n: number, timeout = 5000): Promise<Buffer> {
    if (this.recvBuf.length >= n) {
      const result = this.recvBuf.subarray(0, n);
      this.recvBuf = this.recvBuf.subarray(n);
      this.buffered = this.recvBuf.length;
      return Promise.resolve(result);
    }
    return new Promise((resolve, reject) => {
      this.readTarget = n;
      this.resolveRead = resolve;
      const timer = setTimeout(() => {
        this.resolveRead = null;
        reject(new Error(`timeout reading ${n} bytes, have ${this.recvBuf.length}`));
      }, timeout);
      this.resolveRead = (buf) => {
        clearTimeout(timer);
        resolve(buf);
      };
    });
  }

  async readMessage(): Promise<{ opcode: number; seq: number; payload: Buffer }> {
    const header = await this.read(10);
    const opcode = header.readUInt8(8) | (header.readUInt8(9) << 8);
    if (opcode === 0xc9) {
      const data = await this.read(48);
      return { opcode, seq: 0, payload: data };
    } else if (opcode === 0x25) {
      const data = await this.read(30);
      return { opcode, seq: 0, payload: data };
    } else if (opcode === 0x47) {
      const data = await this.read(44);
      return { opcode, seq: data.readUInt16LE(0), payload: data.subarray(8) };
    } else if (opcode === 0x48) {
      const data = await this.read(12);
      return { opcode, seq: data.readUInt16LE(0), payload: data.subarray(8) };
    } else if (opcode === 0x011c) {
      const ack = await this.read(12);
      const payloadLen = ack.readUInt16LE(8);
      const payload = await this.read(payloadLen);
      return { opcode, seq: ack.readUInt16LE(0), payload };
    } else {
      const data = await this.read(8);
      return { opcode, seq: data.readUInt16LE(0), payload: data.subarray(6) };
    }
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sock.connect(STICK_PORT, STICK_HOST, resolve);
      this.sock.once('error', reject);
    });
  }

  send(data: Buffer) { this.sock.write(data); }
  close() { this.sock.destroy(); }
}

function buildPacket(magic: Buffer, opcode: number, seq: number, payload?: Buffer): Buffer {
  const header = Buffer.alloc(18);
  magic.copy(header, 0);
  header.writeUInt16LE(opcode, 8);
  header.writeUInt16LE(seq, 10);
  if (payload) return Buffer.concat([header, payload]);
  return header;
}

async function doHandshake(conn: StickConnection): Promise<Buffer> {
  // Hello
  const helloPacket = buildPacket(MAGIC_CLIENT, 0x47, 1);
  conn.send(helloPacket);

  let helloResp = await conn.readMessage();
  while (helloResp.opcode === 0x25) {
    helloResp = await conn.readMessage();
  }
  if (helloResp.opcode !== 0x47) throw new Error(`Expected 0x47, got 0x${helloResp.opcode.toString(16)}`);

  const stickPubKey = helloResp.payload.subarray(4, 36);
  console.log(`Stick pubkey: ${stickPubKey.toString('hex')}`);

  // ECDH
  const clientKeys = crypto.generateKeyPairSync('x25519');
  const clientPubRaw = clientKeys.publicKey.export({ type: 'spki', format: 'der' });
  const clientPubKey = clientPubRaw.subarray(clientPubRaw.length - 32);

  const stickPubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), stickPubKey]),
    format: 'der',
    type: 'spki',
  });
  const sharedSecret = crypto.diffieHellman({
    privateKey: clientKeys.privateKey,
    publicKey: stickPubKeyObj,
  });
  console.log(`Shared secret: ${sharedSecret.toString('hex')}`);

  // Key exchange
  const softwareName = Buffer.alloc(32);
  Buffer.from('software').copy(softwareName);
  const keyExPayload = Buffer.concat([softwareName, stickPubKey, clientPubKey]);
  conn.send(buildPacket(MAGIC_CLIENT, 0x48, 7, keyExPayload));
  const keyExResp = await conn.readMessage();
  console.log(`Key exchange: opcode=0x${keyExResp.opcode.toString(16)}`);

  // Init
  conn.send(Buffer.from([...MAGIC_STICK, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00]));

  // Device query
  conn.send(Buffer.from([...MAGIC_STICK, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00]));
  const devResp = await conn.readMessage();
  console.log(`Device: opcode=0x${devResp.opcode.toString(16)}`);

  // Session setup
  conn.send(buildPacket(MAGIC_STICK, 0x011c, 8, Buffer.from([0x15, 0x00, 0x16, 0x00])));
  const sessResp = await conn.readMessage();
  console.log(`Session: opcode=0x${sessResp.opcode.toString(16)}`);

  // Drain extras
  await new Promise(r => setTimeout(r, 500));
  while (conn.buffered > 0) {
    await conn.readMessage().catch(() => null);
  }

  return sharedSecret;
}

function buildDmxFrame(
  seq: number,
  counter: number,
  dmx: Buffer, // 512-byte DMX universe
  key: Buffer, // 32-byte AES-256 key
  ivStrategy: string,
): Buffer {
  const frame = Buffer.alloc(576);

  // Header (bytes 0-31, plaintext)
  MAGIC_STICK.copy(frame, 0);         // 0-7: "Stick_3A"
  frame.writeUInt16LE(0x19, 8);       // 8-9: opcode
  frame.writeUInt16LE(seq, 10);       // 10-11: sequence
  // 12-17: zeros (reserved)
  frame[18] = 0x00;
  frame[19] = 0x00;
  frame[20] = 0x00;
  frame[21] = 0x02;
  frame[22] = 0x64;                   // 0x64 = 100
  frame[23] = counter & 0xFF;         // incrementing counter

  // Plaintext for encryption (bytes 32-575 = 544 bytes)
  // First 32 bytes: header/metadata within encrypted region
  // Then 512 bytes: DMX universe
  const plaintext = Buffer.alloc(544);
  // The first 16 bytes of plaintext might be a timestamp or sequence info
  // Try different layouts
  dmx.copy(plaintext, 32); // DMX data at offset 32 within encrypted region

  // Generate IV based on strategy
  let iv: Buffer;
  switch (ivStrategy) {
    case 'zeros':
      iv = Buffer.alloc(16);
      break;
    case 'header':
      // Use bytes 8-23 of the frame header as IV
      iv = frame.subarray(8, 24);
      break;
    case 'counter':
      // IV = sequence number padded to 16 bytes
      iv = Buffer.alloc(16);
      iv.writeUInt16LE(seq, 0);
      break;
    case 'counter-be':
      iv = Buffer.alloc(16);
      iv.writeUInt32BE(seq, 12);
      break;
    case 'bytes24-31':
      // Maybe bytes 24-39 of the frame are the IV (not encrypted, just overwritten)
      iv = Buffer.alloc(16);
      break;
    default:
      iv = Buffer.alloc(16);
  }

  // AES-128-CBC encrypt (16-byte key)
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  cipher.setAutoPadding(false); // No padding, exact 544 bytes
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  encrypted.copy(frame, 32);

  return frame;
}

const SERIAL = '685678';
const PASSWORD = '%$uy}g!B';

// AES-128 → 16-byte keys
const sha16 = (b: Buffer) => crypto.createHash('sha256').update(b).digest().subarray(0, 16);
const md5b = (b: Buffer) => crypto.createHash('md5').update(b).digest();
const S = Buffer.from(SERIAL);
const P = Buffer.from(PASSWORD);

function deriveKeys(sharedSecret: Buffer): { name: string; key: Buffer }[] {
  return [
    { name: 'shared[:16]', key: sharedSecret.subarray(0, 16) },
    { name: 'md5(shared)', key: md5b(sharedSecret) },
    { name: 'sha16(shared)', key: sha16(sharedSecret) },
    { name: 'md5(shared+serial)', key: md5b(Buffer.concat([sharedSecret, S])) },
    { name: 'md5(shared+pwd)', key: md5b(Buffer.concat([sharedSecret, P])) },
    { name: 'md5(shared+serial+pwd)', key: md5b(Buffer.concat([sharedSecret, S, P])) },
    { name: 'md5(shared+pwd+serial)', key: md5b(Buffer.concat([sharedSecret, P, S])) },
    { name: 'md5(serial+shared)', key: md5b(Buffer.concat([S, sharedSecret])) },
    { name: 'md5(pwd+shared)', key: md5b(Buffer.concat([P, sharedSecret])) },
    { name: 'sha16(shared+serial)', key: sha16(Buffer.concat([sharedSecret, S])) },
    { name: 'sha16(shared+pwd)', key: sha16(Buffer.concat([sharedSecret, P])) },
    { name: 'sha16(shared+pwd+serial)', key: sha16(Buffer.concat([sharedSecret, P, S])) },
    { name: 'hmac-md5(pwd,shared)', key: crypto.createHmac('md5', P).update(sharedSecret).digest() },
    { name: 'hmac-md5(shared,pwd)', key: crypto.createHmac('md5', sharedSecret).update(P).digest() },
    { name: 'hmac-sha256(pwd,shared)[:16]', key: crypto.createHmac('sha256', P).update(sharedSecret).digest().subarray(0, 16) },
    { name: 'shared_xor_md5pwd', key: (() => {
      const h = md5b(P);
      const r = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) r[i] = sharedSecret[i] ^ h[i];
      return r;
    })() },
  ];
}

async function main() {
  const args = process.argv.slice(2);
  const keyName = args[0] || 'all';
  const ivStrategy = args[1] || 'zeros';

  console.log('Connecting to Stick...');

  const conn = new StickConnection();
  await conn.connect();
  console.log('Connected. Doing handshake...');

  const sharedSecret = await doHandshake(conn);
  console.log(`Shared secret: ${sharedSecret.toString('hex')}`);

  const allKeys = deriveKeys(sharedSecret);

  const dmx = Buffer.alloc(512);
  dmx[5] = 255;  // ch6 = intensity
  dmx[8] = 255;  // ch9 = saturation
  dmx[9] = 85;   // ch10 = hue (green)

  const udp = dgram.createSocket('udp4');

  const keysToTry = keyName === 'all' ? allKeys : allKeys.filter(k => k.name === keyName);

  for (const { name, key } of keysToTry) {
    console.log(`\n--- Trying key: ${name} (iv=${ivStrategy}) ---`);
    console.log(`  key: ${key.toString('hex')}`);

    let seq = 0;
    let counter = 0;
    for (let i = 0; i < 200; i++) { // ~5 seconds worth at 40fps
      const frame = buildDmxFrame(seq, counter, dmx, key, ivStrategy);
      udp.send(frame, 0, 576, STICK_PORT, STICK_HOST);
      seq = (seq + 4) & 0xFFFF;
      counter = (counter + 1) & 0xFF;
      await new Promise(r => setTimeout(r, 25));
    }
    console.log(`  Sent 200 frames. Check light for GREEN.`);
    await new Promise(r => setTimeout(r, 2000));
  }

  console.log('\nAll keys tried.');
  udp.close();
  conn.close();
}

main().catch(console.error);
