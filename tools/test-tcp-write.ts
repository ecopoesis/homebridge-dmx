import * as net from 'net';
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
    const ascii = [];
    for (let j = 0; j < 16; j++) {
      if (i + j < len) {
        hex.push(buf[i + j].toString(16).padStart(2, '0'));
        const c = buf[i + j];
        ascii.push(c >= 32 && c < 127 ? String.fromCharCode(c) : '.');
      } else {
        hex.push('  ');
      }
    }
    console.log(`  ${i.toString(16).padStart(4, '0')}  ${hex.join(' ')}  ${ascii.join('')}`);
  }
  if (buf.length > maxLen) console.log(`  ... (${buf.length - maxLen} more bytes)`);
}

class StickConnection {
  private sock: net.Socket;
  private recvBuf = Buffer.alloc(0);
  private resolveRead: ((buf: Buffer) => void) | null = null;
  private readTarget = 0;

  constructor() {
    this.sock = new net.Socket();
    this.sock.on('data', (data) => {
      this.recvBuf = Buffer.concat([this.recvBuf, data]);
      this.checkRead();
    });
  }

  private checkRead() {
    if (this.resolveRead && this.recvBuf.length >= this.readTarget) {
      const result = this.recvBuf.subarray(0, this.readTarget);
      this.recvBuf = this.recvBuf.subarray(this.readTarget);
      const resolve = this.resolveRead;
      this.resolveRead = null;
      resolve(result);
    }
  }

  read(n: number, timeout = 5000): Promise<Buffer> {
    if (this.recvBuf.length >= n) {
      const result = this.recvBuf.subarray(0, n);
      this.recvBuf = this.recvBuf.subarray(n);
      return Promise.resolve(result);
    }
    return new Promise((resolve, reject) => {
      this.readTarget = n;
      this.resolveRead = resolve;
      const timer = setTimeout(() => {
        this.resolveRead = null;
        reject(new Error(`timeout reading ${n} bytes, have ${this.recvBuf.length}`));
      }, timeout);
      const origResolve = this.resolveRead;
      this.resolveRead = (buf) => {
        clearTimeout(timer);
        resolve(buf);
      };
    });
  }

  async readMessage(): Promise<{ opcode: number; seq: number; payload: Buffer }> {
    const header = await this.read(10);
    const magic = header.subarray(0, 8).toString();
    const opcode = header.readUInt8(8) | (header.readUInt8(9) << 8);

    // Different opcodes have different response sizes
    // Read the seq+reserved block (6 bytes minimum)
    if (opcode === 0xc9) {
      // Device info: 48 bytes after header
      const data = await this.read(48);
      return { opcode, seq: 0, payload: data };
    } else if (opcode === 0x25) {
      // Capability mask - variable, read remaining
      const data = await this.read(30);
      return { opcode, seq: 0, payload: data };
    } else if (opcode === 0x47) {
      // G hello response: 8 bytes ack + 36 bytes (4 + 32 pubkey)
      const data = await this.read(44);
      return { opcode, seq: data.readUInt16LE(0), payload: data.subarray(8) };
    } else if (opcode === 0x48) {
      // H key exchange ack: 8 bytes + 4 bytes
      const data = await this.read(12);
      return { opcode, seq: data.readUInt16LE(0), payload: data.subarray(8) };
    } else if (opcode === 0x011c) {
      // Session setup: 12 bytes ack then variable
      const ack = await this.read(12);
      const payloadLen = ack.readUInt16LE(8);
      if (payloadLen > 0) {
        const data = await this.read(payloadLen);
        return { opcode, seq: ack.readUInt16LE(0), payload: data };
      }
      return { opcode, seq: ack.readUInt16LE(0), payload: Buffer.alloc(0) };
    } else if (opcode === 0x70) {
      // DMX response: 12 bytes ack + 512 bytes state
      const ack = await this.read(12);
      const state = await this.read(512);
      return { opcode, seq: ack.readUInt16LE(0), payload: state };
    } else {
      // Unknown - try reading 12 bytes
      const data = await this.read(12).catch(() => Buffer.alloc(0));
      return { opcode, seq: 0, payload: data };
    }
  }

  send(buf: Buffer) {
    this.sock.write(buf);
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sock.connect(STICK_PORT, STICK_HOST, resolve);
      this.sock.on('error', reject);
    });
  }

  close() {
    this.sock.destroy();
  }

  get buffered() { return this.recvBuf.length; }
}

// Build a protocol packet: magic(8) + opcode(2) + seq(2) + reserved(6) + payload
function buildPacket(magic: Buffer, opcode: number, seq: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(18);
  magic.copy(header, 0);
  header.writeUInt8(opcode & 0xff, 8);
  header.writeUInt8((opcode >> 8) & 0xff, 9);
  header.writeUInt16LE(seq, 10);
  // bytes 12-17 are zero (reserved)
  return Buffer.concat([header, payload]);
}

async function main() {
  const conn = new StickConnection();
  await conn.connect();
  console.log('Connected to Stick');

  // Step 1: ECDH Hello (opcode G = 0x47)
  const helloPacket = buildPacket(MAGIC_CLIENT, 0x47, 6, Buffer.alloc(0));
  hexDump('SEND hello (G)', helloPacket);
  conn.send(helloPacket);

  let helloResp = await conn.readMessage();
  console.log(`RECV opcode=0x${helloResp.opcode.toString(16)} seq=${helloResp.seq}`);
  hexDump('hello payload', helloResp.payload);

  // Drain unsolicited 0x25 capability messages until we get the 0x47 hello
  while (helloResp.opcode === 0x25) {
    console.log('Got capability mask, reading next message...');
    helloResp = await conn.readMessage();
    console.log(`RECV opcode=0x${helloResp.opcode.toString(16)}`);
    hexDump('payload', helloResp.payload);
  }

  if (helloResp.opcode !== 0x47) {
    console.error(`Expected hello (0x47), got 0x${helloResp.opcode.toString(16)}`);
    conn.close();
    return;
  }

  // Extract Stick's ECDH public key (32 bytes, offset 4 in payload)
  const stickPubKey = helloResp.payload.subarray(4, 36);
  console.log(`Stick pubkey: ${stickPubKey.toString('hex')}`);

  // Step 2: Generate X25519 key pair
  const clientKeys = crypto.generateKeyPairSync('x25519');
  const clientPubRaw = clientKeys.publicKey.export({ type: 'spki', format: 'der' });
  const clientPubKey = clientPubRaw.subarray(clientPubRaw.length - 32);
  console.log(`Client pubkey: ${clientPubKey.toString('hex')}`);

  // Derive shared secret
  const stickPubKeyObj = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      stickPubKey,
    ]),
    format: 'der',
    type: 'spki',
  });
  const sharedSecret = crypto.diffieHellman({
    privateKey: clientKeys.privateKey,
    publicKey: stickPubKeyObj,
  });
  console.log(`Shared secret: ${sharedSecret.toString('hex')}`);

  // Step 3: Key exchange (opcode H = 0x48)
  const softwareName = Buffer.alloc(32);
  Buffer.from('software').copy(softwareName);
  const keyExPayload = Buffer.concat([softwareName, stickPubKey, clientPubKey]);
  const keyExPacket = buildPacket(MAGIC_CLIENT, 0x48, 7, keyExPayload);
  hexDump('SEND key exchange (H)', keyExPacket);
  conn.send(keyExPacket);

  const keyExResp = await conn.readMessage();
  console.log(`RECV opcode=0x${keyExResp.opcode.toString(16)}`);
  hexDump('key exchange response', keyExResp.payload);

  // Drain any unsolicited messages
  if (conn.buffered > 0) {
    console.log(`${conn.buffered} bytes buffered, reading...`);
    const extra = await conn.readMessage().catch(() => null);
    if (extra) console.log(`Extra message: opcode=0x${extra.opcode.toString(16)}`);
  }

  // Step 4: Init (opcode F = 0x46)
  const initPacket = Buffer.from([...MAGIC_STICK, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00]);
  hexDump('SEND init (F)', initPacket);
  conn.send(initPacket);

  // Step 5: Device query
  const queryPacket = Buffer.from([...MAGIC_STICK, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00]);
  hexDump('SEND device query', queryPacket);
  conn.send(queryPacket);

  const devResp = await conn.readMessage();
  console.log(`RECV opcode=0x${devResp.opcode.toString(16)} (device info)`);
  hexDump('device info', devResp.payload, 48);

  // Step 6: Session setup (opcode 0x011C)
  const sessionPayload = Buffer.from([0x15, 0x00, 0x16, 0x00]);
  const sessionPacket = buildPacket(MAGIC_STICK, 0x011c, 8, sessionPayload);
  hexDump('SEND session setup', sessionPacket);
  conn.send(sessionPacket);

  const sessResp = await conn.readMessage();
  console.log(`RECV opcode=0x${sessResp.opcode.toString(16)} (session)`);

  // Drain any extra messages
  await new Promise(r => setTimeout(r, 500));
  while (conn.buffered > 0) {
    const msg = await conn.readMessage().catch(() => null);
    if (msg) console.log(`Extra: opcode=0x${msg.opcode.toString(16)}, payload=${msg.payload.length} bytes`);
    else break;
  }

  // Step 7: Make fixture 2 RED
  // DMX addr 6 = intensity 255, addr 9 = saturation 255, addr 10 = hue 0 (red)
  console.log('\n=== Making fixture 2 RED ===');
  const writes: [number, number, string][] = [
    [6, 255, 'intensity'],
    [9, 255, 'saturation'],
    [10, 0,  'hue (red=0)'],
  ];

  let dmxSeq = 0x15;
  for (const [channel, value, label] of writes) {
    const payload = Buffer.from([value, 0x00, 0x00, 0x00, channel]);
    const packet = buildPacket(MAGIC_STICK, 0x70, dmxSeq++, payload);
    console.log(`  ch${channel} = ${value} (${label})`);
    conn.send(packet);
    await new Promise(r => setTimeout(r, 100));
  }
  console.log('All writes sent. Waiting 2s for Stick to process...');
  await new Promise(r => setTimeout(r, 2000));

  console.log('\nDone.');
  conn.close();
}

main().catch(console.error);
