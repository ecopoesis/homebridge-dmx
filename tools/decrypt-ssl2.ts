import { readFileSync, writeFileSync } from 'node:fs'

// AraCrypt LFSR stream cipher - ported from HakanL's C# gist
// https://gist.github.com/HakanL/f67fb9452d086856f105d64bc13a3f46

class AraCrypt {
  private lfsrA = 0x13579BDF
  private lfsrB = 0x2468ACE0
  private lfsrC = 0xFDB97531

  private readonly maskA = 0x80000062
  private readonly maskB = 0x40000020
  private readonly maskC = 0x10000002
  private readonly rot0A = 0x7FFFFFFF
  private readonly rot0B = 0x3FFFFFFF
  private readonly rot0C = 0x0FFFFFFF
  private readonly rot1A = 0x80000000
  private readonly rot1B = 0xC0000000
  private readonly rot1C = 0xF0000000

  setKey(key: string): void {
    // Pad to at least 12 chars by repeating individual characters
    let seed = key
    let idx = 0
    while (seed.length < 12) {
      seed += seed[idx++]
    }

    // Reset LFSRs
    this.lfsrA = 0x13579BDF
    this.lfsrB = 0x2468ACE0
    this.lfsrC = 0xFDB97531

    // Distribute: chars 0-3 → A, chars 4-7 → B, chars 8-11 → C
    for (let i = 0; i < 4; i++) {
      this.lfsrA = (((this.lfsrA << 8) >>> 0) | seed.charCodeAt(i + 0)) >>> 0
      this.lfsrB = (((this.lfsrB << 8) >>> 0) | seed.charCodeAt(i + 4)) >>> 0
      this.lfsrC = (((this.lfsrC << 8) >>> 0) | seed.charCodeAt(i + 8)) >>> 0
    }

    if (this.lfsrA === 0) this.lfsrA = 0x13579BDF
    if (this.lfsrB === 0) this.lfsrB = 0x2468ACE0
    if (this.lfsrC === 0) this.lfsrC = 0xFDB97531
  }

  transformByte(input: number): number {
    let crypto = 0
    let outB = (this.lfsrB & 1) >>> 0
    let outC = (this.lfsrC & 1) >>> 0

    for (let i = 0; i < 8; i++) {
      if ((this.lfsrA & 1) !== 0) {
        // Clock A with feedback, then clock B
        this.lfsrA = ((((this.lfsrA ^ this.maskA) >>> 0) >>> 1) | this.rot1A) >>> 0
        if ((this.lfsrB & 1) !== 0) {
          this.lfsrB = ((((this.lfsrB ^ this.maskB) >>> 0) >>> 1) | this.rot1B) >>> 0
          outB = 1
        } else {
          this.lfsrB = ((this.lfsrB >>> 1) & this.rot0B) >>> 0
          outB = 0
        }
      } else {
        // Clock A without feedback, then clock C
        this.lfsrA = ((this.lfsrA >>> 1) & this.rot0A) >>> 0
        if ((this.lfsrC & 1) !== 0) {
          this.lfsrC = ((((this.lfsrC ^ this.maskC) >>> 0) >>> 1) | this.rot1C) >>> 0
          outC = 1
        } else {
          this.lfsrC = ((this.lfsrC >>> 1) & this.rot0C) >>> 0
          outC = 0
        }
      }
      crypto = ((crypto << 1) | (outB ^ outC)) & 0xFF
    }

    input = (input ^ crypto) & 0xFF
    if (input === 0) input = crypto
    return input
  }

  transform(data: Buffer): Buffer {
    const out = Buffer.alloc(data.length)
    for (let i = 0; i < data.length; i++) {
      out[i] = this.transformByte(data[i])
    }
    return out
  }
}

const keyCandidates = [
  'Daslight',
  'DasLight',
  'daslight',
  'DasCrypt',
  'DasCryptKey',
  'DasCryptV4',
  'Daslight4',
  'DAS',
  'Nicolaudie-Sunlite',
  'Nicolaudie-SUNLITE',
  'NICOLAUDIE-SUNLITE',
  'Nico-Sunlite',
  'NicolaudieSunlite',
  'Nicolaudie',
  'nicolaudie',
  'SUNLITE',
  'Sunlite',
  'SunliteSuite',
  'Sunlite Suite',
  'Daslight-Sunlite',
  'DaslightSunlite',
  'Daslight Sunlite',
]

const filePath = process.argv[2] || '/Applications/EsaPro2/ScanLibrary/_imported/WAC Lighting DC-WD05 Architectural.ssl2'
console.log(`Reading: ${filePath}`)
const data = readFileSync(filePath)
console.log(`File size: ${data.length} bytes`)
console.log(`First 16 bytes: ${Array.from(data.subarray(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`)

console.log(`\nTrying ${keyCandidates.length} key candidates...\n`)

for (const key of keyCandidates) {
  const crypt = new AraCrypt()
  crypt.setKey(key)
  const decrypted = crypt.transform(data)
  const head = decrypted.subarray(0, 100).toString('latin1')

  const isXml = head.includes('<?xml') || head.includes('<DLM') || head.includes('<DLMFILE')

  if (isXml) {
    console.log(`*** KEY FOUND: "${key}" ***`)
    console.log(`First 300 chars:\n${decrypted.subarray(0, 300).toString('latin1')}`)
    const outPath = filePath.replace('.ssl2', '.xml')
    writeFileSync(outPath, decrypted)
    console.log(`\nDecrypted XML written to: ${outPath}`)
    process.exit(0)
  } else {
    const preview = Array.from(decrypted.subarray(0, 12)).map(b =>
      b >= 32 && b < 127 ? String.fromCharCode(b) : '.'
    ).join('')
    console.log(`  "${key}" → ${preview}`)
  }
}

console.log('\nNo key matched. Dumping details for top candidates:\n')
for (const key of keyCandidates.slice(0, 6)) {
  const crypt = new AraCrypt()
  crypt.setKey(key)
  const decrypted = crypt.transform(data)
  console.log(`Key "${key}":`)
  console.log(`  hex: ${Array.from(decrypted.subarray(0, 40)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`)
  console.log(`  asc: ${Array.from(decrypted.subarray(0, 40)).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')}`)
}
