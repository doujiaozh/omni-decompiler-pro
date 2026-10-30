// smoke test — exercises the engine on real samples (not part of the plugin)
import { decompile } from './lib/engine.js'
import { writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const tmp = 'D:\\Code\\omni-decompiler-pro\\.smoke'
if (!existsSync(tmp)) mkdirSync(tmp, { recursive: true })

// 1. minimal valid WASM module: one (main) function with empty body
const wasm = Buffer.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version 1
  0x01, 0x04, 0x01, 0x60, 0x00, 0x00,             // type section: ()->()
  0x03, 0x02, 0x01, 0x00,                         // function section: 1 func, type 0
  0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,             // code section: body = nop, end
])
writeFileSync(join(tmp, 'mini.wasm'), wasm)

// 2. minimal ELF64 header + one null section header entry (objdump-recognizable)
const elf = Buffer.alloc(128)
elf.write('\x7fELF', 0, 'ascii')
elf[4] = 2 // 64-bit
elf[5] = 1 // little endian
elf[6] = 1 // ELF version
elf.writeUInt16LE(1, 16) // ET_REL
elf.writeUInt16LE(0x3e, 18) // EM_X86_64
elf.writeUInt32LE(1, 20) // e_version
elf.writeUInt32LE(0, 32) // e_phoff (none)
elf.writeUInt32LE(64, 40) // e_shoff → section header table at 64
elf.writeUInt16LE(0, 54) // e_phentsize
elf.writeUInt16LE(0, 56) // e_phnum
elf.writeUInt16LE(64, 52) // e_ehsize
elf.writeUInt16LE(64, 58) // e_shentsize
elf.writeUInt16LE(1, 60) // e_shnum (incl. null section)
elf.writeUInt16LE(0, 62) // e_shstrndx
// section header table at offset 64: single zeroed entry (SHT_NULL)
writeFileSync(join(tmp, 'mini.elf'), elf)

// 3. fake APK: a ZIP whose central directory lists AndroidManifest.xml + classes.dex
function makeZip(entries) {
  const chunks = []
  const central = []
  let offset = 0
  for (const [name, data] of entries) {
    const nameBuf = Buffer.from(name, 'utf8')
    const local = Buffer.alloc(30)
    local.write('PK\x03\x04', 0, 'binary')
    local.writeUInt32LE(0, 6) // no compression
    local.writeUInt16LE(nameBuf.length, 26)
    local.writeUInt16LE(data.length, 28)
    chunks.push(local, nameBuf, Buffer.from(data))
    const cen = Buffer.alloc(46)
    cen.write('PK\x01\x02', 0, 'binary')
    cen.writeUInt16LE(nameBuf.length, 28)
    cen.writeUInt32LE(data.length, 34) // uncompressed
    cen.writeUInt32LE(data.length, 42) // uncompressed size dup
    cen.writeUInt32LE(offset, 42) // relative offset of local header
    central.push(cen, nameBuf)
    offset += local.length + nameBuf.length + data.length
  }
  const centralBuf = Buffer.concat(central)
  const end = Buffer.alloc(22)
  end.write('PK\x05\x06', 0, 'binary')
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralBuf.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([Buffer.concat(chunks), centralBuf, end])
}
const dex = Buffer.alloc(0x70)
dex.write('dex\n', 0, 'binary') // dex magic 0x64 0x65 0x78 0x0a
dex.writeUInt32LE(0x12345678, 8) // checksum
dex.writeUInt32LE(0x70, 32) // file_size
dex.writeUInt32LE(0x70, 36) // header_size
writeFileSync(join(tmp, 'classes.dex'), dex)
writeFileSync(join(tmp, 'fake.apk'), makeZip([
  ['AndroidManifest.xml', Buffer.from('<manifest package="com.example.smoke"/>')],
  ['classes.dex', dex],
]))

const config = {
  cacheDir: join(tmp, 'cache'),
  autoDownload: false, // exercise the fallback chain only
  commandTimeoutMs: 120000,
  maxOutputChars: 4000,
  keepWorkspace: false,
}

const targets = [
  ['D:\\mingw64\\bin\\libssp-0.dll', 'native PE → objdump'],
  [join(tmp, 'mini.wasm'), 'WASM → wabt (npm install expected, no net → fallback)'],
  [join(tmp, 'mini.elf'), 'ELF → objdump'],
  [join(tmp, 'fake.apk'), 'APK → jadx missing (no net) → archive recurse → strings'],
  [join(tmp, 'classes.dex'), 'DEX → jadx missing → strings'],
  ['D:\\Code\\omni-decompiler-pro\\package.json', 'text → strings fallback'],
]

for (const [file, label] of targets) {
  console.log('\n========== ' + label + ' ==========')
  try {
    const r = await decompile(file, config)
    console.log('format=' + r.format + ' engine=' + r.engine + ' ok=' + r.ok)
    console.log('summary: ' + r.summary)
    console.log('warnings: ' + JSON.stringify(r.warnings))
    console.log('info: ' + JSON.stringify(r.info))
    console.log('code[:600]:\n' + r.code.slice(0, 600))
  } catch (e) {
    console.log('THREW: ' + e.message)
  }
}
