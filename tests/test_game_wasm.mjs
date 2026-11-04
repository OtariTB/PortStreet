// tests/test_game_wasm.mjs - Genuine WebAssembly Engine Startup Test Harness
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WASI } from 'wasi';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const WASM_PATH = path.join(ROOT, 'build', 'game.wasm');
const CFG_PATH = path.join(ROOT, 'config', 'local.json');

function getNfsExePath() {
    if (fs.existsSync(CFG_PATH)) {
        try {
            const raw = fs.readFileSync(CFG_PATH, 'utf8').replace(/^\uFEFF/, '');
            const cfg = JSON.parse(raw);
            const p1 = path.join(cfg.game_root, 'Need For Spped - Pro Street', 'nfs.exe');
            if (fs.existsSync(p1)) return p1;
            const p2 = path.join(cfg.game_root, 'nfs.exe');
            if (fs.existsSync(p2)) return p2;
        } catch (e) {}
    }
    const defaultPaths = [
        'C:\\Users\\tabat\\OneDrive\\Desktop\\Need-for-Speed-Pro-Street-SteamRIP.com\\Need For Spped - Pro Street\\nfs.exe',
        'C:\\Games\\Pro Street\\Need For Spped - Pro Street\\nfs.exe',
    ];
    for (const p of defaultPaths) {
        if (fs.existsSync(p)) return p;
    }
    return defaultPaths[0];
}

const NFS_EXE_PATH = getNfsExePath();

function parsePEHeaders(buf) {
    const e_lfanew = buf.readUInt32LE(0x3c);
    const numSections = buf.readUInt16LE(e_lfanew + 6);
    const optHeaderSize = buf.readUInt16LE(e_lfanew + 20);
    const secHeadersOffset = e_lfanew + 24 + optHeaderSize;

    const sections = [];
    for (let i = 0; i < numSections; i++) {
        const off = secHeadersOffset + i * 40;
        let name = buf.toString('latin1', off, off + 8).replace(/\0.*$/, '');
        const virtSize = buf.readUInt32LE(off + 8);
        const virtAddr = buf.readUInt32LE(off + 12);
        const rawSize = buf.readUInt32LE(off + 16);
        const rawOffset = buf.readUInt32LE(off + 20);
        sections.push({ name, virtSize, virtAddr, rawSize, rawOffset });
    }
    return sections;
}

async function run() {
    console.log('=== PortSpeed WebAssembly Genuine Boot Diagnostic ===');
    console.log('WASM Module:', WASM_PATH);
    if (!fs.existsSync(WASM_PATH)) {
        console.error('[FATAL] build/game.wasm not found. Run tools/build_wasm.py first.');
        process.exit(1);
    }
    if (!fs.existsSync(NFS_EXE_PATH)) {
        console.error('[FATAL] Original nfs.exe not found at:', NFS_EXE_PATH);
        process.exit(1);
    }

    const wasi = new WASI({
        version: 'preview1',
        args: ['nfs.exe'],
        env: process.env,
    });

    const wasmBytes = fs.readFileSync(WASM_PATH);
    const module = new WebAssembly.Module(wasmBytes);
    const instance = new WebAssembly.Instance(module, {
        wasi_snapshot_preview1: wasi.wasiImport,
    });

    wasi.initialize(instance);

    console.log('[1/5] Calling fntab_init() to populate master dispatch table...');
    const t0 = Date.now();
    instance.exports.fntab_init();
    console.log(`      fntab_init completed in ${Date.now() - t0}ms`);

    console.log('[2/5] Loading authentic PE sections into WASM linear memory...');
    const exeBuf = fs.readFileSync(NFS_EXE_PATH);
    const sections = parsePEHeaders(exeBuf);
    const wasmMem = new Uint8Array(instance.exports.memory.buffer);

    for (const sec of sections) {
        if (sec.rawSize > 0 && sec.rawOffset > 0) {
            const data = exeBuf.subarray(sec.rawOffset, sec.rawOffset + sec.rawSize);
            const dst = 0x00400000 + sec.virtAddr;
            wasmMem.set(data, dst);
            console.log(`      Mapped ${sec.name.padEnd(8)} at 0x${dst.toString(16).padStart(8, '0')} (${(sec.rawSize / 1024).toFixed(1)} KB)`);
        }
    }

    // Set DOS header signature 'MZ' at 0x00400000
    wasmMem[0x00400000] = 0x4d; // 'M'
    wasmMem[0x00400001] = 0x5a; // 'Z'

    console.log('[3/5] Setting up TEB (0x00100000) and Guest Stack (0x003FF000)...');
    // TEB self-pointer at fs:[0x18]
    const dv = new DataView(instance.exports.memory.buffer);
    dv.setUint32(0x00100018, 0x00100000, true);
    // Stack base/limit in TEB
    dv.setUint32(0x00100004, 0x00400000, true); // StackBase
    dv.setUint32(0x00100008, 0x00200000, true); // StackLimit

    console.log('[4/5] Binding IAT shims and installing runtime hooks...');
    instance.exports.boot_bind_iats();
    instance.exports.boot_install_hooks();

    // Allocate guest CPU structure in reserved TEB/TLS page (0x00104000)
    // Non-overlapping with guest dynamic heap (0x02000000..0x28000000)
    const CPU_STRUCT_VA = 0x00104000;
    // Zero out CPU struct
    for (let i = 0; i < 512; i++) wasmMem[CPU_STRUCT_VA + i] = 0;
    // Set CPU fields:
    // esp (offset 16) = 0x003ff000
    dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true);
    // eip (offset 32) = 0x004afee0 (GUEST_MAIN_ENTRY_VA)
    dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);
    // fs_base (offset 36) = 0x00100000
    dv.setUint32(CPU_STRUCT_VA + 36, 0x00100000, true);

    console.log('[5/5] Executing genuine C++ static initializers in WebAssembly...');
    const t_init = Date.now();
    let current_ctor = 0, current_fn = 0;
    try {
        let count = 0;
        for (let p = 0x00967608; p < 0x0096a1f4; p += 4) {
            const fn_va = dv.getUint32(p, true);
            if (fn_va !== 0) {
                count++;
                current_ctor = count;
                current_fn = fn_va;
                const saved_esp = dv.getUint32(CPU_STRUCT_VA + 16, true);
                const esp_next = saved_esp - 4;
                dv.setUint32(CPU_STRUCT_VA + 16, esp_next, true);
                dv.setUint32(esp_next, 0x00828ae0, true);
                if (count % 50 === 0 && count < 169) {
                    fs.writeSync(1, `      ... reached Constructor #${count} (0x${fn_va.toString(16)})\n`);
                }
                if (count >= 169) {
                    fs.writeSync(1, `      -> [START] Constructor #${count} (0x${fn_va.toString(16)})...\n`);
                }
                const t_ctor_start = Date.now();
                instance.exports.dispatch_indirect(CPU_STRUCT_VA, fn_va);
                const t_ctor_elapsed = Date.now() - t_ctor_start;
                if (count === 169) {
                    const obj_count = dv.getUint32(0x00ab47e4, true);
                    const arr_ptr = dv.getUint32(0x00ab47e0 + 0x16c, true);
                    const ctor_count = arr_ptr !== 0 ? dv.getUint32(arr_ptr - 4, true) : 0;
                    const low_10c = dv.getUint8(0x10c);
                    const low_110 = dv.getUint32(0x110, true);
                    if (obj_count === 87 && arr_ptr >= 0x02000000 && arr_ptr < 0x28000000 && ctor_count === 87 && low_10c === 0 && low_110 === 0) {
                        fs.writeSync(1, `      [PASS] Constructor #169 completed! Descriptor count=[0xab47e4]=${obj_count}, Element array=[0xab494c]=0x${arr_ptr.toString(16)} (header count=${ctor_count}, size=${obj_count * 12 + 4} bytes), null-guard clean [${t_ctor_elapsed}ms]\n`);
                    } else {
                        fs.writeSync(1, `      [FAIL] Constructor #169 invalid state! count=${obj_count}, arr=0x${arr_ptr.toString(16)}, header=${ctor_count}, low_10c=${low_10c}, low_110=0x${low_110.toString(16)}\n`);
                        process.exit(1);
                    }
                } else if (count > 169) {
                    fs.writeSync(1, `      <- [DONE]  Constructor #${count} (0x${fn_va.toString(16)}) [${t_ctor_elapsed}ms]\n`);
                }
                dv.setUint32(CPU_STRUCT_VA + 16, saved_esp, true);
            }
        }
        console.log("      Constructors executed: " + count + " / 960 in " + (Date.now() - t_init) + "ms");
    } catch (err) {
        console.error(`[FAIL] Constructor #${current_ctor} (0x${current_fn.toString(16)}) trapped:`, err);
        dumpCPU(dv, CPU_STRUCT_VA);
        console.log('\n--- bChunk Pool Object State (0x00abb060) ---');
        const bchunk = 0x00abb060;
        console.log(`init_flag (+0x10c): ${dv.getUint8(bchunk + 0x10c)}`);
        console.log(`field_+0x100:      0x${dv.getUint32(bchunk + 0x100, true).toString(16)}`);
        console.log(`field_+0x104:      0x${dv.getUint32(bchunk + 0x104, true).toString(16)}`);
        console.log(`field_+0x108:      0x${dv.getUint32(bchunk + 0x108, true).toString(16)}`);
        console.log(`fastmem_ptr (+0x110): 0x${dv.getUint32(bchunk + 0x110, true).toString(16)}`);
        console.log(`fastmem_sz (+0x114):  0x${dv.getUint32(bchunk + 0x114, true).toString(16)}`);
        console.log(`fastmem_off (+0x118): 0x${dv.getUint32(bchunk + 0x118, true).toString(16)}`);
        console.log('First 8 buckets:');
        for (let b = 0; b < 8; b++) {
            console.log(`  bucket[${b}]: 0x${dv.getUint32(bchunk + b * 4, true).toString(16)}`);
        }
        process.exit(1);
    }

    console.log('[6/5] Setting up main() arguments and entering genuine ProStreet main()...');
    instance.exports.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);

    const t_main = Date.now();
    try {
        console.log('      Invoking sub_004afee0 via boot_invoke_main(dry_run = false)...');
        const rc = instance.exports.boot_invoke_main(CPU_STRUCT_VA, false);
        console.log(`      boot_invoke_main returned: ${rc} in ${Date.now() - t_main}ms`);
    } catch (err) {
        console.log('\n================ FIRST WASM RUNTIME FAILURE ================');
        console.log('Trap / Error:', err.message);
        dumpCPU(dv, CPU_STRUCT_VA);
        console.log('============================================================');
    }

    // D3D9 Ring Buffer Inspection
    const D3D9_RING_BUFFER_VA = 0x02010000;
    const ringMagic = dv.getUint32(D3D9_RING_BUFFER_VA, true);
    const ringVer = dv.getUint32(D3D9_RING_BUFFER_VA + 4, true);
    const ringHead = dv.getUint32(D3D9_RING_BUFFER_VA + 8, true);
    const ringTail = dv.getUint32(D3D9_RING_BUFFER_VA + 12, true);
    const ringCap = dv.getUint32(D3D9_RING_BUFFER_VA + 16, true);
    const frameIndex = dv.getUint32(D3D9_RING_BUFFER_VA + 20, true);

    console.log('\n=== DIRECT3D 9 SHARED MEMORY RING BUFFER STATE ===');
    console.log(`Magic: 0x${ringMagic.toString(16)} (expected 0x39443344 'D3D9')`);
    console.log(`Version: ${ringVer}`);
    console.log(`Head offset: ${ringHead} bytes`);
    console.log(`Tail offset: ${ringTail} bytes`);
    console.log(`Frame index: ${frameIndex}`);

    const CMD_NAMES = {
        0: 'NOP',
        1: 'CLEAR',
        2: 'BEGIN_SCENE',
        3: 'END_SCENE',
        4: 'PRESENT',
        5: 'SET_RENDER_STATE',
        6: 'SET_SAMPLER_STATE',
        7: 'SET_TEXTURE',
        8: 'SET_TRANSFORM',
        9: 'SET_VIEWPORT',
        10: 'SET_STREAM_SOURCE',
        11: 'SET_INDICES',
        12: 'DRAW_PRIMITIVE',
        13: 'DRAW_INDEXED_PRIMITIVE'
    };

    if (ringHead > 0) {
        console.log(`Serialized Command Packets (${ringHead} bytes written):`);
        let offset = 0;
        let pidx = 0;
        while (offset < ringHead && pidx < 50) {
            const pva = D3D9_RING_BUFFER_VA + 64 + offset;
            const cmdType = dv.getUint16(pva, true);
            const flags = dv.getUint16(pva + 2, true);
            const payloadBytes = dv.getUint32(pva + 4, true);
            const cname = CMD_NAMES[cmdType] || `UNKNOWN_CMD_${cmdType}`;
            console.log(`  [Packet #${pidx}] Type=${cmdType} (${cname}), Flags=0x${flags.toString(16)}, Payload=${payloadBytes} bytes`);
            offset += 8 + payloadBytes;
            pidx++;
        }
    } else {
        console.log('No commands written to ring buffer (head = 0).');
    }

    // Inspect Constructor #169 object state
    const ctor169Obj = 0x00ab47e0;
    const c169Count = dv.getUint32(ctor169Obj + 4, true);
    const c169Arr = dv.getUint32(ctor169Obj + 0x16c, true);
    console.log('\n=== CONSTRUCTOR #169 STATE ===');
    console.log(`Object 0x${ctor169Obj.toString(16)}: descriptor count=${c169Count}, element_array=0x${c169Arr.toString(16)}`);
    if (c169Arr >= 0x02000000 && c169Arr < 0x28000000) {
        const allocHeader = dv.getUint32(c169Arr - 4, true);
        console.log(`Element array resides in dynamic heap! Heap alloc header count=${allocHeader}`);
    } else {
        console.log(`WARNING: Element array pointer 0x${c169Arr.toString(16)} is not in heap range!`);
    }
}

function dumpCPU(dv, cpu_va) {
    const eax = dv.getUint32(cpu_va + 0, true);
    const ecx = dv.getUint32(cpu_va + 4, true);
    const edx = dv.getUint32(cpu_va + 8, true);
    const ebx = dv.getUint32(cpu_va + 12, true);
    const esp = dv.getUint32(cpu_va + 16, true);
    const ebp = dv.getUint32(cpu_va + 20, true);
    const esi = dv.getUint32(cpu_va + 24, true);
    const edi = dv.getUint32(cpu_va + 28, true);
    const eip = dv.getUint32(cpu_va + 32, true);
    const fs  = dv.getUint32(cpu_va + 36, true);

    console.log(`EAX: 0x${eax.toString(16).padStart(8, '0')}  ECX: 0x${ecx.toString(16).padStart(8, '0')}  EDX: 0x${edx.toString(16).padStart(8, '0')}  EBX: 0x${ebx.toString(16).padStart(8, '0')}`);
    console.log(`ESP: 0x${esp.toString(16).padStart(8, '0')}  EBP: 0x${ebp.toString(16).padStart(8, '0')}  ESI: 0x${esi.toString(16).padStart(8, '0')}  EDI: 0x${edi.toString(16).padStart(8, '0')}`);
    console.log(`EIP: 0x${eip.toString(16).padStart(8, '0')}  FS:  0x${fs.toString(16).padStart(8, '0')}`);

    if (esp >= 0x00200000 && esp < 0x00400000) {
        console.log('Stack Top:');
        for (let o = 0; o < 32; o += 4) {
            const val = dv.getUint32(esp + o, true);
            console.log(`  [ESP+0x${o.toString(16).padStart(2, '0')}]: 0x${val.toString(16).padStart(8, '0')}`);
        }
    }
}

run().catch(err => {
    console.error('[UNHANDLED]', err);
});
