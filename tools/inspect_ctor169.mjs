import fs from 'node:fs';
import { WASI } from 'node:wasi';

async function main() {
    const wasi = new WASI({ version: 'preview1', args: ['game.wasm'], env: process.env });
    const wasmBuffer = fs.readFileSync('build/game.wasm');
    const mod = await WebAssembly.compile(wasmBuffer);
    const inst = await WebAssembly.instantiate(mod, { wasi_snapshot_preview1: wasi.wasiImport });
    wasi.initialize(inst);
    const exp = inst.exports;
    exp.guest_memory_init();
    exp.fntab_init();

    const raw = fs.readFileSync('C:/Users/tabat/OneDrive/Desktop/Need-for-Speed-Pro-Street-SteamRIP.com/Need For Spped - Pro Street/nfs.exe');
    const peOffset = raw.readUInt32LE(0x3c);
    const optHeaderOffset = peOffset + 24;
    const sizeOfOptHeader = raw.readUInt16LE(peOffset + 20);
    const numSections = raw.readUInt16LE(peOffset + 6);
    const secTableOffset = optHeaderOffset + sizeOfOptHeader;
    const wasmMem = new Uint8Array(exp.memory.buffer);
    const dv = new DataView(exp.memory.buffer);

    for (let i = 0; i < numSections; i++) {
        const off = secTableOffset + i * 40;
        const vaddr = raw.readUInt32LE(off + 12);
        const rawSize = raw.readUInt32LE(off + 16);
        const rawPtr = raw.readUInt32LE(off + 20);
        const va = 0x00400000 + vaddr;
        if (rawSize > 0 && rawPtr > 0) {
            wasmMem.set(raw.subarray(rawPtr, rawPtr + rawSize), va);
        }
    }

    wasmMem[0x00400000] = 0x4d; wasmMem[0x00400001] = 0x5a;
    dv.setUint32(0x00100018, 0x00100000, true);
    dv.setUint32(0x00100004, 0x00400000, true);
    dv.setUint32(0x00100008, 0x00200000, true);
    exp.boot_bind_iats();
    exp.boot_install_hooks();

    const CPU_STRUCT_VA = 0x00104000;
    for (let i = 0; i < 512; i++) wasmMem[CPU_STRUCT_VA + i] = 0;
    dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true);
    dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);
    dv.setUint32(CPU_STRUCT_VA + 36, 0x00100000, true);

    let count = 0;
    for (let p = 0x00967608; p < 0x0096a1f4; p += 4) {
        const fn_va = dv.getUint32(p, true);
        if (fn_va !== 0) {
            count++;
            if (count === 169) {
                console.log('--- BEFORE CTOR 169 ---');
                console.log('g_heap_cur or whatever allocator global:');
                console.log('[0xabb060]:', dv.getUint32(0xabb060, true), dv.getUint32(0xabb064, true));
            }
            const saved_esp = dv.getUint32(CPU_STRUCT_VA + 16, true);
            dv.setUint32(CPU_STRUCT_VA + 16, saved_esp - 4, true);
            dv.setUint32(saved_esp - 4, 0x00828ae0, true);
            exp.dispatch_indirect(CPU_STRUCT_VA, fn_va);
            dv.setUint32(CPU_STRUCT_VA + 16, saved_esp, true);
            if (count === 169) {
                console.log('--- AFTER CTOR 169 ---');
                break;
            }
        }
    }

    console.log('=== INSPECTION OF CONSTRUCTOR #169 OBJECT AT 0x00ab47e0 ===');
    console.log('[0xab47e0] (vtable)   : 0x' + dv.getUint32(0x00ab47e0, true).toString(16));
    console.log('[0xab47e4] (count)    : ' + dv.getUint32(0x00ab47e4, true));
    for (let off = 0; off <= 0x170; off += 4) {
        const addr = 0x00ab47e0 + off;
        const val = dv.getUint32(addr, true);
        if (val !== 0) {
            console.log(`  [0x${addr.toString(16)}] (offset +0x${off.toString(16)}) = 0x${val.toString(16)} (${val})`);
        }
    }

    console.log('=== MEMORY AROUND 0x00000005 ===');
    for (let i = 0; i < 36; i += 4) {
        console.log(`  [0x${(5 + i).toString(16)}] = 0x${dv.getUint32(5 + i, true).toString(16)}`);
    }
}

main().catch(console.error);
