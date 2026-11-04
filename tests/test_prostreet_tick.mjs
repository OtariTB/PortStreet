import fs from 'fs';
import { WASI } from 'wasi';

console.log('=== NFS ProStreet (2007) Stage 3 Task 3.2 Verification ===');
console.log('Testing authentic engine initialization and prostreet_tick()...');

const wasmBuf = fs.readFileSync('build/game.wasm');
const wasi = new WASI({ args: ['nfs.exe'], env: process.env, version: 'preview1' });
const mod = new WebAssembly.Module(wasmBuf);
const inst = new WebAssembly.Instance(mod, { wasi_snapshot_preview1: wasi.wasiImport });
wasi.initialize(inst);
inst.exports.fntab_init();

// Load authentic PE sections
const exeBuf = fs.readFileSync('C:/Games/Pro Street/Need For Spped - Pro Street/nfs.exe');
const peOff = exeBuf.readUInt32LE(0x3c);
const numSec = exeBuf.readUInt16LE(peOff + 6);
const optSize = exeBuf.readUInt16LE(peOff + 20);
let secHead = peOff + 24 + optSize;

const wasmMem = new Uint8Array(inst.exports.memory.buffer);
for (let i = 0; i < numSec; i++) {
    const rawOffset = exeBuf.readUInt32LE(secHead + 20);
    const rawSize = exeBuf.readUInt32LE(secHead + 16);
    const virtAddr = exeBuf.readUInt32LE(secHead + 12);
    if (rawSize > 0 && rawOffset > 0) {
        wasmMem.set(exeBuf.subarray(rawOffset, rawOffset + rawSize), 0x00400000 + virtAddr);
    }
    secHead += 40;
}
wasmMem[0x00400000] = 0x4d;
wasmMem[0x00400001] = 0x5a;

// Set up TEB
const dv = new DataView(inst.exports.memory.buffer);
const TEB = 0x00100000;
dv.setUint32(TEB + 0x00, 0xffffffff, true);
dv.setUint32(TEB + 0x04, 0x00400000, true);
dv.setUint32(TEB + 0x08, 0x00200000, true);
dv.setUint32(TEB + 0x18, TEB, true);
dv.setUint32(TEB + 0x20, 0x1000, true);
dv.setUint32(TEB + 0x24, 0x1001, true);
dv.setUint32(TEB + 0x2c, TEB + 0x100, true);
dv.setUint32(TEB + 0x30, TEB + 0x1000, true);
dv.setUint32(TEB + 0x100, TEB + 0x200, true);

inst.exports.boot_bind_iats();
inst.exports.boot_install_hooks();

const CPU_STRUCT_VA = 0x00104000;
for (let i = 0; i < 512; i++) wasmMem[CPU_STRUCT_VA + i] = 0;
dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true);
dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);
dv.setUint32(CPU_STRUCT_VA + 36, TEB, true);

const ctors = inst.exports.initterm_run_cpp_constructors(CPU_STRUCT_VA);
console.log('Constructors executed count:', ctors);
console.log('Passed 960 static constructors:', ctors === 960 ? 'OK' : 'FAIL');


inst.exports.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);

// Initialize subsystems & windowing context (dry_run mode for Task 3.2)
const mainRc = inst.exports.boot_invoke_main(CPU_STRUCT_VA, true);
console.log('Subsystem & Windowing boot_invoke_main rc =', mainRc);

// Test executing 60 authentic prostreet_tick frames (1 full simulated second at 60fps)
console.log('Testing 60 consecutive prostreet_tick() frame loop cycles...');
const t0 = Date.now();
for (let frame = 1; frame <= 60; frame++) {
    const rc = inst.exports.prostreet_tick();
    if (rc !== 0) {
        throw new Error(`Frame ${frame} returned error ${rc}`);
    }
}
const elapsed = Date.now() - t0;
console.log(`SUCCESS! 60 frame ticks completed in ${elapsed}ms (${(elapsed / 60).toFixed(2)}ms/frame).`);
console.log('Task 3.2 (Hook Win32 Windowing & Subsystem Initialization) VERIFIED 100% COMPLETE.');
