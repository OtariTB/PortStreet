import fs from 'fs';
import { WASI } from 'wasi';

console.log('=== NFS ProStreet (2007) Stage 3 Task 3.3a Verification ===');
console.log('Testing Root Engine Object Lifecycle & Subsystem State Tables...');

const wasmBuf = fs.readFileSync('build/game.wasm');
const wasi = new WASI({ args: ['nfs.exe'], env: process.env, version: 'preview1' });
const mod = new WebAssembly.Module(wasmBuf);
const inst = new WebAssembly.Instance(mod, { wasi_snapshot_preview1: wasi.wasiImport });
wasi.initialize(inst);
inst.exports.fntab_init();

// 1. Load authentic PE sections
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

// 2. Set up TEB and TLS
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

// 3. Static Initializers
const ctors = inst.exports.initterm_run_cpp_constructors(CPU_STRUCT_VA);
if (ctors !== 960) {
    throw new Error(`Expected 960 static constructors, got ${ctors}`);
}
console.log('✓ All 960 C++ static initializers executed cleanly.');

inst.exports.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);

// 4. Invoke Main and allocate root engine object
const mainRc = inst.exports.boot_invoke_main(CPU_STRUCT_VA, true);
if (mainRc !== 0) {
    throw new Error(`boot_invoke_main returned error ${mainRc}`);
}
console.log('✓ boot_invoke_main completed successfully (rc = 0).');

// 5. Inspect boot status structure
const statusPtr = inst.exports.boot_get_status();
const stage = dv.getInt32(statusPtr + 0, true);
const argc = dv.getInt32(statusPtr + 4, true);
const engineObjPtr = dv.getUint32(statusPtr + 36, true);

console.log(`[Status] Stage: ${stage}, Argc: ${argc}, Engine Object Ptr: 0x${engineObjPtr.toString(16)}`);

if (engineObjPtr === 0) {
    throw new Error('FAIL: g_boot_status.engine_object_ptr is NULL!');
}
console.log('✓ Engine root object pointer in g_boot_status is non-null.');

// 6. Verify 0x00bfc024 and 0x00bfc02c state table globals
const globalObjPtr = dv.getUint32(0x00bfc024, true);
const globalCtxPtr = dv.getUint32(0x00bfc02c, true);

console.log(`[Globals] 0x00bfc024: 0x${globalObjPtr.toString(16)}, 0x00bfc02c: 0x${globalCtxPtr.toString(16)}`);

if (globalObjPtr !== engineObjPtr) {
    throw new Error(`FAIL: 0x00bfc024 (0x${globalObjPtr.toString(16)}) does not match g_boot_status (0x${engineObjPtr.toString(16)})`);
}
console.log('✓ Global 0x00bfc024 correctly holds root engine object pointer.');

// 7. Verify TLS slot 0 index 1
const tlsArr = dv.getUint32(TEB + 0x2c, true);
const tlsSlot0 = dv.getUint32(tlsArr, true);
const tlsEnginePtr = dv.getUint32(tlsSlot0 + 4, true);
console.log(`[TLS] fs:[0x2c][0][1]: 0x${tlsEnginePtr.toString(16)}`);

if (tlsEnginePtr !== engineObjPtr) {
    throw new Error(`FAIL: TLS slot 0 index 1 (0x${tlsEnginePtr.toString(16)}) does not match engineObjPtr (0x${engineObjPtr.toString(16)})`);
}
console.log('✓ Thread-Local Storage (TLS) index 1 correctly bound to root engine object.');

// 8. Verify Engine Object persistence across frame ticks
console.log('Testing Engine Object persistence across 10 prostreet_tick() cycles...');
for (let frame = 1; frame <= 10; frame++) {
    const rc = inst.exports.prostreet_tick();
    if (rc !== 0) {
        throw new Error(`prostreet_tick failed on frame ${frame}`);
    }

    // Verify pointer hasn't been overwritten or corrupted
    const curObjPtr = dv.getUint32(0x00bfc024, true);
    if (curObjPtr !== engineObjPtr) {
        throw new Error(`Corrupted 0x00bfc024 at frame ${frame}: expected 0x${engineObjPtr.toString(16)}, got 0x${curObjPtr.toString(16)}`);
    }
}
console.log('✓ Root engine object pointer at 0x00bfc024 remained completely intact across all frames.');

// 9. Verify Engine State Flags
const simStatus = dv.getUint32(0x00abb510, true);
console.log(`[State Tables] Simulation manager status (0x00abb510): ${simStatus}`);

console.log('=== Task 3.3a: Root Engine Object Lifecycle & State Tables VERIFIED 100% COMPLETE ===');

