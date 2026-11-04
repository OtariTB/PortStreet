// tests/test_guest_stack_arguments.mjs - Stage 3 Task 3.1 Guest Stack & Argument Validation
import fs from 'fs';
import path from 'path';
import assert from 'assert/strict';
import { fileURLToPath } from 'url';
import { WASI } from 'wasi';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const WASM_PATH = path.join(ROOT, 'build', 'game.wasm');

console.log('=== Stage 3 Task 3.1: Guest Stack & Argument Setup Diagnostic ===');

const wasmBuf = fs.readFileSync(WASM_PATH);
const wasi = new WASI({ args: [], env: {}, version: 'preview1' });
const mod = new WebAssembly.Module(wasmBuf);
const inst = new WebAssembly.Instance(mod, { wasi_snapshot_preview1: wasi.wasiImport });
wasi.initialize(inst);

inst.exports.guest_memory_init();
inst.exports.boot_bind_iats();
inst.exports.boot_install_hooks();

const wasmMem = new Uint8Array(inst.exports.memory.buffer);
const dv = new DataView(inst.exports.memory.buffer);
const CPU_STRUCT_VA = 0x00104000;

function resetCPU() {
    for (let i = 0; i < 512; i++) wasmMem[CPU_STRUCT_VA + i] = 0;
    dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true);
    dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);
    dv.setUint32(CPU_STRUCT_VA + 36, 0x00100000, true);
}

// -------------------------------------------------------------------------
// Test 1: Standard Arguments Setup ("nfs.exe")
// -------------------------------------------------------------------------
console.log('\n[Test 1] Standard single argument setup (argc = 1)...');
resetCPU();
inst.exports.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);

const esp1 = dv.getUint32(CPU_STRUCT_VA + 16, true);
assert.equal(esp1, 0x003ff000 - 16, 'ESP must be decremented by 16 bytes for 4 dwords');

const ret_va = dv.getUint32(esp1, true);
const argc1  = dv.getUint32(esp1 + 4, true);
const argv1  = dv.getUint32(esp1 + 8, true);
const envp1  = dv.getUint32(esp1 + 12, true);

assert.equal(ret_va, 0x00828ae0, '[ESP+0] Return address must be GUEST_DUMMY_RETURN_VA (0x00828ae0)');
assert.equal(argc1, 1, '[ESP+4] argc must be 1');
assert.equal(argv1, 0x00101100, '[ESP+8] argv must point to GUEST_ARGV_TAB_ADDR (0x00101100)');
assert.equal(envp1, 0x00101110, '[ESP+12] envp must point to GUEST_ENVP_TAB_ADDR (0x00101110)');

// Verify argv table contents
const arg0_ptr = dv.getUint32(argv1, true);
const arg1_ptr = dv.getUint32(argv1 + 4, true);
assert.equal(arg0_ptr, 0x00102000, 'argv[0] must point to 0x00102000');
assert.equal(arg1_ptr, 0, 'argv[1] must be null terminator (0)');

// Verify string content at 0x00102000
const str0 = Buffer.from(wasmMem.subarray(arg0_ptr, arg0_ptr + 8)).toString('ascii').replace(/\0.*$/, '');
assert.equal(str0, 'nfs.exe', 'arg[0] string must be "nfs.exe"');

// Verify CRT globals
assert.equal(dv.getUint32(0x00b33a64, true), 1, 'CRT global 0x00b33a64 (__argc) must be 1');
assert.equal(dv.getUint32(0x00b33a6c, true), 0x00101100, 'CRT global 0x00b33a6c (__argv) must be 0x00101100');
assert.equal(dv.getUint32(0x00b33a68, true), 0x00101110, 'CRT global 0x00b33a68 (_environ) must be 0x00101110');

console.log('  PASS: Standard argument stack layout, tables, strings, and CRT globals verified.');

// -------------------------------------------------------------------------
// Test 2: Lifecycle Dry Run Validation
// -------------------------------------------------------------------------
console.log('\n[Test 2] Main lifecycle dry run execution...');
const rc_dry = inst.exports.boot_invoke_main(CPU_STRUCT_VA, true);
assert.equal(rc_dry, 0, 'boot_invoke_main(dry_run = true) must return 0');

const h0 = dv.getUint32(0xbbad1c, true);
const h1 = dv.getUint32(0xbbad20, true);
const h2 = dv.getUint32(0xbbad24, true);
const h3 = dv.getUint32(0xbbad28, true);
console.log(`  Created event handles: 0x${h0.toString(16)}, 0x${h1.toString(16)}, 0x${h2.toString(16)}, 0x${h3.toString(16)}`);
assert.ok(h0 > 0 && h1 > 0 && h2 > 0 && h3 > 0, 'All 4 sync event handles must be non-zero');

const engine_obj = dv.getUint32(0x00bfc024, true);
console.log(`  Root engine object pointer: 0x${engine_obj.toString(16)}`);
assert.ok(engine_obj >= 0x02000000, 'Root engine object pointer must be in valid guest heap');

const quit_flag = dv.getUint32(0x00abae68, true);
assert.equal(quit_flag, 1, 'Quit flag (0x00abae68) must be set to 1 for clean loop termination');

console.log('  PASS: Lifecycle dry run successfully validated event handles, engine object, and clean quit.');

// -------------------------------------------------------------------------
// Test 3: Multi-Argument & Safe Mode Validation (["nfs.exe", "-safemode", "-windowed"])
// -------------------------------------------------------------------------
console.log('\n[Test 3] Multi-argument setup with -safemode (argc = 3)...');
resetCPU();

// Write test arguments into guest scratch memory (0x02100000)
const SCRATCH_VA = 0x02100000;
const args = ['nfs.exe', '-safemode', '-windowed'];
let strOff = SCRATCH_VA + 64;
const argTableVa = SCRATCH_VA;

for (let i = 0; i < args.length; i++) {
    const s = args[i];
    for (let c = 0; c < s.length; c++) wasmMem[strOff + c] = s.charCodeAt(c);
    wasmMem[strOff + s.length] = 0;
    dv.setUint32(argTableVa + i * 4, strOff, true);
    strOff += (s.length + 4) & ~3;
}
dv.setUint32(argTableVa + args.length * 4, 0, true);

inst.exports.boot_setup_arguments(CPU_STRUCT_VA, args.length, argTableVa);

const esp3 = dv.getUint32(CPU_STRUCT_VA + 16, true);
const argc3 = dv.getUint32(esp3 + 4, true);
const argv3 = dv.getUint32(esp3 + 8, true);

assert.equal(argc3, 3, '[ESP+4] argc must be 3');
assert.equal(dv.getUint32(0x00b33a64, true), 3, 'CRT __argc must be 3');

// Check argv array in guest memory
for (let i = 0; i < args.length; i++) {
    const p = dv.getUint32(argv3 + i * 4, true);
    assert.ok(p > 0, `argv[${i}] must be non-zero pointer`);
    let s = '';
    let cur = p;
    while (wasmMem[cur] !== 0) s += String.fromCharCode(wasmMem[cur++]);
    assert.equal(s, args[i], `argv[${i}] string must match "${args[i]}"`);
}
assert.equal(dv.getUint32(argv3 + args.length * 4, true), 0, 'argv[3] must be null terminator (0)');

// Execute dry run to verify safe mode global is written
inst.exports.boot_invoke_main(CPU_STRUCT_VA, true);
const safemode_val = dv.getUint32(0x00ac7378, true);
assert.equal(safemode_val, 1, 'Safe mode global (0x00ac7378) must be set to 1 when -safemode argument is present');

console.log('  PASS: Multi-argument table, individual strings, null-termination, and safe mode flag verified.');

console.log('\n================================================================');
console.log('ALL TASK 3.1 GUEST STACK & ARGUMENT CHECKS PASSED (100% OK)');
console.log('================================================================\n');
