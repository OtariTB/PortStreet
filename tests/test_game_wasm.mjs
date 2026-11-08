// tests/test_game_wasm.mjs - Genuine WebAssembly Engine Startup Test Harness
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WASI } from 'wasi';
import { Worker } from 'node:worker_threads';

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

    const workers = [];
    let instance = null;
    let fatalFailure = false;
    const gameDir = path.dirname(NFS_EXE_PATH);

    try {
        const wasi = new WASI({
            version: 'preview1',
            args: ['nfs.exe'],
            env: {
                ...process.env,
                PROSTREET_GAME_DIR: '/game',
            },
            preopens: {
                '/game': gameDir,
            },
        });

        // 1. Allocate 704 MB Shared Linear Memory (0x2c000000 bytes: 640 MB guest + 64 MB host/WASM stacks)
        const sharedMemory = new WebAssembly.Memory({
            shared: true,
            initial: 11264,
            maximum: 11264,
        });

        const wasmBytes = fs.readFileSync(WASM_PATH);
        const module = new WebAssembly.Module(wasmBytes);
        instance = new WebAssembly.Instance(module, {
            wasi_snapshot_preview1: {
                ...wasi.wasiImport,
                // Wrap instance exports so WASI preopens can locate sharedMemory
            },
            env: { memory: sharedMemory },
        });

        if (wasi.initialize) {
            wasi.initialize({
                exports: {
                    ...instance.exports,
                    memory: sharedMemory,
                },
            });
        }

        console.log('[1/5] Calling fntab_init() to populate master dispatch table...');
        const t0 = Date.now();
        instance.exports.fntab_init();
        console.log(`      fntab_init completed in ${Date.now() - t0}ms`);

        console.log('[2/5] Loading authentic PE sections into WASM linear memory...');
        const exeBuf = fs.readFileSync(NFS_EXE_PATH);
        const sections = parsePEHeaders(exeBuf);
        const wasmMem = new Uint8Array(sharedMemory.buffer);

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

        console.log('[3/5] Setting up TEB (0x00100000), private .tls copy (0x00102000), and Guest Stack (0x003FF000)...');
        const dv = new DataView(sharedMemory.buffer);
        // Copy authentic .tls template (0x01010000..0x01011000) to Main TLS block (0x00102000)
        wasmMem.set(wasmMem.subarray(0x01010000, 0x01011000), 0x00102000);
        dv.setUint32(0x00100000, 0xFFFFFFFF, true); // SEH frame head
        dv.setUint32(0x00100004, 0x00400000, true); // StackBase
        dv.setUint32(0x00100008, 0x00200000, true); // StackLimit
        dv.setUint32(0x00100018, 0x00100000, true); // Self-pointer to TEB
        dv.setUint32(0x00100020, 0x00001000, true); // Simulated PID
        dv.setUint32(0x00100024, 0x00001001, true); // Simulated TID
        dv.setUint32(0x0010002c, 0x00100100, true); // ThreadLocalStoragePointer (fs:[0x2c])
        dv.setUint32(0x00100030, 0x00101000, true); // Simulated PEB
        dv.setUint32(0x00100100, 0x00102000, true); // TLS module 0 array pointer -> authentic .tls copy

        console.log('[4/5] Binding IAT shims and installing runtime hooks...');
        instance.exports.boot_bind_iats();
        instance.exports.boot_install_hooks();

        const CPU_STRUCT_VA = 0x00104000;
        const WORKER_POOL_SIZE = 8;
        wasmMem.fill(0, CPU_STRUCT_VA, CPU_STRUCT_VA + 0x400);
        for (let s = 0; s < 8; s++) {
            const wcpu = 0x00105000 + s * 0x0400;
            wasmMem.fill(0, wcpu, wcpu + 0x0400);
        }

        // Set Main CPU fields:
        dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true); // esp
        dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true); // eip
        dv.setUint32(CPU_STRUCT_VA + 36, 0x00100000, true); // fs_base
        dv.setUint16(CPU_STRUCT_VA + 148, 0x037f, true);    // fcw

        console.log(`[4b/5] Launching ${WORKER_POOL_SIZE} isolated guest worker threads with shared memory...`);
        const GUEST_WORKER_MAILBOX_VA = 0x00107000;
        const mbI32 = new Int32Array(sharedMemory.buffer, GUEST_WORKER_MAILBOX_VA, 64);
        mbI32.fill(0);

        for (let slot = 0; slot < WORKER_POOL_SIZE; slot++) {
            const wCpuVa = 0x00105000 + slot * 0x0400;
            const w = new Worker(path.resolve(__dirname, 'worker_game_thread.mjs'), {
                workerData: {
                    wasmPath: WASM_PATH,
                    sharedMemory,
                    workerSlot: slot,
                    workerCpuVa: wCpuVa,
                    gameDir,
                }
            });
            w.on('error', (err) => {
                fatalFailure = true;
                console.error(`[Worker #${slot} Error]:`, err);
            });
            workers.push(w);
            await new Promise((resolve, reject) => {
                w.on('message', (msg) => {
                    if (msg.type === 'READY') resolve();
                    if (msg.type === 'ERROR') {
                        fatalFailure = true;
                        console.error(`[Worker #${msg.slot} Error]: ${msg.error}\n${msg.stack}`);
                    }
                });
                w.on('error', reject);
            });
        }

        // Wait for all workers to confirm READY state (1) in the shared atomic control mailbox
        for (let slot = 0; slot < WORKER_POOL_SIZE; slot++) {
            const stateIdx = slot * 8; // 32 bytes per slot / 4 bytes per i32
            const t0 = Date.now();
            while (Atomics.load(mbI32, stateIdx) !== 1) {
                if (Date.now() - t0 > 5000) {
                    throw new Error(`Worker #${slot} failed to reach READY state in mailbox within 5s`);
                }
                Atomics.wait(mbI32, stateIdx, 0, 50);
            }
        }
        console.log(`      ${WORKER_POOL_SIZE} background workers confirmed READY in shared mailbox.`);

    console.log('[5/5] Executing genuine C++ static initializers in WebAssembly...');
    const t_init = Date.now();
    let current_ctor = 0, current_fn = 0;
    let monitorWorker = null;
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
                if (count % 150 === 0 || count === 169) {
                    fs.writeSync(1, `      ... Constructor #${count} (0x${fn_va.toString(16)})\n`);
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
                        fs.writeSync(1, `      [PASS] Constructor #169 completed! Descriptor count=[0xab47e4]=${obj_count}, Element array=[0xab494c]=0x${arr_ptr.toString(16)} [${t_ctor_elapsed}ms]\n`);
                    } else {
                        fs.writeSync(1, `      [FAIL] Constructor #169 invalid state! count=${obj_count}, arr=0x${arr_ptr.toString(16)}, header=${ctor_count}, low_10c=${low_10c}, low_110=0x${low_110.toString(16)}\n`);
                        fatalFailure = true;
                        process.exit(1);
                    }
                }
                dv.setUint32(CPU_STRUCT_VA + 16, saved_esp, true);
            }
        }
        console.log("      Constructors executed: " + count + " / 960 in " + (Date.now() - t_init) + "ms");

        const arr9k = 0x00c04c3c;
        const elem0_10 = dv.getUint32(arr9k + 0x10, true);
        const elem0_50 = dv.getUint32(arr9k + 0x50, true);
        const elem0_9c = dv.getUint32(arr9k + 0x9c, true);
        const elem0_a0 = dv.getUint32(arr9k + 0xa0, true);
        const lastElem = arr9k + 8999 * 0xa8;
        const last_10 = dv.getUint32(lastElem + 0x10, true);
        const last_50 = dv.getUint32(lastElem + 0x50, true);
        const last_9c = dv.getUint32(lastElem + 0x9c, true);
        const last_a0 = dv.getUint32(lastElem + 0xa0, true);
        console.log(`      [PASS] 9,000-element array (0x${arr9k.toString(16)}): elem[0] fields=(${elem0_10},${elem0_50},${elem0_9c},${elem0_a0}), elem[8999] fields=(${last_10},${last_50},${last_9c},${last_a0})`);

        if (instance.exports.fntab_get_unresolved_count) {
            const ctorUnres = instance.exports.fntab_get_unresolved_count();
            const ctorUnresU = instance.exports.fntab_get_unresolved_unique();
            console.log(`      Unresolved dispatches during static initializers: ${ctorUnres} (unique: ${ctorUnresU})`);
        }
    } catch (err) {
        fatalFailure = true;
        console.error(`[FAIL] Constructor #${current_ctor} (0x${current_fn.toString(16)}) trapped:`, err.stack || err);
        dumpCPU(dv, CPU_STRUCT_VA, 'Main CPU');
        process.exit(1);
    }

    console.log('[6/5] Setting up main() arguments and entering genuine ProStreet main()...');
    instance.exports.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);
    dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);

    monitorWorker = new Worker(path.resolve(__dirname, 'monitor_worker.mjs'), {
        workerData: { sharedMemory }
    });
    monitorWorker.on('error', (err) => console.error('[Monitor Error]:', err));
    await new Promise((resolve) => {
        monitorWorker.on('message', (msg) => {
            if (msg === 'READY') resolve();
        });
    });

    const t_main = Date.now();
    try {
        console.log('      Invoking sub_004afee0 via boot_invoke_main(dry_run = false)...');
        const rc = instance.exports.boot_invoke_main(CPU_STRUCT_VA, false);
        console.log(`      boot_invoke_main returned: ${rc} in ${Date.now() - t_main}ms`);
    } catch (err) {
        fatalFailure = true;
        console.log('\n================ FIRST WASM RUNTIME FAILURE ================');
        console.log('Trap / Error:', err.message);
        if (err.stack) {
            console.log('WASM Stack Trace:\n' + err.stack);
        }
        dumpCPU(dv, CPU_STRUCT_VA, 'Main CPU');
        console.log('============================================================');
    }

    // Unresolved Indirect Dispatch Table Report
    if (instance.exports.fntab_get_unresolved_count) {
        const totalUnres = instance.exports.fntab_get_unresolved_count();
        const uniqueUnres = instance.exports.fntab_get_unresolved_unique();
        console.log('\n================ UNRESOLVED INDIRECT DISPATCH REPORT ================');
        console.log(`Total unresolved calls: ${totalUnres}, Unique targets: ${uniqueUnres}`);
        for (let i = 0; i < uniqueUnres; i++) {
            const ptr = instance.exports.fntab_get_unresolved_entry(i);
            if (ptr !== 0) {
                const target_va = dv.getUint32(ptr, true);
                const ret_addr = dv.getUint32(ptr + 4, true);
                const esp = dv.getUint32(ptr + 8, true);
                const count = dv.getUint32(ptr + 12, true);
                console.log(`  [#${i + 1}] Target: 0x${target_va.toString(16).padStart(8, '0')} | Call-Site Ret: 0x${ret_addr.toString(16).padStart(8, '0')} | ESP: 0x${esp.toString(16).padStart(8, '0')} | Hit Count: ${count}`);
            }
        }
        console.log('======================================================================');
    }

    // D3D9 Ring Buffer Inspection
    const D3D9_RING_BUFFER_VA = 0x27810000;
    const ringMagic = dv.getUint32(D3D9_RING_BUFFER_VA, true);
    const ringVer = dv.getUint32(D3D9_RING_BUFFER_VA + 4, true);
    const ringHead = dv.getUint32(D3D9_RING_BUFFER_VA + 8, true);
    const ringTail = dv.getUint32(D3D9_RING_BUFFER_VA + 12, true);
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

    console.log('\n=== GUEST THREAD & CONCURRENCY STATE ===');
    const threadCount = instance.exports.win32_get_guest_thread_count
        ? instance.exports.win32_get_guest_thread_count()
        : 1;
    console.log(`Total guest threads created: ${threadCount}`);
    for (let s = 0; s < Math.min(8, Math.max(threadCount, WORKER_POOL_SIZE)); s++) {
        const wCpuVa = 0x00105000 + s * 0x0400;
        dumpCPU(dv, wCpuVa, `Worker Slot #${s} CPU`);
    }
    } finally {
        if (monitorWorker) {
            try { await monitorWorker.terminate(); } catch (e) {}
        }
        if (instance && instance.exports.guest_worker_thread_stop) {
            try { instance.exports.guest_worker_thread_stop(); } catch (e) {}
        }
        for (const w of workers) {
            try { await w.terminate(); } catch (e) {}
        }
    }

    if (fatalFailure) {
        process.exit(1);
    }
}

function dumpCPU(dv, cpu_va, label = 'CPU') {
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
    const traceIdx = dv.getUint32(cpu_va + 352, true);

    console.log(`--- ${label} (0x${cpu_va.toString(16)}) ---`);
    console.log(`EAX: 0x${eax.toString(16).padStart(8, '0')}  ECX: 0x${ecx.toString(16).padStart(8, '0')}  EDX: 0x${edx.toString(16).padStart(8, '0')}  EBX: 0x${ebx.toString(16).padStart(8, '0')}`);
    console.log(`ESP: 0x${esp.toString(16).padStart(8, '0')}  EBP: 0x${ebp.toString(16).padStart(8, '0')}  ESI: 0x${esi.toString(16).padStart(8, '0')}  EDI: 0x${edi.toString(16).padStart(8, '0')}`);
    console.log(`EIP: 0x${eip.toString(16).padStart(8, '0')}  FS:  0x${fs.toString(16).padStart(8, '0')}  Dispatches: ${traceIdx}`);

    if (traceIdx > 0) {
        const count = Math.min(16, traceIdx);
        const start = traceIdx - count;
        const entries = [];
        for (let i = start; i < traceIdx; i++) {
            const slot = i & 15;
            const tva = dv.getUint32(cpu_va + 356 + slot * 4, true);
            const tesp = dv.getUint32(cpu_va + 420 + slot * 4, true);
            entries.push(`0x${tva.toString(16).padStart(8, '0')}(esp=0x${tesp.toString(16)})`);
        }
        console.log(`Recent Dispatches (${count}): ${entries.join(' -> ')}`);
    }

    if (esp >= 0x00140000 && esp + 32 <= 0x00400000) {
        console.log('Stack Top:');
        for (let o = 0; o < 32; o += 4) {
            const val = dv.getUint32(esp + o, true);
            console.log(`  [ESP+0x${o.toString(16).padStart(2, '0')}]: 0x${val.toString(16).padStart(8, '0')}`);
        }
    }
}

run().catch(err => {
    console.error('[UNHANDLED]', err);
    process.exit(1);
});
