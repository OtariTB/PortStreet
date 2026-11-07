// Dedicated worker thread for authentic guest thread execution
import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import { WASI } from 'node:wasi';

const { wasmPath, sharedMemory, workerCpuVa, gameDir } = workerData;
const workerSlot = workerData.workerSlot !== undefined
    ? workerData.workerSlot
    : Math.max(0, Math.floor((workerCpuVa - 0x00105000) / 0x0400));

const wasmBytes = fs.readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);

// WASI preview1 imports for worker instance (including read-only /game mount when provided)
const wasiOpts = {
    version: 'preview1',
    env: {
        ...process.env,
        ...(gameDir ? { PROSTREET_GAME_DIR: '/game' } : {}),
    },
};
if (gameDir && fs.existsSync(gameDir)) {
    wasiOpts.preopens = { '/game': gameDir };
}
const wasi = new WASI(wasiOpts);
const baseWasi = wasi.wasiImport || (wasi.getImportObject && wasi.getImportObject().wasi_snapshot_preview1) || {};

// Bind WASI internal memory reference for preopened fd_read/path_open without invoking _initialize()
const importObject = {
    wasi_snapshot_preview1: {
        ...baseWasi,
        fd_write: function(fd, iovs, iovs_len, nwritten) {
            const dv = new DataView(sharedMemory.buffer);
            let total = 0;
            let str = '';
            for (let i = 0; i < iovs_len; i++) {
                const ptr = dv.getUint32(iovs + i * 8, true);
                const len = dv.getUint32(iovs + i * 8 + 4, true);
                const bytes = new Uint8Array(sharedMemory.buffer, ptr, len);
                str += new TextDecoder().decode(bytes);
                total += len;
            }
            if (fd === 1) process.stdout.write(str);
            else if (fd === 2) process.stderr.write(str);
            if (nwritten) dv.setUint32(nwritten, total, true);
            return 0; // __WASI_ERRNO_SUCCESS
        }
    },
    env: {
        memory: sharedMemory
    }
};

const instance = new WebAssembly.Instance(wasmModule, importObject);

// Bind WASI memory to instance without calling CRT _initialize (via dummy wrapper with empty _initialize)
if (wasi.initialize && gameDir && fs.existsSync(gameDir)) {
    try {
        wasi.initialize({
            exports: {
                memory: sharedMemory,
                _initialize: () => {},
            },
        });
    } catch (_) {}
}

// CRITICAL: Isolate per-worker C/WASM shadow stack (__stack_pointer) in [0x2a000000..0x2c000000]
// so worker threads NEVER collide with the main thread's C stack!
const WORKER_SHADOW_STACK_TOP = 0x2c000000 - workerSlot * 0x00200000;
if (instance.exports.__stack_pointer) {
    instance.exports.__stack_pointer.value = WORKER_SHADOW_STACK_TOP;
}

parentPort.postMessage({ type: 'READY', slot: workerSlot, shadowStackTop: WORKER_SHADOW_STACK_TOP });

// Automatically enter the worker run loop on next tick.
// guest_worker_slot_run writes state=1 (READY) into GUEST_WORKER_MAILBOX_VA (0x00107000)
// and enters memory.atomic.wait32 on &g_guest_threads[slot].signal.
// This decouples guest thread wakeup from Node.js parentPort message loops.
setImmediate(() => {
    try {
        if (instance.exports.guest_worker_slot_run) {
            instance.exports.guest_worker_slot_run(workerSlot);
        } else {
            instance.exports.guest_worker_thread_run(workerCpuVa);
        }
        parentPort.postMessage({ type: 'LOOP_EXITED', slot: workerSlot });
    } catch (err) {
        parentPort.postMessage({ type: 'ERROR', slot: workerSlot, error: err.message, stack: err.stack });
    }
});

parentPort.on('message', (msg) => {
    if (msg.type === 'START') {
        const { targetVa } = msg;
        try {
            const res = instance.exports.dispatch_indirect(workerCpuVa, targetVa);
            parentPort.postMessage({ type: 'DONE', slot: workerSlot, result: res });
        } catch (err) {
            parentPort.postMessage({ type: 'ERROR', slot: workerSlot, error: err.message, stack: err.stack });
        }
    }
});
