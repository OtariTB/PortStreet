// Dedicated worker thread for authentic guest thread verification
import { parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import { WASI } from 'node:wasi';

const { wasmPath, sharedMemory, workerCpuVa } = workerData;

const wasmBytes = fs.readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);

// WASI preview1 imports for worker instance
const wasi = new WASI({ version: 'preview1' });
const baseWasi = wasi.wasiImport || (wasi.getImportObject && wasi.getImportObject().wasi_snapshot_preview1) || {};

// In secondary worker threads sharing linear memory, do NOT re-run _initialize (which corrupts CRT).
// Provide fd_write bound to sharedMemory so printf/fflush works on worker threads without error.
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

parentPort.postMessage({ type: 'READY' });

parentPort.on('message', (msg) => {
    if (msg.type === 'START') {
        const { targetVa } = msg;
        try {
            const res = instance.exports.dispatch_indirect(workerCpuVa, targetVa);
            parentPort.postMessage({ type: 'DONE', result: res });
        } catch (err) {
            parentPort.postMessage({ type: 'ERROR', error: err.message, stack: err.stack });
        }
    } else if (msg.type === 'RUN_LOOP') {
        try {
            parentPort.postMessage({ type: 'LOOP_STARTED' });
            instance.exports.guest_worker_thread_run(workerCpuVa);
            parentPort.postMessage({ type: 'LOOP_EXITED' });
        } catch (err) {
            parentPort.postMessage({ type: 'ERROR', error: err.message, stack: err.stack });
        }
    }
});
