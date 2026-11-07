// Multi-Worker Scheduler Integration Test: Two concurrent guest workers
import { Worker } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import { WASI } from 'node:wasi';

const WASM_PATH = path.resolve('build/game.wasm');

async function run() {
    console.log('[TEST] === Starting Multi-Worker Scheduler Verification ===');

    if (!fs.existsSync(WASM_PATH)) {
        throw new Error(`build/game.wasm not found at ${WASM_PATH}`);
    }

    const wasmBytes = fs.readFileSync(WASM_PATH);
    const wasmModule = new WebAssembly.Module(wasmBytes);

    const sharedMemory = new WebAssembly.Memory({
        shared: true,
        initial: 11264,
        maximum: 11264
    });

    const i32 = new Int32Array(sharedMemory.buffer);
    const u32 = new Uint32Array(sharedMemory.buffer);

    const wasi = new WASI({ version: 'preview1' });
    const importObject = {
        ...wasi.getImportObject(),
        env: { memory: sharedMemory }
    };

    const mainInstance = new WebAssembly.Instance(wasmModule, importObject);
    if (wasi.initialize) {
        wasi.initialize(mainInstance);
    }

    mainInstance.exports.fntab_init();
    mainInstance.exports.boot_bind_iats();

    const GUEST_WORKER_MAILBOX_VA = 0x00107000;
    const mbI32 = new Int32Array(sharedMemory.buffer, GUEST_WORKER_MAILBOX_VA, 64);
    mbI32.fill(0);

    const workers = [];
    const NUM_WORKERS = 2;

    console.log(`[TEST] Launching ${NUM_WORKERS} background host worker threads...`);
    for (let slot = 0; slot < NUM_WORKERS; slot++) {
        const wCpuVa = 0x00105000 + slot * 0x0400;
        const w = new Worker(path.resolve('tests/worker_game_thread.mjs'), {
            workerData: {
                wasmPath: WASM_PATH,
                sharedMemory,
                workerSlot: slot,
                workerCpuVa: wCpuVa,
            }
        });
        w.on('error', (err) => {
            console.error(`[TEST Worker #${slot} Error]:`, err);
        });
        workers.push(w);
    }

    // Wait for all workers to confirm READY state (1) in the shared atomic control mailbox
    for (let slot = 0; slot < NUM_WORKERS; slot++) {
        const stateIdx = slot * 8;
        const t0 = Date.now();
        while (Atomics.load(mbI32, stateIdx) !== 1) {
            if (Date.now() - t0 > 5000) {
                throw new Error(`Worker #${slot} failed to reach READY state in mailbox within 5s`);
            }
            Atomics.wait(mbI32, stateIdx, 0, 50);
        }
    }
    console.log(`[TEST] PASS: All ${NUM_WORKERS} workers confirmed READY in shared mailbox.`);

    // Test 1: Worker Slot 0 execution (entry = 0x00905610)
    console.log('[TEST] Testing Worker Slot 0 (entry = 0x00905610)...');
    const slot0_arglist = 0x00b44e80;
    // Set up dummy struct for slot 0 arglist
    u32[slot0_arglist >> 2] = 0;
    u32[(slot0_arglist + 4) >> 2] = 0;
    u32[(slot0_arglist + 8) >> 2] = 0; // flag written by worker
    u32[(slot0_arglist + 0x10) >> 2] = 0;
    u32[(slot0_arglist + 0x14) >> 2] = 0;
    u32[(slot0_arglist + 0x18) >> 2] = 0;
    u32[(slot0_arglist + 0x1c) >> 2] = 0;

    const tidPtr0 = 0x003fe050;
    const h0 = mainInstance.exports.win32_create_guest_thread(0x00905610, slot0_arglist, 0, 4, tidPtr0);
    console.log(`[TEST] Thread 0 created: handle=0x${h0.toString(16)}, tid=0x${u32[tidPtr0 >> 2].toString(16)}`);

    // Resume thread 0
    mainInstance.exports.win32_resume_guest_thread(h0);

    // Wait for thread 0 to complete or write flag
    const tStart0 = Date.now();
    let thread0Completed = false;
    while (Date.now() - tStart0 < 3000) {
        if (Atomics.load(mbI32, 0 * 8 + 4) > 0 || u32[(slot0_arglist + 8) >> 2] > 0) {
            thread0Completed = true;
            break;
        }
        await new Promise(r => setTimeout(r, 10));
    }
    if (!thread0Completed) {
        throw new Error('FAIL: Worker Slot 0 did not complete entry 0x00905610 within 3s');
    }
    console.log('[TEST] PASS: Worker Slot 0 executed and completed authentic entry 0x00905610!');

    // Test 2: Worker Slot 1 execution (entry = 0x008976e4, streaming worker)
    console.log('[TEST] Testing Worker Slot 1 (entry = 0x008976e4, streaming worker)...');
    const ARGLIST_VA = 0x003fecc0;
    const STREAMING_MGR_VA = 0x0221bd18;
    const STARTUP_EVENT = mainInstance.exports.win32_create_event();
    const QUEUE_EVENT = mainInstance.exports.win32_create_event();

    // Setup Streaming Manager Structure
    u32[STREAMING_MGR_VA >> 2] = 0;
    u32[(STREAMING_MGR_VA + 4) >> 2] = 0;                 // running status
    u32[(STREAMING_MGR_VA + 8) >> 2] = 0;                 // shutdown flag
    u32[(STREAMING_MGR_VA + 0x10) >> 2] = 0;              // queue head
    u32[(STREAMING_MGR_VA + 0x78) >> 2] = STARTUP_EVENT;  // startup event handle
    u32[(STREAMING_MGR_VA + 0x44 + 4) >> 2] = QUEUE_EVENT;// queue wait event

    // Setup Arglist Packet
    u32[ARGLIST_VA >> 2] = 0;                             // [arglist] = 0 (Ack flag)
    u32[(ARGLIST_VA + 4) >> 2] = 0x008991ac;              // worker routine = sub_008991ac
    u32[(ARGLIST_VA + 8) >> 2] = STREAMING_MGR_VA;        // context = streaming manager

    const tidPtr1 = 0x003fe054;
    const h1 = mainInstance.exports.win32_create_guest_thread(0x008976e4, ARGLIST_VA, 0, 4, tidPtr1);
    console.log(`[TEST] Thread 1 created: handle=0x${h1.toString(16)}, tid=0x${u32[tidPtr1 >> 2].toString(16)}`);

    // Verify thread 1 is still suspended
    await new Promise(r => setTimeout(r, 50));
    if (Atomics.load(i32, ARGLIST_VA >> 2) !== 0) {
        throw new Error('FAIL: Thread 1 executed while suspended!');
    }
    console.log('[TEST] PASS: Thread 1 stayed suspended before ResumeThread.');

    // Resume thread 1
    console.log('[TEST] Resuming Thread 1...');
    mainInstance.exports.win32_resume_guest_thread(h1);

    // Wait for authentic acknowledgment write [ARGLIST_VA] == 1
    const tStart1 = Date.now();
    let ackSeen = false;
    while (Date.now() - tStart1 < 5000) {
        if (Atomics.load(i32, ARGLIST_VA >> 2) === 1) {
            ackSeen = true;
            break;
        }
        await new Promise(r => setTimeout(r, 10));
    }
    if (!ackSeen) {
        throw new Error('FAIL: Timed out waiting for worker sub_008976e4 to write [arglist]=1');
    }
    const tAck = Date.now() - tStart1;
    console.log(`[TEST] PASS: Authentic acknowledgment [arglist]=1 written by sub_008976e4 in ${tAck}ms!`);

    // Verify sub_008991ac running status flag [esi + 4] = 1
    let statusSeen = false;
    const tStatus = Date.now();
    while (Date.now() - tStatus < 5000) {
        if (Atomics.load(i32, (STREAMING_MGR_VA + 4) >> 2) === 1) {
            statusSeen = true;
            break;
        }
        await new Promise(r => setTimeout(r, 10));
    }
    if (!statusSeen) {
        throw new Error('FAIL: sub_008991ac did not set running status [esi+4]=1');
    }
    console.log('[TEST] PASS: sub_008991ac running and waiting in queue wait.');

    // Clean shutdown
    console.log('[TEST] Shutting down worker...');
    Atomics.store(i32, (STREAMING_MGR_VA + 8) >> 2, 1);
    mainInstance.exports.win32_signal_event(QUEUE_EVENT);
    mainInstance.exports.guest_worker_thread_stop();

    for (const w of workers) {
        await w.terminate();
    }

    console.log('[TEST] === ALL MULTI-WORKER SCHEDULER CHECKS PASSED ===');
}

run().catch((err) => {
    console.error('[TEST] ERROR:', err);
    process.exit(1);
});
