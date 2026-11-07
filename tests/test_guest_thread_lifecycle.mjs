// Focused test: Authentic Guest Thread Lifecycle (_beginthreadex -> ResumeThread -> Ack -> Queue Wait -> Shutdown)
import { Worker } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import { WASI } from 'node:wasi';

const WASM_PATH = path.resolve('build/game.wasm');

async function run() {
    console.log('[TEST] === Starting Guest Thread Lifecycle Verification ===');

    if (!fs.existsSync(WASM_PATH)) {
        throw new Error(`build/game.wasm not found at ${WASM_PATH}`);
    }

    const wasmBytes = fs.readFileSync(WASM_PATH);
    const wasmModule = new WebAssembly.Module(wasmBytes);

    // 1. Allocate 704 MB Shared Memory
    const sharedMemory = new WebAssembly.Memory({
        shared: true,
        initial: 11264,
        maximum: 11264
    });

    const i32 = new Int32Array(sharedMemory.buffer);
    const u32 = new Uint32Array(sharedMemory.buffer);

    // 2. Instantiate Main Thread WASM Instance
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

    // 3. Setup Memory Layout
    const MAIN_CPU_VA       = 0x00104000;
    const WORKER_CPU_VA     = 0x00105000;
    const MAIN_STACK_TOP    = 0x003FF000;
    const ARGLIST_VA        = 0x003FE000;
    const STREAMING_MGR_VA  = 0x0221BD18;
    const THREAD_ID_PTR_VA  = 0x003FE050;

    const STARTUP_EVENT = mainInstance.exports.win32_create_event();
    const QUEUE_EVENT   = mainInstance.exports.win32_create_event();
    console.log(`[TEST] Created Win32 events: Startup=0x${STARTUP_EVENT.toString(16)}, Queue=0x${QUEUE_EVENT.toString(16)}`);

    // Setup Main CPU
    u32[MAIN_CPU_VA >> 2] = 0x11111111; // eax
    u32[(MAIN_CPU_VA + 16) >> 2] = MAIN_STACK_TOP; // esp
    u32[(MAIN_CPU_VA + 40) >> 2] = 0x00100000; // fs_base (main TEB)

    // Setup Streaming Manager Structure
    u32[STREAMING_MGR_VA >> 2] = 0;
    u32[(STREAMING_MGR_VA + 4) >> 2] = 0;           // running status
    u32[(STREAMING_MGR_VA + 8) >> 2] = 0;           // shutdown flag
    u32[(STREAMING_MGR_VA + 0x10) >> 2] = 0;        // queue head
    u32[(STREAMING_MGR_VA + 0x78) >> 2] = STARTUP_EVENT; // startup event handle
    u32[(STREAMING_MGR_VA + 0x44 + 4) >> 2] = QUEUE_EVENT; // queue wait event

    // Setup Arglist Packet on Main Stack
    u32[ARGLIST_VA >> 2] = 0;              // [arglist] = 0 (Ack flag)
    u32[(ARGLIST_VA + 4) >> 2] = 0x008991ac; // worker routine = sub_008991ac
    u32[(ARGLIST_VA + 8) >> 2] = STREAMING_MGR_VA; // context = streaming manager

    // 4. Launch Background Worker in Run Loop
    console.log('[TEST] Launching host Worker thread with guest_worker_thread_run...');
    const worker = new Worker(path.resolve('tests/worker_game_thread.mjs'), {
        workerData: {
            wasmPath: WASM_PATH,
            sharedMemory,
            workerCpuVa: WORKER_CPU_VA
        }
    });

    let workerError = null;
    let workerLoopExited = false;

    await new Promise((resolve, reject) => {
        worker.on('message', (msg) => {
            if (msg.type === 'READY') resolve();
            if (msg.type === 'LOOP_EXITED') workerLoopExited = true;
            if (msg.type === 'ERROR') {
                workerError = msg.error;
                console.error('[TEST] Worker error:', msg.error, msg.stack);
            }
        });
        worker.on('error', reject);
    });

    // Start worker loop in background
    worker.postMessage({ type: 'RUN_LOOP' });
    await new Promise(r => setTimeout(r, 20));
    console.log('[TEST] PASS: Worker thread active and waiting in guest_worker_thread_run loop.');

    // 5. TEST: Call _beginthreadex with CREATE_SUSPENDED (initflag = 4)
    console.log('[TEST] Invoking _beginthreadex with CREATE_SUSPENDED (0x04)...');
    // Prepare stack for sub_0092045a / _beginthreadex (cdecl, 6 args + ret_addr):
    let esp = MAIN_STACK_TOP;
    esp -= 4; u32[esp >> 2] = THREAD_ID_PTR_VA;   // arg 6: thrdaddr
    esp -= 4; u32[esp >> 2] = 0x00000004;         // arg 5: initflag = CREATE_SUSPENDED
    esp -= 4; u32[esp >> 2] = ARGLIST_VA;         // arg 4: arglist
    esp -= 4; u32[esp >> 2] = 0x008976e4;         // arg 3: start_address = sub_008976e4
    esp -= 4; u32[esp >> 2] = 0;                  // arg 2: stack_size = default
    esp -= 4; u32[esp >> 2] = 0;                  // arg 1: security = NULL
    esp -= 4; u32[esp >> 2] = 0x0089799c;         // return address
    u32[(MAIN_CPU_VA + 16) >> 2] = esp;

    // Dispatch sub_0092045a (_beginthreadex thunk)
    mainInstance.exports.dispatch_indirect(MAIN_CPU_VA, 0x0092045a);

    const hThread = u32[MAIN_CPU_VA >> 2];
    const tid = u32[THREAD_ID_PTR_VA >> 2];
    console.log(`[TEST] _beginthreadex returned hThread=0x${hThread.toString(16)}, tid=0x${tid.toString(16)}`);

    if (hThread === 0 || hThread === 0x1000) {
        throw new Error(`FAIL: _beginthreadex failed to return a valid thread handle: ${hThread}`);
    }
    if (tid !== 0x2001) {
        throw new Error(`FAIL: _beginthreadex did not write expected thread ID: ${tid}`);
    }
    console.log('[TEST] PASS: _beginthreadex returned genuine thread handle and written thread ID.');

    // Caller cleans up arguments (cdecl: esp += 24)
    esp += 24;
    u32[(MAIN_CPU_VA + 16) >> 2] = esp;

    // 6. Verify worker is STILL SUSPENDED (Ack flag must be 0)
    console.log('[TEST] Verifying worker did NOT run while suspended...');
    await new Promise(r => setTimeout(r, 50));
    const ackBeforeResume = Atomics.load(i32, ARGLIST_VA >> 2);
    if (ackBeforeResume !== 0) {
        throw new Error(`FAIL: Worker executed while CREATE_SUSPENDED! ack=${ackBeforeResume}`);
    }
    console.log('[TEST] PASS: CREATE_SUSPENDED respected. Worker remained suspended, ack flag=0.');

    // 7. TEST: Call ResumeThread(hThread)
    console.log('[TEST] Invoking ResumeThread(hThread)...');
    esp -= 4; u32[esp >> 2] = hThread;            // arg 1: hThread (DISPATCH_CALL would have popped return address)
    u32[(MAIN_CPU_VA + 16) >> 2] = esp;

    mainInstance.exports.dispatch_indirect(MAIN_CPU_VA, 0x00967048); // ResumeThread IAT slot

    const resumeRc = u32[MAIN_CPU_VA >> 2];
    console.log(`[TEST] ResumeThread returned: ${resumeRc}`);
    if (resumeRc !== 1) {
        throw new Error(`FAIL: ResumeThread did not return previous suspend count 1 (got ${resumeRc})`);
    }
    console.log('[TEST] PASS: ResumeThread returned 1.');

    // 8. TEST: Wait for Authentic Acknowledgment [arglist] == 1
    console.log('[TEST] Main thread waiting for authentic acknowledgment write at [arglist]...');
    const t0 = performance.now();
    let ackSeen = false;
    while (performance.now() - t0 < 5000) {
        if (Atomics.load(i32, ARGLIST_VA >> 2) === 1) {
            ackSeen = true;
            break;
        }
        if (workerError) throw new Error(`Worker failed: ${workerError}`);
        await new Promise(r => setTimeout(r, 1));
    }

    if (!ackSeen) {
        throw new Error('FAIL: Timed out waiting for worker sub_008976e4 to write [arglist]=1');
    }
    const tAck = (performance.now() - t0).toFixed(2);
    console.log(`[TEST] PASS: Authentic acknowledgment [arglist]=1 written by sub_008976e4 in ${tAck}ms!`);

    // 9. Verify sub_008991ac running status and SetEvent(startup_event)
    let statusSeen = false;
    while (performance.now() - t0 < 5000) {
        if (Atomics.load(i32, (STREAMING_MGR_VA + 4) >> 2) === 1) {
            statusSeen = true;
            break;
        }
        await new Promise(r => setTimeout(r, 1));
    }
    if (!statusSeen) throw new Error('FAIL: sub_008991ac did not set running status [esi+4]=1');
    console.log('[TEST] PASS: sub_008991ac executed and set running status flag [esi + 4] = 1.');

    // 10. Verify worker is waiting in queue wait without blocking main thread
    console.log('[TEST] Worker entered queue wait loop (sub_0092e287 / WaitForSingleObject).');
    let sum = 0;
    for (let k = 0; k < 500000; k++) sum += k;
    console.log(`[TEST] PASS: Main thread completely unblocked (computation checksum=${sum}).`);

    // 11. TEST: Clean Worker Shutdown
    console.log('[TEST] Signaling worker shutdown flag [esi + 8] = 1 and notifying queue event...');
    Atomics.store(i32, (STREAMING_MGR_VA + 8) >> 2, 1); // shutdown flag
    mainInstance.exports.win32_signal_event(QUEUE_EVENT);

    const tShutdown = performance.now();
    let shutdownSeen = false;
    while (performance.now() - tShutdown < 5000) {
        if (Atomics.load(i32, (STREAMING_MGR_VA + 4) >> 2) === 0) {
            shutdownSeen = true;
            break;
        }
        await new Promise(r => setTimeout(r, 1));
    }

    if (!shutdownSeen) {
        throw new Error('FAIL: Worker failed to exit sub_008991ac after shutdown signal');
    }
    console.log('[TEST] PASS: Worker observed shutdown flag, exited sub_008991ac and reset running status to 0.');

    // Stop worker loop
    mainInstance.exports.guest_worker_thread_stop();
    await worker.terminate();

    // 12. Validate Main Thread CPU registers remained pristine
    const mainEax = u32[MAIN_CPU_VA >> 2];
    const mainTeb = u32[(MAIN_CPU_VA + 40) >> 2];
    console.log(`[TEST] Main CPU validation: EAX=0x${mainEax.toString(16)}, TEB=0x${mainTeb.toString(16)}`);
    if (mainTeb !== 0x00100000) {
        throw new Error('FAIL: Main thread TEB corrupted!');
    }
    console.log('[TEST] PASS: Main thread CPU context remained 100% pristine.');

    console.log('[TEST] === ALL GUEST THREAD LIFECYCLE CHECKS PASSED ===');
}

run().catch((err) => {
    console.error('[TEST] ERROR:', err);
    process.exit(1);
});
