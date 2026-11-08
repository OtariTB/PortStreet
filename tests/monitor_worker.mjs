// Background monitoring thread to sample guest CPU, workers, and D3D9 ring buffer
// asynchronously without being blocked by the main thread's synchronous WASM execution.
import { workerData, parentPort } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';

const { sharedMemory } = workerData;
const dv = new DataView(sharedMemory.buffer);

const LOG_PATH = path.resolve('build', 'monitor.log');
try { fs.writeFileSync(LOG_PATH, '=== MONITOR STARTED ===\n'); } catch (e) {}

function log(msg) {
    try {
        fs.writeSync(1, msg + '\n');
        fs.appendFileSync(LOG_PATH, msg + '\n');
    } catch (e) {}
}

parentPort.postMessage('READY');

const CPU_MAIN_VA = 0x00104000;
const CPU_WORKER_BASE_VA = 0x00105000;
const MAILBOX_VA = 0x00107000;
const D3D9_RING_VA = 0x27810000;
const TASK_POOL_A_VA = 0x00b44e00;
const TASK_POOL_B_VA = 0x00b45000;

function readWorkerCpu(slot) {
    return readCpu(CPU_WORKER_BASE_VA + slot * 0x0400);
}

function readTaskPool(baseVa, poolName) {
    const slots = [];
    for (let i = 0; i < 32; i++) {
        const slotVa = baseVa + 0x1c + i * 0x28;
        const status = dv.getUint8(slotVa);
        const compPtr = dv.getUint32(slotVa + 4, true);
        let compVal = 0;
        if (compPtr >= 0x00100000 && compPtr < sharedMemory.buffer.byteLength - 4) {
            compVal = dv.getUint32(compPtr, true);
        }
        if (status !== 0 || compPtr !== 0) {
            slots.push({ slot: i, status, compPtr: '0x' + compPtr.toString(16).padStart(8, '0'), compVal });
        }
    }
    return slots;
}

function readCpu(base) {
    return {
        eax: dv.getUint32(base + 0, true),
        ecx: dv.getUint32(base + 4, true),
        edx: dv.getUint32(base + 8, true),
        ebx: dv.getUint32(base + 12, true),
        esp: dv.getUint32(base + 16, true),
        ebp: dv.getUint32(base + 20, true),
        esi: dv.getUint32(base + 24, true),
        edi: dv.getUint32(base + 28, true),
        eip: dv.getUint32(base + 32, true),
        traceIdx: dv.getUint32(base + 352, true),
    };
}

function readMem32(va) {
    if (va >= 0 && va < sharedMemory.buffer.byteLength - 4) {
        return dv.getUint32(va, true);
    }
    return 0;
}

function readRecentTrace(base, count = 16) {
    const traceIdx = dv.getUint32(base + 352, true);
    if (traceIdx === 0) return [];
    const n = Math.min(count, traceIdx);
    const start = traceIdx - n;
    const entries = [];
    for (let i = start; i < traceIdx; i++) {
        const slot = i & 15;
        const va = dv.getUint32(base + 356 + slot * 4, true);
        const esp = dv.getUint32(base + 420 + slot * 4, true);
        entries.push({ i, va, esp });
    }
    return entries;
}

function readD3D9() {
    const magic = dv.getUint32(D3D9_RING_VA + 0, true);
    const head = dv.getUint32(D3D9_RING_VA + 8, true);
    const tail = dv.getUint32(D3D9_RING_VA + 12, true);
    const frameIndex = dv.getUint32(D3D9_RING_VA + 20, true);
    let cmds = [];
    if (magic === 0x39443344 && head > 0) {
        let off = 0;
        let count = 0;
        while (off < head && count < 10) {
            const pva = D3D9_RING_VA + 64 + off;
            const cmdType = dv.getUint16(pva, true);
            const cmdSize = dv.getUint16(pva + 2, true);
            cmds.push({ type: cmdType, size: cmdSize });
            if (cmdSize === 0) break;
            off += cmdSize;
            count++;
        }
    }
    return { magic, head, tail, frameIndex, cmds };
}

function readWorkerMailbox(slot) {
    const off = MAILBOX_VA + slot * 32;
    return {
        state: dv.getUint32(off + 0, true),
        signal: dv.getUint32(off + 4, true),
        entry: dv.getUint32(off + 8, true),
        completed: dv.getUint32(off + 16, true),
    };
}

const t0 = Date.now();
const sampleTimes = [1000, 5000, 10000, 20000, 30000];
const reportedMilestones = new Set();

let lastTraceIdx = 0;
let seenDaA70 = false;
let seenDaA70Return = false;
let seenDaE50 = false;
let seenDaE50Return = false;

const interval = setInterval(() => {
    const elapsed = Date.now() - t0;
    const mainCpu = readCpu(CPU_MAIN_VA);
    const trace = readRecentTrace(CPU_MAIN_VA, 16);

    for (const t of trace) {
        if (t.va === 0x006daa70) seenDaA70 = true;
        if (t.va === 0x006d2df0 || t.va === 0x00430fd0 || t.va === 0x006dae50) {
            if (seenDaA70) seenDaA70Return = true;
        }
        if (t.va === 0x006dae50) seenDaE50 = true;
        if (t.va === 0x00828710) {
            if (seenDaE50) seenDaE50Return = true;
        }
    }

    for (const target of sampleTimes) {
        if (elapsed >= target && !reportedMilestones.has(target)) {
            reportedMilestones.add(target);
            const d3d = readD3D9();

            const deltaDispatches = mainCpu.traceIdx - lastTraceIdx;
            const isProgressing = deltaDispatches > 0;
            const stackTopVal = readMem32(mainCpu.esp);

            log(`\n================== MONITOR SAMPLE @ ${Math.round(elapsed / 1000)}s ==================`);
            log(`Main Thread Dispatches : ${mainCpu.traceIdx} (${isProgressing ? `+${deltaDispatches} active` : 'STALLED / FROZEN'})`);
            log(`Main Thread Registers  : EIP=0x${mainCpu.eip.toString(16).padStart(8, '0')} ESP=0x${mainCpu.esp.toString(16).padStart(8, '0')} [ESP]=0x${stackTopVal.toString(16).padStart(8, '0')}`);
            log(`                         EAX=0x${mainCpu.eax.toString(16).padStart(8, '0')} ECX=0x${mainCpu.ecx.toString(16).padStart(8, '0')} EDX=0x${mainCpu.edx.toString(16).padStart(8, '0')} EBX=0x${mainCpu.ebx.toString(16).padStart(8, '0')} ESI=0x${mainCpu.esi.toString(16).padStart(8, '0')}`);

            const traceStr = trace.map(e => `0x${e.va.toString(16).padStart(8, '0')}(esp=0x${e.esp.toString(16).padStart(8, '0')})`).join(' -> ');
            log(`Recent Dispatches (16) : ${traceStr}`);

            for (let s = 0; s < 8; s++) {
                const ws = readWorkerCpu(s);
                const mb = readWorkerMailbox(s);
                if (ws.traceIdx > 0 || mb.state > 0 || mb.entry > 0) {
                    log(`Worker Slot #${s}        : dispatches=${ws.traceIdx} EIP=0x${ws.eip.toString(16).padStart(8, '0')} ESP=0x${ws.esp.toString(16).padStart(8, '0')} state=${mb.state} entry=0x${mb.entry.toString(16).padStart(8, '0')}`);
                }
            }

            const poolA = readTaskPool(TASK_POOL_A_VA, 'PoolA');
            const poolB = readTaskPool(TASK_POOL_B_VA, 'PoolB');
            if (poolA.length > 0) {
                const poolAStr = poolA.map(s => `[slot ${s.slot}: stat=${s.status} ptr=${s.compPtr} val=${s.compVal}]`).join(', ');
                log(`Task Pool A (0x00b44e00): ${poolAStr}`);
            }
            if (poolB.length > 0) {
                const poolBStr = poolB.map(s => `[slot ${s.slot}: stat=${s.status} ptr=${s.compPtr} val=${s.compVal}]`).join(', ');
                log(`Task Pool B (0x00b45000): ${poolBStr}`);
            }

            log(`Direct3D 9 Ring Buffer : magic=0x${d3d.magic.toString(16)} head=${d3d.head} tail=${d3d.tail} frameCount=${d3d.frameIndex} cmdCount=${d3d.cmds.length}`);
            log(`Boot Checkpoints       : sub_006daa70 (startup)=${seenDaA70 ? (seenDaA70Return ? 'RETURNED' : 'ENTERED') : 'NOT_SEEN'}, sub_006dae50 (frame tick)=${seenDaE50 ? (seenDaE50Return ? 'RETURNED' : 'ENTERED') : 'NOT_SEEN'}`);

            lastTraceIdx = mainCpu.traceIdx;
        }
    }
}, 100);

parentPort.on('message', (msg) => {
    if (msg === 'STOP') {
        clearInterval(interval);
        process.exit(0);
    }
});
