import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createGuestMemory,
  createWasiImports,
  initializeDispatchTable,
  initializeReactor,
  instantiateProStreet,
  isDispatchTableInitialized,
  isReactorInitialized,
  ProStreetManifest,
} from '../src/wasm_loader.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.resolve(__dirname, '../public');
const GAME_WASM = path.resolve(__dirname, '../../build/game.wasm');

// Minimal module: imports shared env.memory (16..32 pages) and re-exports it as "memory".
// Mirrors the legacy/synthetic build contract (see tools/build_wasm.py build_synthetic_wasm_binary).
const LEGACY_IMPORTING_MODULE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
  0x02, 0x10, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x03, 0x10, 0x20, // import env.memory
  0x07, 0x0a, 0x01, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, // export memory
]);

function legacyManifest(guestEnd: number): ProStreetManifest {
  return {
    pages: 16,
    maxPages: 32,
    guestEnd,
    size: LEGACY_IMPORTING_MODULE.length,
    opt: '-O0',
    toolchain: 'test',
    shards: 0,
    functions: 0,
    compiledAt: '',
  };
}

test('WasmLoader verifies prostreet.json manifest schema', () => {
  const jsonPath = path.join(PUBLIC_DIR, 'prostreet.json');
  assert.ok(fs.existsSync(jsonPath), 'prostreet.json must exist');

  const raw = fs.readFileSync(jsonPath, 'utf-8');
  const manifest: ProStreetManifest = JSON.parse(raw);

  assert.equal(manifest.pages, 16384); // 1024 MB
  assert.equal(manifest.maxPages, 65536); // 4096 MB
  assert.equal(manifest.guestEnd, 671088640); // 640 MB
  assert.equal(manifest.shards, 32);
  assert.equal(manifest.functions, 31995);
  assert.ok(manifest.size > 0);
});

test('WasmLoader creates guest linear memory according to manifest', () => {
  const manifest: ProStreetManifest = {
    pages: 16,
    maxPages: 32,
    guestEnd: 671088640,
    size: 100,
    opt: '-O3',
    toolchain: 'synthetic-wasm-host',
    shards: 32,
    functions: 31995,
    compiledAt: new Date().toISOString(),
  };

  const mem = createGuestMemory(manifest);
  assert.ok(mem instanceof WebAssembly.Memory);
  assert.ok(mem.buffer.byteLength >= 16 * 65536);
});

test('WasmLoader creates WASI syscall imports and processes fd_write stdout', () => {
  const mem = new WebAssembly.Memory({ initial: 2, maximum: 4 });
  let captured = '';

  const wasi = createWasiImports(mem, (text) => {
    captured += text;
  });

  assert.ok(typeof wasi.proc_exit === 'function');
  assert.ok(typeof wasi.fd_write === 'function');
  assert.ok(typeof wasi.clock_time_get === 'function');

  // Write a string to guest memory at 0x100
  const view = new DataView(mem.buffer);
  const u8 = new Uint8Array(mem.buffer);
  const msg = 'Need for Speed ProStreet Engine Boot\n';
  const encoded = new TextEncoder().encode(msg);
  u8.set(encoded, 0x100);

  // Set up iovec at 0x20: { ptr: 0x100, len: msg.length }
  view.setUint32(0x20, 0x100, true);
  view.setUint32(0x24, encoded.length, true);

  // Invoke fd_write(fd=1, iovs=0x20, iovsLen=1, nwritten=0x30)
  const ret = wasi.fd_write(1, 0x20, 1, 0x30);
  assert.equal(ret, 0);
  assert.equal(view.getUint32(0x30, true), encoded.length);
  assert.equal(captured, msg);
});

test('WasmLoader WASI shims accept a lazy memory getter (module-owned memory)', () => {
  const mem = new WebAssembly.Memory({ initial: 2, maximum: 4 });
  let captured = '';
  const wasi = createWasiImports(() => mem, (text) => {
    captured += text;
  });

  const msg = 'lazy\n';
  const encoded = new TextEncoder().encode(msg);
  new Uint8Array(mem.buffer).set(encoded, 0x100);
  const view = new DataView(mem.buffer);
  view.setUint32(0x20, 0x100, true);
  view.setUint32(0x24, encoded.length, true);

  assert.equal(wasi.fd_write(1, 0x20, 1, 0x30), 0);
  assert.equal(captured, msg);

  // A getter that has no memory yet must fail loudly, not silently write nowhere
  const early = createWasiImports(() => {
    throw new Error('memory not resolved');
  });
  assert.throws(() => early.fd_write(1, 0, 0, 0), /memory not resolved/);
});

test('WasmLoader (legacy) module importing env.memory shares the host-created memory', async () => {
  const module = await WebAssembly.compile(LEGACY_IMPORTING_MODULE);
  const engine = await instantiateProStreet(module, legacyManifest(65536));

  assert.ok(engine.memory instanceof WebAssembly.Memory);
  assert.equal(engine.memory, engine.exports.memory, 'LoadedEngine.memory must be the exported memory');
  assert.equal(engine.memory.buffer.byteLength, 16 * 65536, 'host-created memory is what the module received');
});

test('WasmLoader rejects an engine memory smaller than the guest arena', async () => {
  const module = await WebAssembly.compile(LEGACY_IMPORTING_MODULE);
  await assert.rejects(
    () => instantiateProStreet(module, legacyManifest(16 * 65536 + 1)),
    /smaller than the guest arena/
  );
});

// Minimal WASI reactor module: owns a 1-page memory and exports `_initialize`.
// First call increments i32 at offset 0 from 0 -> 1; any subsequent raw call traps
// with `unreachable` (reproducing wasi-sdk crt1-reactor.c double-init trap).
const SYNTHETIC_REACTOR_MODULE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
  0x03, 0x02, 0x01, 0x00,
  0x05, 0x04, 0x01, 0x01, 0x01, 0x02,
  0x07, 0x18, 0x02,
    0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
    0x0b, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x00,
  0x0a, 0x1a, 0x01, 0x18, 0x00,
    0x41, 0x00, 0x28, 0x02, 0x00,
    0x04, 0x40, 0x00, 0x0b,
    0x41, 0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x41, 0x01, 0x6a, 0x36, 0x02, 0x00,
    0x0b,
]);

test('WasmLoader invokes _initialize() exactly once and guards against double-init (Task 3.3c-3a)', async () => {
  const module = await WebAssembly.compile(SYNTHETIC_REACTOR_MODULE);
  const engine = await instantiateProStreet(module, legacyManifest(65536));

  const view = new DataView(engine.memory.buffer);
  assert.equal(view.getUint32(0, true), 1, '_initialize() must run automatically during instantiateProStreet');
  assert.equal(isReactorInitialized(engine.instance), true);

  // Calling initializeReactor or engine.exports._initialize again must be a safe no-op (no unreachable trap)
  assert.equal(initializeReactor(engine.instance), false, 'second initializeReactor call must return false');
  assert.doesNotThrow(() => {
    engine.exports._initialize?.();
  });
  assert.equal(view.getUint32(0, true), 1, '_initialize counter must remain 1 after guarded repeat calls');
});

test('WasmLoader uses the module-owned memory of the real game.wasm (single-memory contract)', {
  skip: !fs.existsSync(GAME_WASM) && 'build/game.wasm not built',
}, async () => {
  const manifest: ProStreetManifest = JSON.parse(
    fs.readFileSync(path.join(PUBLIC_DIR, 'prostreet.json'), 'utf-8')
  );
  const module = await WebAssembly.compile(fs.readFileSync(GAME_WASM));

  // The real engine imports no memory: it owns one and exports it.
  const imports = WebAssembly.Module.imports(module);
  assert.equal(imports.some((i) => i.kind === 'memory'), false, 'game.wasm must not import a memory');

  const engine = await instantiateProStreet(module, manifest);
  assert.equal(engine.memory, engine.exports.memory, 'LoadedEngine.memory must be the module exported memory');
  assert.ok(engine.memory.buffer.byteLength >= manifest.guestEnd, 'guest arena must fit in engine memory');

  // Verify Task 3.3c-3a on real game.wasm: _initialize() ran once during instantiateProStreet
  // and subsequent guarded calls do not trap, whereas a raw second call to instance.exports._initialize traps.
  assert.equal(isReactorInitialized(engine.instance), true, 'real game.wasm reactor must be initialized');
  assert.equal(initializeReactor(engine.instance), false, 'repeat initializeReactor must be a no-op');
  assert.doesNotThrow(() => {
    engine.exports._initialize?.();
  }, 'guarded engine.exports._initialize() must not trap on repeat calls');
  assert.throws(
    () => {
      (engine.instance.exports as any)._initialize();
    },
    /unreachable/,
    'raw instance.exports._initialize() must trap because instantiateProStreet already ran it once'
  );

  // Verify Task 3.3c-3b on real game.wasm: fntab_init() ran right after _initialize()
  // and populated g_dtab as reported by fntab_count().
  assert.equal(isDispatchTableInitialized(engine.instance), true, 'g_dtab must be initialized by instantiateProStreet');
  assert.equal(initializeDispatchTable(engine.instance), false, 'repeat initializeDispatchTable must be a no-op');
  assert.equal(typeof engine.exports.fntab_count, 'function', 'game.wasm must export fntab_count()');
  const populatedCount = engine.exports.fntab_count!();
  assert.equal(populatedCount, 30796, 'fntab_count() must report all 30,796 populated g_dtab entries');

  // Prove host and engine see the SAME bytes: the host plants a sentinel in g_boot_status.argc,
  // the engine zeroes the struct in boot_reset_status(); the host must then observe the zero.
  const exp = engine.exports as any;
  const statusPtr: number = exp.boot_get_status();
  assert.ok(statusPtr > 0, 'boot_get_status must return a guest pointer');
  const argcOffset = statusPtr + 4;
  new DataView(engine.memory.buffer).setUint32(argcOffset, 0xdeadbeef, true);
  exp.boot_reset_status();
  assert.equal(
    new DataView(engine.memory.buffer).getUint32(argcOffset, true),
    0,
    'engine write must be visible through LoadedEngine.memory'
  );
});

const NFS_EXE_PATH = 'C:/Games/Pro Street/Need For Spped - Pro Street/nfs.exe';

test('WasmLoader prostreet_tick() through loader path never hangs before or after engine init (Task 3.3c-3c)', {
  skip: !fs.existsSync(GAME_WASM) && 'build/game.wasm not built',
  timeout: 5000,
}, async () => {
  const manifest: ProStreetManifest = JSON.parse(
    fs.readFileSync(path.join(PUBLIC_DIR, 'prostreet.json'), 'utf-8')
  );
  const module = await WebAssembly.compile(fs.readFileSync(GAME_WASM));
  const engine = await instantiateProStreet(module, manifest);
  const exp = engine.exports as any;

  // 1. Before PE + C++ static constructors have run (e.g. when /data/nfs.exe is absent),
  // prostreet_tick() must return -2 immediately rather than hanging in sub_0074ac50's
  // uninitialized circular list at 0x00a79bc8 (Finding F2).
  const tUnbooted0 = performance.now();
  const unbootedRc = engine.exports.prostreet_tick!(16666);
  const unbootedMs = performance.now() - tUnbooted0;
  assert.equal(unbootedRc, -2, 'prostreet_tick before static constructors must return -2');
  assert.ok(unbootedMs < 50, `unbooted prostreet_tick must return immediately (took ${unbootedMs.toFixed(2)}ms)`);

  // 2. When nfs.exe is present, complete the engine init on the LoadedEngine and verify
  // prostreet_tick() executes sub_006dae50 and returns 0 within the hard timeout.
  if (fs.existsSync(NFS_EXE_PATH)) {
    const exeBuf = fs.readFileSync(NFS_EXE_PATH);
    const peOff = exeBuf.readUInt32LE(0x3c);
    const numSec = exeBuf.readUInt16LE(peOff + 6);
    const optSize = exeBuf.readUInt16LE(peOff + 20);
    let secHead = peOff + 24 + optSize;
    const wasmMem = new Uint8Array(engine.memory.buffer);
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

    const dv = new DataView(engine.memory.buffer);
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

    exp.boot_bind_iats();
    exp.boot_install_hooks();

    const CPU_STRUCT_VA = 0x00104000;
    dv.setUint32(CPU_STRUCT_VA + 16, 0x003ff000, true);
    dv.setUint32(CPU_STRUCT_VA + 32, 0x004afee0, true);
    dv.setUint32(CPU_STRUCT_VA + 36, TEB, true);

    assert.equal(exp.initterm_run_cpp_constructors(CPU_STRUCT_VA), 960);
    exp.boot_setup_arguments(CPU_STRUCT_VA, 1, 0);
    assert.equal(exp.boot_invoke_main(CPU_STRUCT_VA, 1), 0);

    const tTick0 = performance.now();
    const tickRc = engine.exports.prostreet_tick!(16666);
    const tickMs = performance.now() - tTick0;
    assert.equal(tickRc, 0, 'booted prostreet_tick must return 0');
    assert.ok(tickMs < 50, `booted prostreet_tick must complete well under 50ms (took ${tickMs.toFixed(2)}ms)`);
  }
});

test('WasmLoader validates and instantiates the shipped prostreet.wasm binary', async () => {
  const wasmPath = path.join(PUBLIC_DIR, 'prostreet.wasm');
  assert.ok(fs.existsSync(wasmPath), 'prostreet.wasm must exist');

  const wasmBytes = fs.readFileSync(wasmPath);
  assert.ok(WebAssembly.validate(wasmBytes), 'prostreet.wasm must be valid WebAssembly');

  const module = await WebAssembly.compile(wasmBytes);
  assert.ok(module instanceof WebAssembly.Module);

  const manifest = JSON.parse(fs.readFileSync(path.join(PUBLIC_DIR, 'prostreet.json'), 'utf-8'));
  const engine = await instantiateProStreet(module, manifest);
  assert.ok(engine.instance instanceof WebAssembly.Instance);
  assert.equal(engine.memory, engine.exports.memory);

  const exp = engine.exports as any;
  assert.ok(typeof exp.prostreet_main === 'function');
  assert.ok(typeof exp.prostreet_get_guest_memory === 'function');
  assert.ok(typeof exp.prostreet_tick === 'function');
  // NOTE: prostreet_main()/prostreet_tick() are deliberately NOT invoked here. The real engine
  // needs _initialize()/fntab_init() first (plan 3.3c-3) and a non-blocking init entry (3.3c-4);
  // calling them on a bare instance hangs. They are exercised end-to-end from 3.3c-3 onward.
});
