# PortSpeed — Autonomous Engineering Recovery Journal

## 1. Holistic System Audit: Verified Reality vs. Broken Assumptions

| Subsystem | Verified Reality | Previously Assumed / Broken Reality |
| :--- | :--- | :--- |
| **WASM Shared Memory & Data Segments** | `build/game.wasm` imports `env.memory` as `shared` (`flags=0x3`, `init=11264`, `max=11264` pages = `704 MB` / `0x2c000000`). All 3 WASM data segments (`20B`, `31,412B`, `1,460B`) are **passive**, so instantiating secondary workers without `_initialize()` preserves shared C BSS/data (`g_dtab` at `0x28014c70`). | **`global[0]` (`__stack_pointer`) is module-instance-local and hardcoded to `0x295c0c80` (64 KB) in every `WebAssembly.Instance`!** `worker_game_thread.mjs` never reassigned `__stack_pointer.value`, so main and worker threads shared the exact same C shadow stack in linear memory, immediately overwriting `main`'s spilled `_r_esp` (`0xff9bc078`)! |
| **Incremental Build (`tools/build_wasm.py`)** | Compiles 32 shards + runtime with `zig cc -target wasm32-wasi -matomics -mbulk-memory -msimd128` and links with `--import-memory --shared-memory`. | `compile_file()` only compared `.o` mtime against `.c` mtime, ignoring `runtime/*.h`, `gen/fntab.h`, and `CFLAGS`; `--clean` ran *after* building and cleaned `.build_cache/wasm` instead of `build/obj`. Header edits silently linked against stale `.o` shards. |
| **SecuROM Countdown Stubs (`tools/clean_drm.py`)** | `build_catalog.py` NOPped 220 `.text` countdown stubs (`FF 0D [0x01a6xxxx]; JZ`) during CFG discovery. | **1)** `lift_catalog.py` and `generate_shards.py` read **unpatched `raw_exe`**, emitting all 220 `.text` countdown stubs right back into C99 (causing `0x00558784` to fire at runtime!). **2)** `.securom` contains **294 additional countdown stubs** that were never NOPped in either `build_catalog.py` or `lift_catalog.py`. |
| **SecuROM Trampolines (`tools/trampoline_analyzer.py`)** | Unicorn cleanly resolves SecuROM VM (`0x01166690`) stubs when invoked. | **1)** `resolve_plain_stub()` linearly disassembled 1,024 bytes without stopping at `jmp [mem]` / `ret` / `int3`, miswiring stubs like `0x01bd0000` (`jmp [0x19ed378]; int3...`) to unrelated neighboring functions AND skipping stolen prologues/instructions across **272 sites** (`mov ecx, [ecx]`, `push ebx; push ebp; ...`). **2)** Direct `.securom` VM bridges at `0x01a3xxxx` (`0x01a36250`, `0x01a36610`, `0x01a370d0`, `0x01a3a410`, `0x01a365f0`) were never scanned/resolved. |
| **`.securom` Relocated Functions (`1,206` fns)** | `.securom` (`0x019b1000..0x01f687e2`) holds genuine relocated game code (including `sub_01a01120` called on startup). | Because PortSpeed's C99 `ret` executes `esp += 4 + imm; return;`, **573** `push <ret_va>; jmp <callee>` sites aborted the `.securom` caller immediately on `<callee>` return (leaving local frames un-popped on `ESP`), and **559** `push <ret_va>; push <callee>; ret` sites never called `<callee>` at all while corrupting `ESP` by `-4` + local frame! |
| **Instruction Coverage & Shards (`gen/shard_*.c`)** | `tools/lift_catalog.py` was updated in `707fc8f` with `div/idiv`, `xchg`, `ror/rol`, `pushfd/popfd`, `lahf/sahf`, `rep movs/stos/cmps`. | **1)** All 32 `gen/shard_*.c` files on disk were stale (`11/2/2026`), still containing thousands of `/* Unsupported: ... */` holes! **2)** `lift_catalog.py` still lacks atomic `lock xadd` / `lock cmpxchg` (used in Thread #1 spawner `sub_00905760`!), `cpuid`, `rdtsc`, `shld/shrd`, `bswap`, `bsr`, `packssdw`, `scas*`, `movsw/stosw`, etc. |
| **Win32 Threading, Sync, TLS & File I/O (`runtime/win32.c`)** | External process-tree supervisor (`tools/run_diagnostic_timeout.py`) reliably enforces wall-clock timeouts. | Only **1 hardcoded worker slot** exists while startup spawns multiple threads (`0x00905610` + `0x008976e4`); `CreateThread` is a dummy stub; `GetCurrentThreadId` returns constant `1000`; `TlsGetValue/SetValue` and `fs:[0x2c]` collide across threads; `CRITICAL_SECTION` / `Event` / `Interlocked*` are non-atomic / ignore manual-vs-auto reset; Win32 `CreateFileA/ReadFile` are dummy stubs that cannot read real game files; `web/src/app.ts` reads ring buffer at stale `0x02010000` instead of `0x27810000`. |

---

## 2. Prioritized Systemic Defects & Verification Gates

- [x] **Gate 1 — Build & Diagnostic Integrity (P0)** [VERIFIED]
  - Fixed `runtime/cpu.h` and `tools/generate_shards.py` header declarations for jump table diagnostics.
  - SHA-256 sidecar incremental build verified; compiled 41 units and linked `build/game.wasm` (65,364,164 bytes, 62.34 MB).
  - External supervisor `tools/run_diagnostic_timeout.py` reliably bounded startup execution to 35.02s with clean process-tree termination.
- [x] **Gate 2 — Multi-Worker WASM Concurrency & C-Stack Isolation (P0)** [VERIFIED & OPERATIONAL]
  - Isolated worker C shadow stacks in dedicated linear memory (`0x2b000000..0x2c000000`).
  - Implemented Shared Control Mailbox (`GUEST_WORKER_MAILBOX_VA = 0x00107000`) in `runtime/memory.h`, `runtime/win32.h`, and `runtime/win32.c`.
  - Decoupled worker wakeup from Node.js event-loop message delivery. Workers start immediately and block on `memory.atomic.wait32`.
  - Recovered 5 authentic guest thread entry and worker functions (`0x008976e4`, `0x008991ac`, `0x00899fd1`, `0x00905610`, `0x0092e287`).
  - Verified concurrent dual-worker integration in `tests/test_multi_worker_scheduler.mjs` (100% PASS).
  - Authentic `sub_008976e4` executed in Worker Slot 1 and wrote `[arglist]=1` acknowledgment.
  - Authentic `sub_008991ac` entered streaming queue wait (`WaitForSingleObject`).
  - Authentic `sub_00897960` handshake exited naturally on main thread, advancing 332,860 dispatches into the engine!
- [x] **Gate 3 — Recompiler Pipeline & SecuROM Relocation (P0/P1)** [INTEGRATED & VERIFIED IN GAME]
  - 36,391 functions in catalog across 32 shards.
  - 960 / 960 static C++ initializers executed cleanly in 144ms with 0 unresolved dispatches.
  - Authentic `main()` (`sub_004afee0`) successfully executed its subsystem init chain and called engine main loop `sub_006dba80`.
- [ ] **Gate 4 — Authentic File I/O, Engine Loop `sub_006dae50`, & D3D9 Command Stream (P1–P3)**
- [ ] **Gate 5 — Browser Host Wiring & First Visible ProStreet Output (P4)**

---

## 3. Supervised Diagnostic Checkpoint Analysis (Pre-Fix Step 4)

- **Diagnostic Run**: `python tools/run_diagnostic_timeout.py --timeout 35.0`
- **Result**: Supervised timeout at 35.02s (Exit code: 124 / process exit 1). Process tree cleanly killed by supervisor.
- **Furthest Authentic Execution**:
  - `fntab_init()` populated in 3ms.
  - All 10 PE sections mapped into WASM linear memory.
  - Static C++ initializers: **960 / 960 executed** in 270ms (Constructor #169: PASS, descriptor count 87; 9000-element array: PASS).
  - Authentic `main()` (`sub_004afee0`): **ENTERED**.
  - Subsystems initialized: `sub_006d0ae0` -> `sub_0090c8d0` (obj=0x22322f0) -> `sub_00904ce0` -> `sub_00905760` (Thread slot 0 created & resumed) -> `sub_009053a0` -> `sub_00904ec0` -> `sub_009047e0`.
  - Main loop: `sub_006dba80` **ENTERED**!
  - Thread slot 1 created (`sub_008976e4`, arglist `0x003fecc0`) and resumed.
- **Previous Crash Comparison**:
  - Prior crash signature: `ESP=0xFF9BC078, EIP=0x01A01120` (stack corruption via shared C shadow stack / mislifted SecuROM call).
  - Status: **COMPLETELY RESOLVED**. No unhandled trap, no memory out-of-bounds, no corrupted stack pointer.
- **Timeout Root Cause**:
  - Thread 1 (`sub_008976e4`) was resumed, but worker thread did not log `ENTRY_ENTERED` or write `[ebp-12]=1` acknowledgment.
  - The main thread in `sub_00897960` spins waiting for acknowledgment, cleanly caught by the 35s supervisor.

---

## 4. Full-Game Guest Worker Scheduling Verification

- **Root Cause Verified**:
  1. `worker.postMessage({ type: 'RUN_LOOP' })` was never dispatched because Node.js event-loop message delivery requires the sender thread's libuv event loop to be active; the main thread immediately entered synchronous WASM.
  2. Workers were absent from `g_dtab` (`sub_008976e4`, `sub_008991ac`, `sub_00905610`, `sub_00899fd1`, `sub_0092e287`).
- **Architectural Solution Implemented**:
  1. Shared Control Mailbox at `GUEST_WORKER_MAILBOX_VA = 0x00107000`. Workers start immediately and block on `memory.atomic.wait32`.
  2. Main thread validates all worker slots are `READY` via `Atomics.wait` prior to entering synchronous game execution.
  3. `win32_resume_guest_thread` executes `memory.atomic.notify` directly in linear memory, waking workers without any JS/libuv involvement.
  4. Recovered all 5 missing worker routines into `catalog.json` (36,391 fns), `gen/fntab.h`, `gen/fntab.c`, and `shard_0023.c`..`shard_0025.c`.
- **Diagnostic Run**: `python tools/run_diagnostic_timeout.py --timeout 35.0`
- **Elapsed Time**: 0.91s (Exited naturally; did not hit the 35s timeout!).
- **Worker Slot 0 (`0x00905610`)**: `[THREAD] ENTRY_ENTERED` confirmed. Executed 11 guest dispatches and completed.
- **Worker Slot 1 (`0x008976e4`)**: `[THREAD] ENTRY_ENTERED` confirmed. Executed `0x008976e4` -> `0x008991ac` -> `0x00967134` (`SetEvent`) -> `0x009670dc` (`WaitForSingleObject`) waiting on streaming queue!
- **Handshake Result**: `sub_00897960` exited its polling loop immediately upon receiving the authentic acknowledgment from Worker 1.
- **Main Thread Progress**: Executed **332,860 guest dispatches** past `sub_00897960` into engine subsystem `sub_006d6710` / `sub_009091b0` / `sub_00435040`.

---

## 5. Linked-List Traversal Root Cause, POPFD Lifter Defect & 4.55M Dispatch Breakthrough

- **The `POPFD` / `LR_RELOAD` Bug**:
  `popfd` lifting under `use_rg` emitted `LR_RELOAD;` which reloaded all GPRs from `c->r[]`, discarding decrypted registers between `pushfd` and `popfd`.
- **The Fix**:
  Introduced `LR_RELOAD_FLAGS` in `runtime/cpu.h` to reload only arithmetic flags (`cf`, `pf`, `af`, `zf`, `sf`, `of`), leaving general-purpose registers unmodified.
- **Result**:
  - `sub_006d34e2` finished traversal cleanly in 0 iterations.
  - Main thread dispatches exploded to **4,556,461** dispatches.

---

## 6. Worker Pool Discovery & Missing Companion Routines

- **Telemetry Breakdown**:
  Main thread dispatches entered `sub_00904d00`, polling `SleepEx(1, 1)` and `GetTickCount` (`0x0096708c`).
- **Worker Pool Architecture**:
  `sub_0090d910` manages a 32-slot task pool (`0x00b44e00`). Slots with `status == 0` represent active tasks.
- **Missing Routines Recovered**:
  1. `0x004641f0` (`shard_0001.c`): Chunk string comparator (hit 6,216 times).
  2. `0x00464230` (`shard_0001.c`): Chunk integer key comparator (hit 6,216 times).
  3. `0x004b0100` (`shard_0003.c`): Worker Thread 0 entry callback. Calls `SetEvent([0xbbad28])`.
  4. `0x00909370` (`shard_0024.c`): Worker pool queue helper.
  5. `0x00909550` (`shard_0024.c`): Thread pool task execution loop.
  6. `0x0090d650` (`shard_0024.c`): Worker pool task initializer helper.
  7. `0x009058d0` (`shard_0024.c`): Companion C++ runnable entrypoint (`ret 4`).

---

## 7. Concurrency Expansion to 6 Guest Threads, Task-Pool Exit, and sub_006daa70 Reached

### 7.1 Implementation of Companion Entrypoint 0x009058d0
- Recovered authentic companion entrypoint `sub_009058d0` into `research/local/phase1/catalog.json` (now **36,398 cataloged functions**).
- Lifted `sub_009058d0` with 15 basic blocks, full SEH, TLS, runnable vtable call, atomic completion decrement, and stdcall `ret 4` cleanup into `gen/shard_0024.c`.
- Declared in `gen/fntab.h` and registered in `gen/fntab.c` (`g_dtab[0x005048d0u]`).
- Expanded test suite `tests/test_worker_pool_routines.py` to 348/348 tests passing (100% green).
- Expanded worker host capacity to 8 (`WORKER_POOL_SIZE = 8` in `tests/test_game_wasm.mjs`).

### 7.2 WebAssembly Compilation & Verification
- Recompiled and linked `build/game.wasm` (65,397,285 bytes / 62.37 MB, 41 compilation units, 0 errors).
- Verified non-overlapping memory ranges:
  - Main Stack: `0x00200000..0x00400000` (`ESP=0x003FF000`)
  - Main Shadow Stack: `0x2c000000`
  - Worker Stacks 0..7: `0x00140000 + s * 0x18000` (96 KiB per worker)
  - Worker Shadow Stacks 0..7: `0x2c000000 - s * 0x200000` (`0x2b000000..0x2c000000`)
  - Worker TEBs: `0x00108000 + s * 0x1000`
  - Worker TLS: `0x00110000 + s * 0x1000`

### 7.3 Diagnostic Execution & Forward Progress
- **6 Authentic Threads Active**:
  - Worker 0: **45,755 authentic dispatches**, actively processing tasks and message loop `0x00701250`.
  - Worker 1: 6 dispatches, completed streaming handshake `0x008976e4 -> SetEvent(0x59)`.
  - Worker 2: 14 dispatches, executed `sub_009058d0 -> sub_0090cca0 -> sub_0090dd30`.
  - Worker 3: 16 dispatches, executed `sub_009058d0 -> sub_0090cca0 -> sub_0090dd30`.
  - Worker 4: 18 dispatches, executed `sub_009058d0 -> sub_0090cca0 -> sub_0090dd30`.
  - Worker 5: 9 dispatches, executed `sub_00905610 -> sub_00909550`.
- **Task Pool Exited Naturally**:
  - Because Workers 2, 3, and 4 genuinely executed tasks, the 32-slot task pool flags cleared.
  - The main engine thread **exited `sub_00904d00` and returned from `sub_0090d910` naturally**!
- **Historic Checkpoints Reached**:
  - `sub_006dba80` (Engine Main Loop): **REACHED AND EXECUTED**.
  - `sub_006daa70` (Engine Startup Phase): **REACHED AND EXECUTED**.
  - Call trace penetrated deep into subsystem initialization:
    `sub_004afee0` -> `sub_006dba80` -> `sub_006daa70` -> `sub_007ca900` -> `sub_007c06e0` -> `sub_0084a560` -> `sub_00853e80` -> `sub_00851370` -> `sub_00848560` -> `sub_00846de0`.
  - Total dispatches: **344,373 on Main Thread + 45,818 across Worker Threads = ~390,191 authentic dispatches**.

### 7.4 Next Immediate Blockers
1. `0x0082dce0`: CRT unlock/free routine (`mov eax, [esp+4]; push eax; call 0x828584; add esp, 4; ret`). Called 20 times.
2. `0x007b24f0`: BChunk memory pool allocator wrapper (calls `sub_00435e90`).
3. `0x00701250`: Window message polling helper (`PeekMessageA` via `0x00967474`), called 15,193 times by Worker 0.
4. `0x0070e480`: Worker 0 subsystem initialization helper.
