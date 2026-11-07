# PortSpeed

> **Experimental native browser port of Need for Speed: ProStreet (PC v1.1, 2007) via static x86 Ahead-Of-Time recompilation and WebAssembly.**

---

## Legal & Research Disclaimer

**PortSpeed is an independent reverse-engineering, binary translation, and digital preservation research project.**
- This project is **not** affiliated with, sponsored by, or endorsed by Electronic Arts, EA Black Box, or their licensors.
- "Need for Speed" and "Need for Speed: ProStreet" are trademarks of Electronic Arts Inc.
- **No copyrighted game assets, proprietary game executables, or original binary assets are distributed in this repository.** Users must supply their own legally purchased copy of *Need for Speed: ProStreet* (PC v1.1, `nfs.exe`).

---

## Architectural Foundation: Static AOT Binary Recompilation

PortSpeed translates the original 2007 Windows x86 game code to modern web browsers via **Ahead-Of-Time (AOT) static binary recompilation** rather than instruction-by-instruction emulation or building a reimplemented racing clone:

```mermaid
graph TD
    A["Original PC nfs.exe (28.7 MB)"] --> B["Phase 1: SecuROM Deobfuscation & Cataloging"]
    B --> C["Phase 2: Static x86 -> C99 Lifter (36,391 functions, 32 shards)"]
    C --> D["Phase 3: Platform Runtime & Engine Boot (Shared-WASM Threads, CRT, Win32)"]
    D --> E["Phase 4: Direct3D 9 Command Ring Buffer & WebGPU / WebGL2"]
    E --> F["Phase 5: AudioWorklet, DirectInput & OPFS Asset Streaming"]
    F --> G["Phase 6: In-Game Racing Simulation & Gameplay Loop"]
```

1. **Static Ahead-Of-Time Lifter:** 36,391 authentic x86 functions cataloged and lifted into 32 modular C99 translation units (`gen/shard_0000.c` .. `gen/shard_0031.c`) with WebAssembly SIMD128 intrinsics, 80-bit precision x87 circular stack emulation, and bit-parallel arithmetic flag computation (`FLAGS_ADC_M`, `FLAGS_SBB_M`, `FLAGS_LOG_M`).
2. **1:1 Guest Linear Memory Layout:** 704 MB shared WebAssembly linear memory (`IMAGE_BASE=0`, `0x00000000..0x2c000000`). Guest virtual addresses map directly to linear memory offsets without pointer translation overhead.
3. **Master Dispatch Table (`g_dtab`):** Direct $O(1)$ function pointer array of 5,660,672 entries covering `0x00401000..0x00967000`, resolving direct and indirect dispatches at native speed.
4. **Shared-WASM Threading & Control Mailbox:** Secondary Web Workers instantiate the identical WebAssembly module with imported shared memory. Per-worker C shadow stacks are strictly isolated in high linear memory (`0x2b000000..0x2c000000`, 2 MB each). Worker thread synchronization and scheduling operate via a dedicated Shared Control Mailbox (`0x00107000`) and native WebAssembly atomics (`memory.atomic.wait32` / `memory.atomic.notify`).
5. **Clean CRT & Win32 Shim Layer:** Dynamic `MSVCR80.dll` IAT imports (156 functions) and Win32 imports (198 functions) shimmed in clean C99.
6. **Zero Remake / Authentic Scope:** PortSpeed executes genuine game machine code. No synthetic tracks, placeholder vehicles, or hardcoded game loops exist.

---

## Current Engineering Status & Verified Reality

> [!WARNING]
> **Authenticity & Playability Status**:
> - **The game is NOT yet playable in the browser.**
> - **Original 3D world rendering, menus, and visual gameplay frames are NOT yet produced.**
> - **Zero authentic rendered frames have been output to the screen.**
> - The production WebAssembly binary [`build/game.wasm`](file:///c:/Users/tabat/OneDrive/Desktop/NFS-PortStreet-Project/build/game.wasm) (**62.34 MB**) builds cleanly with atomics and shared memory.
> - In genuine WebAssembly execution under Node.js WASI, the engine executes all **960 / 960 static C++ initializers**, enters genuine `main()` ([`sub_004afee0`](file:///c:/Users/tabat/OneDrive/Desktop/NFS-PortStreet-Project/gen/shard_0002.c)), initializes engine subsystems, spawns and resumes two guest worker threads, authentically completes the streaming thread startup handshake, and executes **332,860 guest dispatches** before trapping.
> - **Active Blocker:** A stack pointer divergence (`ESP = 0xff9bc0d0`) occurs at 332,860 dispatches inside vector destructor helper `sub_008285e8` (`__ehvec_dtor`), triggering an out-of-bounds linear memory trap.

---

## Detailed Milestone Status: Implemented vs. Pending

| Subsystem / Feature | Status | Verification & Evidence |
| :--- | :--- | :--- |
| **SecuROM Deobfuscation** | **IMPLEMENTED & VERIFIED** | 220 `.text` + 294 `.securom` countdown stubs neutralized; 2,153 indirect trampolines resolved; stolen prologues recovered. |
| **x86 to C99 Instruction Lifter** | **IMPLEMENTED & VERIFIED** | 36,391 functions lifted across 32 shards; SIMD128, 80-bit x87 FPU, atomic `lock xadd`/`cmpxchg`, bit-parallel flags. |
| **Master Dispatch Table (`g_dtab`)** | **IMPLEMENTED & VERIFIED** | Direct $O(1)$ table covering `0x00401000..0x00967000` (5.6M entries); initialized in 3 ms. |
| **C++ Static Initializers (`_initterm`)** | **IMPLEMENTED & VERIFIED** | All **960 / 960** initializers execute to completion in 144 ms with 0 unresolved dispatches. Constructor #169 verified. |
| **Authentic `main()` Entry** | **IMPLEMENTED & VERIFIED** | `sub_004afee0` entered with valid Win32 arguments; root subsystems initialized (`sub_0090c8d0` obj=`0x22322f0`). |
| **Shared-Memory WASM Multithreading** | **IMPLEMENTED & VERIFIED** | 4 Web Workers running with imported shared memory; C shadow stack isolated in `0x2b000000..0x2c000000`. |
| **Shared Control Mailbox (`0x00107000`)** | **IMPLEMENTED & VERIFIED** | Atomics-based command wait/notify; decoupled from Node.js event-loop message starvation. |
| **Authentic Worker Handshake** | **IMPLEMENTED & VERIFIED** | Worker Slot 1 executes authentic `sub_008976e4`, writes acknowledgment `[arglist]=1`, and enters `sub_008991ac` queue wait. |
| **Engine Main Loop (`sub_006dba80`)** | **PARTIALLY WORKING** | Entered engine loop; handshake exited naturally; **332,860 dispatches executed** before trapping. |
| **Vector Exception / Destructor Stack ABI** | **ACTIVE BLOCKER** | `sub_008285e8` (`__ehvec_dtor`) traps with `ESP = 0xff9bc0d0` due to frame-pointer divergence in `__EH_prolog`/`__EH_epilog`. |
| **Direct3D 9 COM Shims & Ring Buffer** | **TESTED IN ISOLATION** | D3D9 vtables, 64-byte command ring buffer (`0x27810000`), 34 D3DX effects parsed, 597 shaders cataloged. |
| **WebGL2 / WebGPU Host Consumer** | **TESTED IN ISOLATION** | Command processor (`web/src/d3d9_consumer.ts`) with draw calls and state mapping; 19 TypeScript unit tests passing. |
| **DirectInput8 & AudioWorklet** | **TESTED IN ISOLATION** | DirectInput COM vtables, mobile touch overlay, AudioWorklet PCM circular stream verified in isolated harnesses. |
| **OPFS Chunk Asset Streaming** | **TESTED IN ISOLATION** | OPFS streaming worker for 5.6 GB game assets with 1 MiB chunk caching. |
| **First Authentic Rendered Frame** | **NOT YET IMPLEMENTED** | Blocked by Phase 3 engine startup trap (`sub_008285e8`) before reaching `sub_006dae50` / D3D9 present. |
| **Authentic Racing Gameplay** | **NOT YET IMPLEMENTED** | Engine boot must complete before in-game Havok physics, AI, and race tracks activate. |

---

## Technical Architecture Deep Dive

### 1. Memory Space Layout (704 MB Shared Linear Memory)

```
0x00000000 - 0x00100000 : Null-page guard (1 MB)
0x00100000 - 0x00102000 : Main Thread TEB & SEH chain
0x00102000 - 0x00104000 : Main Thread .tls private template copy
0x00104000 - 0x00105000 : Main CPU register structure
0x00105000 - 0x00107000 : Worker CPU register structures (8 x 1 KiB)
0x00107000 - 0x00108000 : Shared Worker Control Mailbox (8 slots x 32 bytes)
0x00108000 - 0x00110000 : Worker TEB blocks (8 x 4 KiB)
0x00110000 - 0x00118000 : Worker .tls copies (8 x 4 KiB)
0x00140000 - 0x00200000 : Worker x86 guest stacks (8 x 96 KiB)
0x00200000 - 0x00400000 : Main x86 guest stack (2 MB, ESP starts at 0x003FF000)
0x00400000 - 0x010ea000 : Authentic PE sections (.text, .rdata, .data, .tls, .rsrc, ars, est, artem, celare)
0x019b1000 - 0x01f687e2 : Authentic .securom code segment
0x02000000 - 0x27800000 : Dynamic Guest Heap (up to 600 MB)
0x27800000 - 0x28000000 : Dedicated D3D9 Command Ring Buffer (8 MB)
0x28000000 - 0x2a000000 : WASM C Heap & Dispatch Table (g_dtab at 0x28014c70)
0x2b000000 - 0x2c000000 : Isolated Worker WASM C Shadow Stacks (0x2c000000 - slot * 2 MB)
```

### 2. Multi-Worker Shared WASM Concurrency

The PC release of *Need for Speed: ProStreet* relies heavily on background threads created via `_beginthreadex` for asynchronous asset decompression and persistent streaming queue processing.

To faithfully support this in WebAssembly:
- Secondary Web Workers instantiate `game.wasm` sharing `env.memory`.
- **C Shadow Stack Isolation:** Clang/LLVM WebAssembly binaries maintain a mutable shadow stack pointer `__stack_pointer`. When instantiating secondary modules, PortSpeed isolates each worker's `__stack_pointer` to `0x2c000000 - slot * 0x00200000`, preventing corruption of the main thread's spilled frame registers.
- **Shared Control Mailbox:** Because Node.js and browser `postMessage` event queues are starved when the main thread executes synchronous WASM, workers communicate via atomic futexes in linear memory. Workers immediately enter `guest_worker_slot_run` upon startup and wait on `memory.atomic.wait32`. `ResumeThread` executes `memory.atomic.notify`, achieving instantaneous thread activation.
- **Authentic Handshake:** Worker Slot 1 executes authentic `sub_008976e4`, which moves `1` into `[arglist]` (`[ebp-12]` on caller stack) and calls `sub_008991ac`. The main thread observes the write and exits its handshake loop naturally.

---

## Development & Verification Commands

All commands are run from the project root:

```powershell
# 1. Run complete unit and regression test suite (55 tests, 100% green)
python -m unittest tests.test_securom_lifting tests.test_trampoline_resolution tests.test_calling_convention_abi tests.test_cpu_heap_and_idiv tests.test_win32_shims tests.test_crt_shims tests.test_thread_recovery -v

# 2. Run multi-worker scheduler integration test (verifies dual worker concurrency and authentic handshake)
node --experimental-wasi-unstable-preview1 tests/test_multi_worker_scheduler.mjs

# 3. Run authentic guest thread lifecycle verification
node --experimental-wasi-unstable-preview1 tests/test_guest_thread_lifecycle.mjs

# 4. Execute single supervised authentic full-game startup diagnostic (35-second hard timeout supervisor)
python tools/run_diagnostic_timeout.py --timeout 35.0

# 5. Compile production game.wasm binary (incremental content-hashed build)
python tools/build_wasm.py --game -j 4
```

---

## Active Blockers & Next Milestones

1. **Gate 3 Blocker — `sub_008285e8` (`__ehvec_dtor`) Stack Frame Divergence:**
   - Resolve the frame pointer and stack adjustment logic in MSVC structured exception handling helpers `sub_00828ebc` (`__EH_prolog`) and `sub_00828f01` (`__EH_epilog`), eliminating the `ESP = 0xff9bc0d0` out-of-bounds trap at 332,860 dispatches.
2. **Gate 3 Blocker — Missing Destructor Callback `0x004b0100`:**
   - Lift missing callback `0x004b0100` invoked from Worker Slot 0 (`0x009056eb`).
3. **Gate 4 — First Authentic Engine Frame (`sub_006dae50`):**
   - Advance through startup phase `sub_006daa70` into `sub_006d2df0` and the authentic frame tick `sub_006dae50`.
   - Verify serialization of the first `D3D9_CMD_PRESENT` packet into the shared memory ring buffer (`0x27810000`).
4. **Gate 5 — Browser Host Consumer & First Visible Output:**
   - Connect the Web Worker host to the browser WebGL2 canvas and render the first authentic engine frame.
