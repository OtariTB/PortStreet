"""PortSpeed - Robust Diagnostic Process Supervisor with Hard Timeout.

Spawns the genuine WASM boot diagnostic (or an arbitrary command) in a separately
supervised operating system child process. Enforces a strict wall-clock deadline
using OS-level tree termination (taskkill on Windows). Immune to in-process hangs,
locks, or infinite loops in WebAssembly or Node.js.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEST_SCRIPT = ROOT / "tests" / "test_game_wasm.mjs"
DEFAULT_TIMEOUT = 35.0
DEFAULT_GRACE = 3.0


def run_supervised(
    cmd: list[str],
    timeout_secs: float = DEFAULT_TIMEOUT,
    grace_secs: float = DEFAULT_GRACE,
    cwd: Path | None = None,
) -> tuple[int, list[str], bool, float]:
    """Execute cmd in a supervised child process, enforcing hard wall-clock timeout.

    Returns:
        (returncode, captured_lines, timed_out, elapsed_secs)
    """
    if cwd is None:
        cwd = ROOT

    print(f"=== PortSpeed Diagnostic Process Supervisor ===")
    print(f"Target Command   : {' '.join(cmd)}")
    print(f"Working Directory: {cwd}")
    print(f"Wall-Clock Limit : {timeout_secs:.1f}s (Grace Period: {grace_secs:.1f}s)")
    print("-" * 65)
    sys.stdout.flush()

    env = dict(os.environ)

    # Launch in child process with standard streams piped
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    captured_lines: list[str] = []
    lock = threading.Lock()

    def reader() -> None:
        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                with lock:
                    captured_lines.append(line)
                sys.stdout.write(line)
                sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[SUPERVISOR READER WARNING] {e}\n")
            sys.stderr.flush()
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    start_time = time.monotonic()
    timed_out = False

    # Supervisor polling loop - independent of child process execution or output
    while True:
        ret = proc.poll()
        if ret is not None:
            break

        elapsed = time.monotonic() - start_time
        if elapsed >= timeout_secs:
            timed_out = True
            break

        time.sleep(0.05)

    elapsed_total = time.monotonic() - start_time

    if timed_out:
        print(f"\n" + "!" * 65)
        print(f"[SUPERVISOR TIMEOUT] Hard wall-clock limit ({timeout_secs:.1f}s) EXPIRED!")
        print(f"[SUPERVISOR TERMINATE] Forcefully killing child process tree (PID {proc.pid})...")
        print("!" * 65)
        sys.stdout.flush()

        # On Windows, taskkill /F /T terminates the target and all child processes/threads
        if sys.platform == "win32":
            try:
                kill_res = subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                    text=True,
                )
                if kill_res.returncode == 0:
                    print(f"[SUPERVISOR] taskkill output: {kill_res.stdout.strip()}")
                else:
                    print(f"[SUPERVISOR] taskkill note: {kill_res.stderr.strip()}")
            except Exception as e:
                print(f"[SUPERVISOR ERROR] taskkill invocation failed: {e}")
        else:
            try:
                proc.terminate()
            except Exception:
                pass

        # Wait up to grace_secs for exit
        try:
            proc.wait(timeout=grace_secs)
        except subprocess.TimeoutExpired:
            print(f"[SUPERVISOR WARNING] Process {proc.pid} did not exit after taskkill grace period. Sending SIGKILL...")
            try:
                proc.kill()
                proc.wait(timeout=2.0)
            except Exception as e:
                print(f"[SUPERVISOR ERROR] kill failed: {e}")

        # Ensure pipes are closed
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass

        reader_thread.join(timeout=1.0)
        returncode = 124  # Standard POSIX timeout exit code
        print(f"[SUPERVISOR STATUS] Child process tree {proc.pid} terminated. Exit code: {returncode} (TIMEOUT)")
    else:
        # Child exited naturally within timeout
        reader_thread.join(timeout=2.0)
        returncode = proc.returncode if proc.returncode is not None else 0
        print(f"\n[SUPERVISOR STATUS] Child process {proc.pid} exited naturally with code {returncode} in {elapsed_total:.2f}s.")

    sys.stdout.flush()
    return (returncode, captured_lines, timed_out, elapsed_total)


def analyze_diagnostic_output(lines: list[str], timed_out: bool, returncode: int, elapsed_secs: float) -> None:
    """Parse and summarize observable execution checkpoints from captured output."""
    print("\n" + "=" * 65)
    print("=== PortSpeed Diagnostic Execution Checkpoint Report ===")
    print("=" * 65)

    # 1. Static Initializers
    last_ctor_start = None
    last_ctor_done = None
    total_ctors = 0
    c169_pass = False

    # 2. Main & Boot checkpoints
    main_entered = False
    engine_root_ctor = False
    main_loop_entered = False
    calling_sub_006d2df0 = False
    sub_006d2df0_returned = False
    frame_tick_called = False
    frame_tick_returned = False

    # 3. Thread lifecycle checkpoints
    thread_created = []
    thread_suspended = []
    thread_resumed = []
    thread_entry_entered = []
    thread_ack_written = []
    thread_queue_wait = []
    thread_exited = []

    # 4. Ring buffer & unresolved targets
    d3d9_packets = 0
    unresolved_calls = []

    for line in lines:
        l = line.strip()
        if "-> [START] Constructor #" in l:
            try:
                part = l.split("-> [START] Constructor #")[1]
                num = int(part.split()[0])
                va = part.split("(")[1].split(")")[0]
                last_ctor_start = (num, va)
            except Exception:
                pass
        elif "<- [DONE]  Constructor #" in l:
            try:
                part = l.split("<- [DONE]  Constructor #")[1]
                num = int(part.split()[0])
                va = part.split("(")[1].split(")")[0]
                last_ctor_done = (num, va)
            except Exception:
                pass
        elif "[PASS] Constructor #169 completed!" in l:
            c169_pass = True
        elif "Constructors executed:" in l:
            try:
                total_ctors = int(l.split("Constructors executed:")[1].split("/")[0].strip())
            except Exception:
                pass

        # Main progress
        if "[MAIN] Entered sub_004afee0" in l:
            main_entered = True
        if "[MAIN] sub_0090c8d0 finished" in l:
            engine_root_ctor = True
        if "[sub_006dba80] ENTERED main engine loop" in l:
            main_loop_entered = True
        if "[sub_006dba80] Calling sub_006d2df0..." in l:
            calling_sub_006d2df0 = True
        if "[sub_006dba80] sub_006d2df0 returned" in l:
            sub_006d2df0_returned = True
        if "[FRAME] -> Calling sub_006dae50" in l:
            frame_tick_called = True
        if "[FRAME 1] sub_006dae50" in l and "returned" in l:
            frame_tick_returned = True

        # Thread checkpoints
        if "[THREAD] CREATED:" in l:
            thread_created.append(l)
        elif "[THREAD] SUSPENDED:" in l:
            thread_suspended.append(l)
        elif "[THREAD] RESUMED:" in l:
            thread_resumed.append(l)
        elif "[THREAD] ENTRY_ENTERED:" in l:
            thread_entry_entered.append(l)
        elif "[THREAD] ACK_WRITTEN:" in l:
            thread_ack_written.append(l)
        elif "[THREAD] QUEUE_WAIT:" in l:
            thread_queue_wait.append(l)
        elif "[THREAD] EXITED:" in l:
            thread_exited.append(l)

        # Unresolved dispatch
        if "[DISPATCH] Unresolved indirect target:" in l:
            unresolved_calls.append(l)

    print(f"Overall Status   : {'TIMEOUT (DEADLINE EXCEEDED)' if timed_out else ('SUCCESS' if returncode == 0 else f'FAILED (code {returncode})')}")
    print(f"Elapsed Time     : {elapsed_secs:.2f}s")
    print(f"Static C++ Ctors : {total_ctors} / 960 executed (Ctor #169: {'PASS' if c169_pass else 'NOT REACHED'})")
    if last_ctor_start:
        print(f"Last Ctor Started: #{last_ctor_start[0]} ({last_ctor_start[1]}) | Done: #{last_ctor_done[0] if last_ctor_done else 0}")

    print("\n--- Engine Boot Chain Checkpoints ---")
    print(f"  [1] sub_004afee0 (Authentic main)       : {'ENTERED' if main_entered else 'NOT REACHED'}")
    print(f"  [2] Subsystems (sub_0090c8d0..sub_009047e0): {'INITIALIZED' if engine_root_ctor else 'NOT REACHED'}")
    print(f"  [3] sub_006dba80 (Engine Main Loop)     : {'ENTERED' if main_loop_entered else 'NOT REACHED'}")
    print(f"  [4] sub_006daa70 (Engine Startup Phase) : {'CALLING sub_006d2df0' if calling_sub_006d2df0 else ('ACTIVE / STALLED' if main_loop_entered else 'NOT REACHED')}")
    print(f"  [5] sub_006d2df0 (Jump Table Site)      : {'RETURNED' if sub_006d2df0_returned else ('CALLED' if calling_sub_006d2df0 else 'NOT REACHED')}")
    print(f"  [6] sub_006dae50 (Authentic Frame Tick) : {'RETURNED (FRAME 1 COMPLETE)' if frame_tick_returned else ('ENTERED' if frame_tick_called else 'NOT REACHED')}")

    print("\n--- Authentic Guest Thread Lifecycle Visibility ---")
    print(f"  CREATED       : {len(thread_created)} events {thread_created[-1] if thread_created else ''}")
    print(f"  SUSPENDED     : {len(thread_suspended)} events {thread_suspended[-1] if thread_suspended else ''}")
    print(f"  RESUMED       : {len(thread_resumed)} events {thread_resumed[-1] if thread_resumed else ''}")
    print(f"  ENTRY_ENTERED : {len(thread_entry_entered)} events {thread_entry_entered[-1] if thread_entry_entered else ''}")
    print(f"  ACK_WRITTEN   : {len(thread_ack_written)} events {thread_ack_written[-1] if thread_ack_written else ''}")
    print(f"  QUEUE_WAIT    : {len(thread_queue_wait)} events {thread_queue_wait[-1] if thread_queue_wait else ''}")
    print(f"  EXITED        : {len(thread_exited)} events {thread_exited[-1] if thread_exited else ''}")

    print("=" * 65)
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="PortSpeed Supervised Diagnostic Runner")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--grace", type=float, default=DEFAULT_GRACE, help=f"Grace period after kill (default: {DEFAULT_GRACE})")
    parser.add_argument("--cmd", nargs=argparse.REMAINDER, help="Custom command to run instead of default test harness")
    args = parser.parse_args()

    if args.cmd:
        cmd = args.cmd
    else:
        cmd = ["node", "--experimental-wasi-unstable-preview1", str(DEFAULT_TEST_SCRIPT)]

    returncode, captured_lines, timed_out, elapsed_secs = run_supervised(
        cmd=cmd,
        timeout_secs=args.timeout,
        grace_secs=args.grace,
        cwd=ROOT,
    )

    analyze_diagnostic_output(captured_lines, timed_out, returncode, elapsed_secs)

    if timed_out:
        return 124
    return returncode


if __name__ == "__main__":
    sys.exit(main())
