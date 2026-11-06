"""Unit and Integration Tests for NFS ProStreet Engine Boot Chain (Step 3.5).

Verifies:
- 1:1 linear guest memory layout and TEB/TLS structure.
- Win32 and CRT IAT binding.
- MSVC C runtime initializers and C++ constructors chain.
- Command-line argument table and stack frame construction for main().
- Safe-mode flag detection and hook execution.
- Early main() synchronization event creation and root object allocation.
- End-to-end dry-run boot execution on authentic nfs.exe.
- Strict consistency between runtime/boot.h, runtime/boot.c, and tools/guest_boot.py.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from tools.build_win32_shims import EXE_PATH
from tools.guest_boot import (
    GuestBoot,
    GUEST_MAIN_VA,
    GUEST_SAFEMODE_VA,
    GUEST_RETURN_ADDR,
    GUEST_SAFEMODE_FLAG_ADDR,
    GUEST_EVENT_ARRAY_ADDR,
    GUEST_QUIT_FLAG_ADDR,
)
from tools.guest_crt import (
    DISPATCH_TEXT_BASE,
    GUEST_ARGV_TAB_ADDR,
    GUEST_ENVP_TAB_ADDR,
    SimulatedCPU,
)
from tools.guest_memory import GuestMemory

WORKSPACE = Path(__file__).resolve().parent.parent


class TestBootUnit(unittest.TestCase):
    """Unit tests for individual stages of the engine boot sequence."""

    def setUp(self):
        self.mem = GuestMemory()
        self.boot = GuestBoot(memory=self.mem)

    def test_boot_initial_state(self):
        """Initial state should be uninitialized with empty logs."""
        self.assertEqual(self.boot.boot_stage, "uninitialized")
        self.assertEqual(self.boot.argc, 0)
        self.assertEqual(len(self.boot.argv), 0)
        self.assertFalse(self.boot.is_safemode)
        self.assertEqual(len(self.boot.subsystems_log), 0)

    def test_teb_and_tls_initialization_at_fs_base(self):
        """Validates that SimulatedCPU properly constructs the Win32 TEB and TLS layout."""
        cpu = self.boot.cpu
        self.assertEqual(cpu.fs_base, 0x00100000)

        # Exception list head sentinel
        self.assertEqual(self.mem.read_u32(cpu.fs_base + 0x00), 0xFFFFFFFF)
        # Stack Base & Limit
        self.assertEqual(self.mem.read_u32(cpu.fs_base + 0x04), 0x003FF000)
        self.assertEqual(self.mem.read_u32(cpu.fs_base + 0x08), 0x00200000)
        # Self-pointer
        self.assertEqual(self.mem.read_u32(cpu.fs_base + 0x18), cpu.fs_base)
        # ThreadLocalStoragePointer (TLS array)
        tls_arr_va = self.mem.read_u32(cpu.fs_base + 0x2C)
        self.assertEqual(tls_arr_va, cpu.fs_base + 0x100)
        # TLS slot 0 points to module 0 TLS block
        tls_slot0 = self.mem.read_u32(tls_arr_va)
        self.assertEqual(tls_slot0, cpu.fs_base + 0x200)

    def test_main_argument_parsing_standard(self):
        """Standard boot with argv = ['nfs.exe']."""
        self.boot.setup_main_arguments(["nfs.exe"])
        self.assertEqual(self.boot.argc, 1)
        self.assertEqual(self.boot.argv, ["nfs.exe"])
        self.assertFalse(self.boot.is_safemode)

        # Verify string written into guest memory
        arg0_ptr = self.mem.read_u32(GUEST_ARGV_TAB_ADDR)
        self.assertEqual(self.mem.read_cstring(arg0_ptr), "nfs.exe")

        # Verify argv[1] is NULL
        self.assertEqual(self.mem.read_u32(GUEST_ARGV_TAB_ADDR + 4), 0)

        # Verify envp[0] is NULL
        self.assertEqual(self.mem.read_u32(GUEST_ENVP_TAB_ADDR), 0)

        # Verify CRT globals written
        self.assertEqual(self.mem.read_u32(0x00B33A64), 1)
        self.assertEqual(self.mem.read_u32(0x00B33A6C), GUEST_ARGV_TAB_ADDR)
        self.assertEqual(self.mem.read_u32(0x00B33A68), GUEST_ENVP_TAB_ADDR)

    def test_main_argument_parsing_with_safemode(self):
        """Argument setup with -safemode flag."""
        self.boot.setup_main_arguments(["nfs.exe", "-safemode", "-nosound"])
        self.assertEqual(self.boot.argc, 3)
        self.assertTrue(self.boot.is_safemode)

        arg1_ptr = self.mem.read_u32(GUEST_ARGV_TAB_ADDR + 4)
        self.assertEqual(self.mem.read_cstring(arg1_ptr), "-safemode")

        arg2_ptr = self.mem.read_u32(GUEST_ARGV_TAB_ADDR + 8)
        self.assertEqual(self.mem.read_cstring(arg2_ptr), "-nosound")

        self.assertEqual(self.mem.read_u32(GUEST_ARGV_TAB_ADDR + 12), 0)

    def test_main_stack_frame_layout(self):
        """Validates that guest stack at entry of main matches genuine MSVC cdecl."""
        self.boot.setup_main_arguments(["nfs.exe"])
        esp = self.boot.cpu.esp

        # [esp + 0] = dummy return address (0x00828ae0)
        self.assertEqual(self.mem.read_u32(esp), GUEST_RETURN_ADDR)
        # [esp + 4] = argc (1)
        self.assertEqual(self.mem.read_u32(esp + 4), 1)
        # [esp + 8] = argv (GUEST_ARGV_TAB_ADDR)
        self.assertEqual(self.mem.read_u32(esp + 8), GUEST_ARGV_TAB_ADDR)
        # [esp + 12] = envp (GUEST_ENVP_TAB_ADDR)
        self.assertEqual(self.mem.read_u32(esp + 12), GUEST_ENVP_TAB_ADDR)

    def test_safemode_hook_resolution(self):
        """Validates hook at 0x004afea0 returns 1 if -safemode, 0 otherwise."""
        self.boot.bind_all_iats()
        self.boot.install_boot_hooks()

        # Without safemode
        self.boot.is_safemode = False
        self.boot.win32.dtab[GUEST_SAFEMODE_VA](self.boot.cpu)
        self.assertEqual(self.boot.cpu.eax, 0)

        # With safemode
        self.boot.is_safemode = True
        self.boot.win32.dtab[GUEST_SAFEMODE_VA](self.boot.cpu)
        self.assertEqual(self.boot.cpu.eax, 1)

    def test_main_dry_run_event_creation_and_exit(self):
        """Verifies dry-run main() creates 4 events, root object, and exits cleanly."""
        self.boot.bind_all_iats()
        self.boot.install_boot_hooks()
        self.boot.setup_main_arguments(["nfs.exe"])

        res = self.boot.invoke_main(dry_run=True)
        self.assertEqual(res, 0)
        self.assertEqual(self.boot.boot_stage, "main_exited")

        # 4 synchronization events created
        self.assertEqual(len(self.boot.event_handles), 4)
        for i in range(4):
            handle = self.mem.read_u32(GUEST_EVENT_ARRAY_ADDR + i * 4)
            self.assertGreater(handle, 0)

        # Root engine object allocated
        root_obj = self.mem.read_u32(0x00BFC024)
        self.assertGreaterEqual(root_obj, 0x02000000)

        # Clean quit flag set
        self.assertEqual(self.mem.read_u32(GUEST_QUIT_FLAG_ADDR), 1)

    def test_teb_tls_chain_resolution_for_main(self):
        """Validates that main()'s FS:[0x2C] dereference chain resolves to valid guest TLS slot."""
        fs_base = self.boot.cpu.fs_base
        self.assertEqual(fs_base, 0x00100000)
        # fs:[0x2c] is ThreadLocalStoragePointer
        tls_arr_ptr = self.mem.read_u32(fs_base + 0x2C)
        self.assertEqual(tls_arr_ptr, 0x00100100)
        # module 0 array pointer
        tls_slot0_ptr = self.mem.read_u32(tls_arr_ptr)
        self.assertEqual(tls_slot0_ptr, 0x00100200)
        # Verify slot + 4 used by authentic main() resides in valid TEB/TLS range (0x00100000..0x00200000)
        main_target_slot = tls_slot0_ptr + 4
        self.assertTrue(0x00100000 <= main_target_slot < 0x00200000)
        # Verify slot can store and return the engine root object pointer
        self.mem.write_u32(main_target_slot, 0x022322F0)
        self.assertEqual(self.mem.read_u32(main_target_slot), 0x022322F0)


class TestBootIntegration(unittest.TestCase):
    """Integration tests running end-to-end boot chain on genuine nfs.exe binary."""

    @unittest.skipUnless(EXE_PATH.exists(), "nfs.exe required for integration tests")
    def test_full_boot_chain_dry_run_genuine_pe(self):
        """Executes full end-to-end boot chain on authentic nfs.exe in dry-run mode."""
        boot = GuestBoot()
        exit_code = boot.boot_end_to_end(args=["nfs.exe"], dry_run=True)

        self.assertEqual(exit_code, 0)
        self.assertEqual(boot.boot_stage, "main_exited")
        self.assertEqual(boot.argc, 1)
        self.assertFalse(boot.is_safemode)
        self.assertEqual(boot.mem.read_u32(GUEST_SAFEMODE_FLAG_ADDR), 0)

        # Verify all subsystems logged
        log_text = "\n".join(boot.subsystems_log)
        self.assertIn("PE sections loaded", log_text)
        self.assertIn("IAT bound: 156 CRT imports, 198 Win32 imports", log_text)
        self.assertIn("Static initializers complete", log_text)
        self.assertIn("960 constructors executed", log_text)
        self.assertIn("Entering main() at 0x004afee0", log_text)
        self.assertIn("Engine synchronization events created", log_text)
        self.assertIn("main() exited cleanly with code 0", log_text)

    @unittest.skipUnless(EXE_PATH.exists(), "nfs.exe required for integration tests")
    def test_full_boot_chain_with_safemode_genuine_pe(self):
        """Executes boot chain with -safemode argument, verifying global flag update."""
        boot = GuestBoot()
        exit_code = boot.boot_end_to_end(args=["nfs.exe", "-safemode"], dry_run=True)

        self.assertEqual(exit_code, 0)
        self.assertTrue(boot.is_safemode)
        self.assertEqual(boot.mem.read_u32(GUEST_SAFEMODE_FLAG_ADDR), 1)
        self.assertIn("Safe mode flag set to 1", boot.subsystems_log)

    def test_generated_boot_c_files_consistency(self):
        """Verifies runtime/boot.h and runtime/boot.c exist and match Python simulator constants."""
        h_path = WORKSPACE / "runtime" / "boot.h"
        c_path = WORKSPACE / "runtime" / "boot.c"

        self.assertTrue(h_path.exists(), "runtime/boot.h must exist")
        self.assertTrue(c_path.exists(), "runtime/boot.c must exist")

        h_content = h_path.read_text(encoding="utf-8")
        c_content = c_path.read_text(encoding="utf-8")

        # Check critical constants
        self.assertIn(f"0x{GUEST_MAIN_VA:08x}u", h_content)
        self.assertIn(f"0x{GUEST_SAFEMODE_VA:08x}u", h_content)
        self.assertIn(f"0x{GUEST_RETURN_ADDR:08x}u", h_content)
        self.assertIn(f"0x{GUEST_SAFEMODE_FLAG_ADDR:08x}u", h_content)
        self.assertIn(f"0x{GUEST_EVENT_ARRAY_ADDR:08x}u", h_content)
        self.assertIn(f"0x{GUEST_QUIT_FLAG_ADDR:08x}u", h_content)

        # Check API functions
        for fn in [
            "boot_init_memory",
            "boot_bind_iats",
            "boot_install_hooks",
            "boot_run_initializers",
            "boot_setup_arguments",
            "boot_invoke_main",
            "boot_engine",
        ]:
            self.assertIn(fn, h_content, f"{fn} must be declared in boot.h")
            self.assertIn(fn, c_content, f"{fn} must be implemented in boot.c")


if __name__ == "__main__":
    unittest.main()

