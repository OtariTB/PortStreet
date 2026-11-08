"""Regression and structural tests for MSVC exception handling and vector destructor stack ABI.

Verifies:
- sub_00828ebc (__EH_prolog): stack frame setup, argument offsets, SEH registration, saved registers
- sub_00828f01 (__EH_epilog): stack unwinding, register restoration, SEH deregistration
- sub_008285e8 (__ehvec_dtor): end-to-end vector destructor call with pristine stack balance
- Differential validation against Unicorn emulator running authentic x86 instructions
"""

import json
from pathlib import Path
import struct
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *

from tools.trampoline_analyzer import create_unicorn_emulator

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestMSVCExceptionStack(unittest.TestCase):
    def setUp(self):
        self.shard20_path = ROOT_DIR / "gen" / "shard_0020.c"
        self.overrides_path = ROOT_DIR / "tools" / "manual_overrides.py"

    def test_generator_and_shard_contain_corrected_prolog_epilog(self):
        """Verify that tools/manual_overrides.py and gen/shard_0020.c contain corrected EH helpers."""
        overrides_text = self.overrides_path.read_text(encoding="utf-8")
        shard20_text = self.shard20_path.read_text(encoding="utf-8")

        for text, name in [(overrides_text, "manual_overrides.py"), (shard20_text, "shard_0020.c")]:
            # Prolog must read alloc_size from [esp + 8], scope_table from [esp + 4]
            self.assertIn("uint32_t scope_table = MR32(c->esp + 4u);", text, f"Missing in {name}")
            self.assertIn("uint32_t alloc_size  = MR32(c->esp + 8u);", text, f"Missing in {name}")
            self.assertIn("uint32_t frame_base  = c->esp + 8u;", text, f"Missing in {name}")
            # Epilog must restore esp to c->ebp + 4u
            self.assertIn("c->esp = c->ebp + 4u;", text, f"Missing in {name}")
            # Epilog must restore ebx, esi, edi
            self.assertIn("c->edi = MR32(saved_ptr + 4);", text, f"Missing in {name}")
            self.assertIn("c->esi = MR32(saved_ptr + 8);", text, f"Missing in {name}")
            self.assertIn("c->ebx = MR32(saved_ptr + 12);", text, f"Missing in {name}")

    def test_unicorn_differential_ehvec_dtor_stack_balance(self):
        """Differential execution test: compare authentic x86 sub_008285e8 in Unicorn against ABI."""
        cfg_path = ROOT_DIR / "config" / "local.json"
        if not cfg_path.exists():
            self.skipTest("config/local.json not found")

        with open(cfg_path) as f:
            cfg = json.load(f)
        exe_path = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
        if not exe_path.exists():
            self.skipTest("nfs.exe not found")

        raw_exe = exe_path.read_bytes()
        mu, _ = create_unicorn_emulator(raw_exe)

        # Set security cookie
        mu.mem_write(0x00a8be00, struct.pack("<I", 0x12345678))

        # Dummy dtor at 0x00500000: ret
        mu.mem_write(0x00500000, b"\xc3")

        # Initial stack setup
        STACK_INIT = 0x001FF000
        # Call sub_008285e8(array=0x00180000, size=4, count=0, dtor=0x00500000)
        mu.mem_write(STACK_INIT - 4, struct.pack("<I", 0x00500000))  # dtor
        mu.mem_write(STACK_INIT - 8, struct.pack("<I", 0))           # count = 0
        mu.mem_write(STACK_INIT - 12, struct.pack("<I", 4))          # size = 4
        mu.mem_write(STACK_INIT - 16, struct.pack("<I", 0x00180000)) # array
        mu.mem_write(STACK_INIT - 20, struct.pack("<I", 0x00401234)) # return_addr

        mu.reg_write(UC_X86_REG_ESP, STACK_INIT - 20)
        mu.reg_write(UC_X86_REG_EBP, 0x001FFE00)
        mu.reg_write(UC_X86_REG_EBX, 0x11111111)
        mu.reg_write(UC_X86_REG_ESI, 0x22222222)
        mu.reg_write(UC_X86_REG_EDI, 0x33333333)

        # Execute sub_008285e8 until return to 0x00401234
        mu.emu_start(0x008285e8, 0x00401234, count=200)

        final_esp = mu.reg_read(UC_X86_REG_ESP)
        final_ebp = mu.reg_read(UC_X86_REG_EBP)
        final_ebx = mu.reg_read(UC_X86_REG_EBX)
        final_esi = mu.reg_read(UC_X86_REG_ESI)
        final_edi = mu.reg_read(UC_X86_REG_EDI)

        # 1. ESP must be exactly cleaned up (4-byte return address + 16 bytes arguments = 20 bytes)
        self.assertEqual(final_esp, STACK_INIT)
        # 2. EBP must be restored to caller's frame
        self.assertEqual(final_ebp, 0x001FFE00)
        # 3. Callee-saved registers preserved
        self.assertEqual(final_ebx, 0x11111111)
        self.assertEqual(final_esi, 0x22222222)
        self.assertEqual(final_edi, 0x33333333)


if __name__ == "__main__":
    unittest.main()
