"""Regression test for popfd instruction lifting and GPR preservation."""
import unittest
import struct
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent

class TestPopfdLifter(unittest.TestCase):
    """Validates that popfd reloads condition flags only, preserving GPRs."""

    def test_lifter_emits_lr_reload_flags_for_popfd(self):
        """Verify lift_catalog.py emits LR_RELOAD_FLAGS for popfd/popf under use_rg."""
        from tools.lift_catalog import InstructionLifter
        lifter = InstructionLifter(cs=None, use_rg=True)
        
        # Test mock instruction for popfd
        class MockInsn:
            mnemonic = "popfd"
            operands = []
            bytes = b"\x9d"
            size = 1
            address = 0x0045bff9
            
        stmts = lifter.lift_instruction(MockInsn())
        self.assertIn("LR_RELOAD_FLAGS;", stmts)
        self.assertNotIn("LR_RELOAD;", stmts)

    def test_cpu_header_defines_lr_reload_flags(self):
        """Verify runtime/cpu.h defines LR_RELOAD_FLAGS."""
        header_path = WORKSPACE / "runtime" / "cpu.h"
        self.assertTrue(header_path.exists())
        content = header_path.read_text(encoding="utf-8")
        self.assertIn("#define LR_RELOAD_FLAGS", content)
        self.assertIn("_r_cf = c->cf;", content)
        self.assertNotIn("_r_eax = c->eax;", content.split("#define LR_RELOAD_FLAGS")[1].split("#")[0])

    def test_unicorn_pushfd_popfd_preserves_gpr(self):
        """Verify authentic execution of pushfd/ror/popfd preserves ESI in Unicorn."""
        import unicorn
        from unicorn import UC_ARCH_X86, UC_MODE_32
        from unicorn.x86_const import (
            UC_X86_REG_ESI, UC_X86_REG_ECX,
            UC_X86_REG_ESP, UC_X86_REG_EFLAGS
        )
        
        uc = unicorn.Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x400000, 0x10000)
        uc.mem_map(0x300000, 0x10000)
        
        # Code:
        # pushfd
        # mov esi, 0x4c247001
        # push ecx
        # mov ecx, 9
        # ror esi, cl  ; 0x00a61238
        # pop ecx
        # popfd
        # hlt
        code = bytes([
            0x9c,                               # pushfd
            0xbe, 0x01, 0x70, 0x24, 0x4c,       # mov esi, 0x4c247001
            0x51,                               # push ecx
            0xb9, 0x09, 0x00, 0x00, 0x00,       # mov ecx, 9
            0xd3, 0xce,                         # ror esi, cl
            0x59,                               # pop ecx
            0x9d,                               # popfd
            0xf4                                # hlt
        ])
        
        CODE_VA = 0x401000
        STACK_VA = 0x308000
        uc.mem_write(CODE_VA, code)
        uc.reg_write(UC_X86_REG_ESP, STACK_VA)
        uc.reg_write(UC_X86_REG_ESI, 0x12345678) # initial ESI
        uc.reg_write(UC_X86_REG_ECX, 0x87654321) # initial ECX
        uc.reg_write(UC_X86_REG_EFLAGS, 0x246)
        
        uc.emu_start(CODE_VA, CODE_VA + len(code) - 1)
        
        final_esi = uc.reg_read(UC_X86_REG_ESI)
        final_ecx = uc.reg_read(UC_X86_REG_ECX)
        final_esp = uc.reg_read(UC_X86_REG_ESP)
        final_flags = uc.reg_read(UC_X86_REG_EFLAGS)
        
        self.assertEqual(final_esi, 0x00a61238, "ESI should retain 0x4c247001 ror 9 = 0x00a61238")
        self.assertEqual(final_ecx, 0x87654321, "ECX should be restored from stack")
        self.assertEqual(final_esp, STACK_VA, "ESP should be perfectly balanced")
        self.assertEqual(final_flags & 0xcd5, 0x246 & 0xcd5, "EFLAGS should be restored by popfd")

if __name__ == "__main__":
    unittest.main()
