"""Targeted Regression Tests for __security_check_cookie (sub_00828460) Stack Conventions.

Validates:
1. sub_00828460 consumes the 4-byte guest return address on the successful repz ret path.
2. tools/manual_overrides.py and gen/shard_0019.c stay synchronized with the fix.
3. ESP is restored correctly after calling sub_00828460.
4. ESI is preserved as 0x00abb060 across sub_00463f70.
5. bChunk initialization in sub_01a11e20 writes to pool+0x10c and pool+0x110, NOT address 0x10c / 0x110.
6. Cookie mismatch branch retains authentic failure path.
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from tools.manual_overrides import MANUAL_RECOVERIES
from tools.build_win32_shims import EXE_PATH
from tools.guest_crt import GuestCRT, SimulatedCPU
from tools.guest_d3d9 import GuestD3D9, D3D9_DIRECT3DCREATE9_IAT_VA
from tools.guest_initterm import GUEST_XC_A, GUEST_XC_Z
from tools.guest_memory import GuestMemory
from tools.guest_win32 import GuestWin32
from tools.trampoline_analyzer import create_unicorn_emulator, va_to_offset
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI,
    UC_X86_REG_EDI, UC_X86_REG_EFLAGS
)


class TestSecurityCookieStack(unittest.TestCase):
    def test_sources_synchronized(self) -> None:
        """Verify manual_overrides.py and gen/shard_0019.c contain the esp cleanup."""
        override_src = MANUAL_RECOVERIES.get(0x00828460, "")
        shard_src = (WORKSPACE / "gen" / "shard_0019.c").read_text(encoding="utf-8")

        self.assertIn("RG_(esp) += 4u;\n    LR_STORE;\n    return;", override_src.replace("\r\n", "\n"))
        self.assertIn("RG_(esp) += 4u;\n    LR_STORE;\n    return;", shard_src.replace("\r\n", "\n"))

    def test_cookie_success_consumes_return_address(self) -> None:
        """Verify that with matching cookie, sub_00828460 consumes 4 bytes from guest stack."""
        raw = Path(EXE_PATH).read_bytes()
        uc, _ = create_unicorn_emulator(raw)
        uc.mem_map(0x00200000, 0x00200000)

        # Set up a cookie at 0x00a8be00
        cookie_val = 0x3af82910
        uc.mem_write(0x00a8be00, struct.pack("<I", cookie_val))

        # Push return address 0x00435f3f
        esp_init = 0x003feff8
        uc.reg_write(UC_X86_REG_ESP, esp_init)
        uc.mem_write(esp_init, struct.pack("<I", 0x00435f3f))
        uc.reg_write(UC_X86_REG_ECX, cookie_val)

        # Execute 0x00828460 until return
        uc.emu_start(0x00828460, 0x00435f3f, timeout=100000)

        esp_after = uc.reg_read(UC_X86_REG_ESP)
        eip_after = uc.reg_read(UC_X86_REG_EIP)

        self.assertEqual(eip_after, 0x00435f3f)
        self.assertEqual(esp_after, esp_init + 4, "sub_00828460 must pop exactly 4 bytes on success")

    def test_cookie_mismatch_branches_to_failure(self) -> None:
        """Verify that with non-matching cookie, sub_00828460 branches to failure path 0x00828da4."""
        raw = Path(EXE_PATH).read_bytes()
        uc, _ = create_unicorn_emulator(raw)
        uc.mem_map(0x00200000, 0x00200000)

        cookie_val = 0x3af82910
        uc.mem_write(0x00a8be00, struct.pack("<I", cookie_val))

        esp_init = 0x003feff8
        uc.reg_write(UC_X86_REG_ESP, esp_init)
        uc.mem_write(esp_init, struct.pack("<I", 0x00435f3f))
        uc.reg_write(UC_X86_REG_ECX, cookie_val ^ 0xdeadbeef) # mismatch!

        # Single step through first 2 instructions to check branch
        uc.emu_start(0x00828460, 0x0082846a, count=2)
        eip_after = uc.reg_read(UC_X86_REG_EIP)
        self.assertEqual(eip_after, 0x0082846a, "Mismatch must branch to 0x0082846a (failure path)")

    def test_sub_00463f70_preserves_esi(self) -> None:
        """Verify that sub_00463f70 preserves ESI as pool pointer across nested calls."""
        raw = Path(EXE_PATH).read_bytes()
        uc, _ = create_unicorn_emulator(raw)
        uc.mem_map(0x00200000, 0x00200000)
        uc.mem_map(0x02000000, 0x02000000)

        mem = GuestMemory()
        mem.load_pe_sections(raw)
        crt = GuestCRT(mem, raw); crt.init_iat()
        win32 = GuestWin32(mem, raw); win32.init_iat()

        iat_handlers = {}
        for slot_va, sym in crt.imports:
            iat_handlers[slot_va] = (sym, crt._get_handler(sym))
            uc.mem_write(slot_va, struct.pack("<I", slot_va))
        for item in win32.imports:
            slot_va, sym = item[1], item[2]
            iat_handlers[slot_va] = (sym, win32._get_handler(sym))
            uc.mem_write(slot_va, struct.pack("<I", slot_va))

        def hook_code(uc_inst, address, size, user_data):
            if address in iat_handlers:
                sym, handler = iat_handlers[address]
                esp = uc_inst.reg_read(UC_X86_REG_ESP)
                ret_addr = struct.unpack("<I", uc_inst.mem_read(esp, 4))[0]
                c = SimulatedCPU(mem)
                c.eax = uc_inst.reg_read(UC_X86_REG_EAX)
                c.ecx = uc_inst.reg_read(UC_X86_REG_ECX)
                c.edx = uc_inst.reg_read(UC_X86_REG_EDX)
                c.ebx = uc_inst.reg_read(UC_X86_REG_EBX)
                c.esp = esp + 4
                c.ebp = uc_inst.reg_read(UC_X86_REG_EBP)
                c.esi = uc_inst.reg_read(UC_X86_REG_ESI)
                c.edi = uc_inst.reg_read(UC_X86_REG_EDI)
                handler(c)
                uc_inst.reg_write(UC_X86_REG_EAX, c.eax)
                uc_inst.reg_write(UC_X86_REG_ECX, c.ecx)
                uc_inst.reg_write(UC_X86_REG_EDX, c.edx)
                uc_inst.reg_write(UC_X86_REG_EBX, c.ebx)
                uc_inst.reg_write(UC_X86_REG_ESP, c.esp)
                uc_inst.reg_write(UC_X86_REG_EBP, c.ebp)
                uc_inst.reg_write(UC_X86_REG_ESI, c.esi)
                uc_inst.reg_write(UC_X86_REG_EDI, c.edi)
                uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

        def hook_trampoline(uc_inst, address, size, user_data):
            if address == 0x0043636c:
                esi = uc_inst.reg_read(UC_X86_REG_ESI)
                pool_ptr = struct.unpack("<I", uc_inst.mem_read(esi * 4 + 0xb4dbf0, 4))[0]
                uc_inst.reg_write(UC_X86_REG_EDI, pool_ptr)
                uc_inst.reg_write(UC_X86_REG_EIP, 0x00436373)
            elif address == 0x00435140:
                uc_inst.reg_write(UC_X86_REG_EIP, 0x01a19100)
            elif address == 0x00431060:
                esp = uc_inst.reg_read(UC_X86_REG_ESP)
                ret_addr = struct.unpack("<I", uc_inst.mem_read(esp, 4))[0]
                uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
                uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_trampoline)

        # Set up pool object at 0xabb060
        bchunk = 0x00abb060
        uc.mem_write(bchunk + 0x100, struct.pack("<I", 0x98d0d0))
        uc.mem_write(bchunk + 0x104, struct.pack("<I", 0x2000))
        uc.mem_write(bchunk + 0x114, struct.pack("<I", 0x219000))
        uc.mem_write(bchunk + 0x32c, struct.pack("<I", 0x19c))

        # Call sub_00463f70 directly:
        # push 0x98d0d0 (arg)
        # push 0x01a11e78 (ret addr)
        esp_init = 0x003feff4
        uc.reg_write(UC_X86_REG_ESP, esp_init)
        uc.mem_write(esp_init, struct.pack("<II", 0x01a11e78, 0x98d0d0))
        uc.reg_write(UC_X86_REG_EAX, bchunk)
        uc.reg_write(UC_X86_REG_EDX, 0x219000)
        uc.reg_write(UC_X86_REG_ESI, bchunk) # ESI must be preserved!

        uc.emu_start(0x00463f70, 0x01a11e78, timeout=2000000)

        esi_after = uc.reg_read(UC_X86_REG_ESI)
        eax_after = uc.reg_read(UC_X86_REG_EAX)
        esp_after = uc.reg_read(UC_X86_REG_ESP)

        self.assertEqual(esi_after, bchunk, "ESI must remain 0x00abb060 through sub_00463f70")
        self.assertGreaterEqual(eax_after, 0x02000000, "Allocation result must be in dynamic heap")
        self.assertEqual(esp_after, esp_init + 8, "sub_00463f70 (ret 4) must pop ret_addr + 4-byte arg")

    def test_bchunk_writes_to_pool_not_null_page(self) -> None:
        """Verify bChunk initialization in sub_01a11e20 writes to pool+0x10c/0x110, not NULL."""
        raw = Path(EXE_PATH).read_bytes()
        uc, _ = create_unicorn_emulator(raw)
        uc.mem_map(0x00200000, 0x00200000)
        uc.mem_map(0x02000000, 0x02000000)

        mem = GuestMemory()
        mem.load_pe_sections(raw)
        crt = GuestCRT(mem, raw); crt.init_iat()
        win32 = GuestWin32(mem, raw); win32.init_iat()

        iat_handlers = {}
        for slot_va, sym in crt.imports:
            iat_handlers[slot_va] = (sym, crt._get_handler(sym))
            uc.mem_write(slot_va, struct.pack("<I", slot_va))
        for item in win32.imports:
            slot_va, sym = item[1], item[2]
            iat_handlers[slot_va] = (sym, win32._get_handler(sym))
            uc.mem_write(slot_va, struct.pack("<I", slot_va))

        def hook_code(uc_inst, address, size, user_data):
            if address in iat_handlers:
                sym, handler = iat_handlers[address]
                esp = uc_inst.reg_read(UC_X86_REG_ESP)
                ret_addr = struct.unpack("<I", uc_inst.mem_read(esp, 4))[0]
                c = SimulatedCPU(mem)
                c.eax = uc_inst.reg_read(UC_X86_REG_EAX)
                c.ecx = uc_inst.reg_read(UC_X86_REG_ECX)
                c.edx = uc_inst.reg_read(UC_X86_REG_EDX)
                c.ebx = uc_inst.reg_read(UC_X86_REG_EBX)
                c.esp = esp + 4
                c.ebp = uc_inst.reg_read(UC_X86_REG_EBP)
                c.esi = uc_inst.reg_read(UC_X86_REG_ESI)
                c.edi = uc_inst.reg_read(UC_X86_REG_EDI)
                handler(c)
                uc_inst.reg_write(UC_X86_REG_EAX, c.eax)
                uc_inst.reg_write(UC_X86_REG_ECX, c.ecx)
                uc_inst.reg_write(UC_X86_REG_EDX, c.edx)
                uc_inst.reg_write(UC_X86_REG_EBX, c.ebx)
                uc_inst.reg_write(UC_X86_REG_ESP, c.esp)
                uc_inst.reg_write(UC_X86_REG_EBP, c.ebp)
                uc_inst.reg_write(UC_X86_REG_ESI, c.esi)
                uc_inst.reg_write(UC_X86_REG_EDI, c.edi)
                uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

        def hook_trampoline(uc_inst, address, size, user_data):
            if address == 0x0043636c:
                esi = uc_inst.reg_read(UC_X86_REG_ESI)
                pool_ptr = struct.unpack("<I", uc_inst.mem_read(esi * 4 + 0xb4dbf0, 4))[0]
                uc_inst.reg_write(UC_X86_REG_EDI, pool_ptr)
                uc_inst.reg_write(UC_X86_REG_EIP, 0x00436373)
            elif address == 0x00435140:
                uc_inst.reg_write(UC_X86_REG_EIP, 0x01a19100)
            elif address == 0x00431060:
                esp = uc_inst.reg_read(UC_X86_REG_ESP)
                ret_addr = struct.unpack("<I", uc_inst.mem_read(esp, 4))[0]
                uc_inst.reg_write(UC_X86_REG_ESP, esp + 4)
                uc_inst.reg_write(UC_X86_REG_EIP, ret_addr)

        uc.hook_add(unicorn.UC_HOOK_CODE, hook_trampoline)

        bchunk = 0x00abb060
        uc.mem_write(bchunk + 0x100, struct.pack("<I", 0x98d0d0))
        uc.mem_write(bchunk + 0x104, struct.pack("<I", 0x2000))
        uc.mem_write(bchunk + 0x114, struct.pack("<I", 0x219000))
        uc.mem_write(bchunk + 0x32c, struct.pack("<I", 0x19c))

        # Call sub_01a11e20:
        esp_init = 0x003feffc
        uc.reg_write(UC_X86_REG_ESP, esp_init)
        uc.mem_write(esp_init, struct.pack("<I", 0x0046413c)) # fake return address
        uc.reg_write(UC_X86_REG_ESI, bchunk)

        uc.emu_start(0x01a11e20, 0x0046413c, timeout=3000000)

        # Check bChunk pool
        init_flag = uc.mem_read(bchunk + 0x10c, 1)[0]
        fastmem_ptr = struct.unpack("<I", uc.mem_read(bchunk + 0x110, 4))[0]

        self.assertEqual(init_flag, 1, "Pool init flag must be 1 at pool+0x10c")
        self.assertGreaterEqual(fastmem_ptr, 0x02000000, "fastmem_ptr must be in dynamic heap range")
        self.assertLess(fastmem_ptr, 0x28000000, "fastmem_ptr must be within dynamic heap ceiling")


if __name__ == "__main__":
    unittest.main()
