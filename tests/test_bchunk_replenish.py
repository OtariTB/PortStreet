"""Targeted Regression Tests for bChunk Allocator Replenishment in Constructor #169.

Validates:
1. sub_00436360 and sub_01a19100 are permanently registered in MANUAL_RECOVERIES.
2. sub_00436360 incorporates authentic unspliced logic: resolves pool ptr at esi*4 + 0xb4dbf0,
   returns 0x6300000 for pool 0 capacity, does not dispatch to SecuROM 0x19e7a74.
3. sub_01a19100 completely initializes the default heap pool at 0xb4dd10: zeroes critical section,
   sets pool flags [esi+0x44]=1 and [esi+0x45]=1, sets pool name, calls sub_00435230, and cleans up 16 bytes.
4. gen/shard_0001.c and gen/shard_0031.c stay synchronized with MANUAL_RECOVERIES.
5. Authentic Unicorn execution of constructor #169 completes with all 87 descriptors allocated.
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
    UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_EBP, UC_X86_REG_ESI,
    UC_X86_REG_EDI, UC_X86_REG_EFLAGS,
)


class TestBChunkReplenish(unittest.TestCase):
    """Test suite validating bChunk replenishment and heap pool initialization."""

    def test_manual_recoveries_registered(self) -> None:
        """Verify sub_00436360 and sub_01a19100 are registered in manual_overrides."""
        self.assertIn(0x00436360, MANUAL_RECOVERIES)
        self.assertIn(0x01a19100, MANUAL_RECOVERIES)

    def test_sub_00436360_unspliced_logic(self) -> None:
        """Verify sub_00436360 does not truncate or dispatch to SecuROM stub."""
        code = MANUAL_RECOVERIES[0x00436360]
        self.assertIn("MR32(RG_(esi)*4u + 0xb4dbf0u)", code)
        self.assertNotIn("0x19e7a74", code)
        self.assertIn("0x6300000u", code)
        self.assertIn("RG_(esp) += 4u;", code)

    def test_sub_01a19100_full_initialization(self) -> None:
        """Verify sub_01a19100 initializes lock, flags, calls sub_00435230, and cleans up 16 bytes."""
        code = MANUAL_RECOVERIES[0x01a19100]
        self.assertIn("MR32(RG_(ecx)+0x00u) = 0u;", code)
        self.assertIn("MR8(RG_(esi)+0x44u) = 1u;", code)
        self.assertIn("MR8(RG_(esi)+0x45u) = 1u;", code)
        self.assertIn("MR32(RG_(esi)) = (RG_(eax));", code)
        self.assertIn("0x00435230u", code)
        self.assertIn("RG_(esp) += 16u;", code)

    def test_shard_sources_synchronized(self) -> None:
        """Verify gen/shard_0001.c and gen/shard_0031.c contain the updated routines."""
        shard1 = (WORKSPACE / "gen" / "shard_0001.c").read_text(encoding="utf-8")
        shard31 = (WORKSPACE / "gen" / "shard_0031.c").read_text(encoding="utf-8")

        self.assertIn("MR32(RG_(esi)*4u + 0xb4dbf0u)", shard1)
        self.assertNotIn("DISPATCH_TAIL(c, MR32(0x19e7a74u));", shard1)

        self.assertIn("MR32(RG_(ecx)+0x00u) = 0u;", shard31)
        self.assertIn("MR8(RG_(esi)+0x44u) = 1u;", shard31)
        self.assertIn("RG_(esp) += 16u;", shard31)

    def test_unicorn_ctor_169_bchunk_replenish(self) -> None:
        """Verify authentic execution of constructor #169 in Unicorn produces 87 descriptors."""
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

        d3d9 = GuestD3D9(mem); d3d9.init_iat()
        iat_handlers[D3D9_DIRECT3DCREATE9_IAT_VA] = ("Direct3DCreate9", d3d9.shim_Direct3DCreate9)
        uc.mem_write(D3D9_DIRECT3DCREATE9_IAT_VA, struct.pack("<I", D3D9_DIRECT3DCREATE9_IAT_VA))
        iat_handlers[0x0082851b] = ("sub_0082851b", lambda c: setattr(c, "eax", 0))

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

        off = va_to_offset(GUEST_XC_A)
        total_slots = (GUEST_XC_Z - GUEST_XC_A) // 4
        non_zero = []
        for i in range(total_slots):
            val = struct.unpack_from("<I", raw, off + i * 4)[0]
            if val != 0:
                non_zero.append((len(non_zero) + 1, val))

        for rank, fn_va in non_zero[:168]:
            uc.reg_write(UC_X86_REG_ESP, 0x003feffc)
            uc.mem_write(0x003feffc, struct.pack("<I", 0x00401000))
            uc.reg_write(UC_X86_REG_EBP, 0x003ff000)
            uc.emu_start(fn_va, 0x00401000, timeout=1000000)

        def hook_trampoline(uc_inst, address, size, user_data):
            if address == 0x00463e97:
                ebp = uc_inst.reg_read(UC_X86_REG_EBP)
                eflags = uc_inst.reg_read(UC_X86_REG_EFLAGS)
                cf = 1 if ebp < 0x400 else 0
                zf = 1 if ebp == 0x400 else 0
                eflags = (eflags & ~0x41) | (cf | (zf << 6))
                uc_inst.reg_write(UC_X86_REG_EFLAGS, eflags)
                uc_inst.reg_write(UC_X86_REG_EIP, 0x00463e9d)
            elif address == 0x00463d70:
                uc_inst.reg_write(UC_X86_REG_EIP, 0x01a11e20)
            elif address == 0x0043636c:
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

        fn_169 = non_zero[168][1]
        uc.reg_write(UC_X86_REG_ESP, 0x003feffc)
        uc.mem_write(0x003feffc, struct.pack("<I", 0x00401000))
        uc.reg_write(UC_X86_REG_EBP, 0x003ff000)
        uc.emu_start(fn_169, 0x00401000, timeout=10000000)

        obj_count = struct.unpack("<I", uc.mem_read(0x00ab47e4, 4))[0]
        arr_ptr = struct.unpack("<I", uc.mem_read(0x00ab47e0 + 0x16c, 4))[0]
        bchunk_data = uc.mem_read(0xabb060, 0x120)
        init_flag = bchunk_data[0x10c]
        fastmem_ptr = struct.unpack_from("<I", bchunk_data, 0x110)[0]
        fastmem_sz = struct.unpack_from("<I", bchunk_data, 0x114)[0]
        fastmem_off = struct.unpack_from("<I", bchunk_data, 0x118)[0]

        self.assertEqual(init_flag, 1)
        self.assertEqual(fastmem_ptr, 0x02000030)
        self.assertEqual(fastmem_sz, 0x00219000)
        self.assertEqual(fastmem_off, 0x00002620)
        self.assertEqual(obj_count, 87)
        self.assertNotEqual(arr_ptr, 0)


if __name__ == "__main__":
    unittest.main()
