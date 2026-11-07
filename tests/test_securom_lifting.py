"""Semantic regression tests for SecuROM function recovery and x86-to-C99 lifting."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from tools.lift_catalog import FunctionLifter, InstructionLifter


WORKSPACE = Path(__file__).resolve().parent.parent


def _build_synthetic_pe(text_va: int, text_bytes: bytes) -> bytes:
    """Construct a minimal PE buffer with a .text section at text_va (file offset 0x1000)."""
    buf = bytearray(0x1000 + max(len(text_bytes), 0x2000))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x014C, 1, 0, 0, 0, 0xE0, 0x010F)
    struct.pack_into("<H", buf, 0x98, 0x010B)
    struct.pack_into("<I", buf, 0xB4, 0x00400000)
    sec_off = 0x80 + 24 + 0xE0
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    vsize = len(buf) - 0x1000
    struct.pack_into(
        "<IIIIIIHHI",
        buf,
        sec_off + 8,
        vsize,
        text_va - 0x00400000,
        vsize,
        0x1000,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    buf[0x1000 : 0x1000 + len(text_bytes)] = text_bytes
    return bytes(buf)


class TestSecuROMLiftingSemantics(unittest.TestCase):
    def setUp(self) -> None:
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

    def test_entry_goto_emitted_when_first_block_precedes_entry(self) -> None:
        """Functions with a basic block at a lower VA than func_entry must jump to L_<entry>."""
        # Block at 0x00401000: mov eax, 99; ret  (e.g. cold backward target)
        # Entry at 0x00401010: mov eax, 7; jmp 0x00401000
        code = bytearray(0x40)
        code[0x00:0x06] = b"\xb8\x63\x00\x00\x00\xc3"
        code[0x10:0x17] = b"\xb8\x07\x00\x00\x00\xeb\xe9"
        pe = _build_synthetic_pe(0x00401000, bytes(code))
        catalog = {
            "image_base": 0x00400000,
            "code_start": 0x00401000,
            "code_end": 0x00403000,
            "functions": [
                {
                    "address": 0x00401010,
                    "blocks": [
                        [0x00401000, 0x00401006, [], 1],
                        [0x00401010, 0x00401017, [0x00401000], 0],
                    ],
                }
            ],
        }
        fl = FunctionLifter(pe, catalog, enable_lregs=True, trampoline_data={"trampolines": []})
        c_src = fl.lift_function(0x00401010)
        self.assertIn("goto L_00401010;", c_src.splitlines()[2] + c_src.splitlines()[3])

    def test_securom_p2_push_push_ret_call_preserves_stack_and_skips_junk(self) -> None:
        """SecuROM P2 (push imm_ret; push imm_callee; ret + junk) must push imm_ret once and continue at imm_ret."""
        # 0x00401000: push 0x00401014 (68 14 10 40 00)
        # 0x00401005: push 0x00401030 (68 30 10 40 00)
        # 0x0040100a: ret             (c3)
        # 0x0040100b..0x00401013: anti-disassembly junk
        # 0x00401014: add eax, 1; ret (83 c0 01 c3)
        # 0x00401030: mov eax, 41; ret (b8 29 00 00 00 c3)
        code = bytearray(0x50)
        code[0x00:0x0B] = b"\x68\x14\x10\x40\x00\x68\x30\x10\x40\x00\xc3"
        code[0x0B:0x14] = b"\xff\xff\xfe\x77\x11\x22\x33\x44\x55"
        code[0x14:0x18] = b"\x83\xc0\x01\xc3"
        code[0x30:0x36] = b"\xb8\x29\x00\x00\x00\xc3"
        pe = _build_synthetic_pe(0x00401000, bytes(code))
        catalog = {
            "image_base": 0x00400000,
            "code_start": 0x00401000,
            "code_end": 0x00403000,
            "functions": [
                {
                    "address": 0x00401000,
                    "blocks": [
                        [0x00401000, 0x0040100B, [0x00401014], 0],
                        [0x00401014, 0x00401018, [], 1],
                    ],
                },
                {
                    "address": 0x00401030,
                    "blocks": [[0x00401030, 0x00401036, [], 1]],
                },
            ],
        }
        fl = FunctionLifter(pe, catalog, enable_lregs=True, trampoline_data={"trampolines": []})
        c_src = fl.lift_function(0x00401000)
        self.assertIn("PUSH32(0x401014u);", c_src)
        self.assertNotIn("PUSH32(0x401030u);", c_src)
        self.assertIn("sub_00401030(c);", c_src)
        self.assertIn("goto L_00401014;", c_src)
        self.assertNotIn("Unsupported:", c_src)

    def test_repne_scasb_and_shared_atomic_instructions_lift_cleanly(self) -> None:
        """repne scasb (MSVC strlen) and lock xadd / cmpxchg must lift without UnsupportedInstruction."""
        il = InstructionLifter(self.cs, use_rg=True)
        # f2 ae = repne scasb
        ins_scas = next(self.cs.disasm(b"\xf2\xae", 0x00401000))
        stmts_scas = "\n".join(il.lift_instruction(ins_scas))
        self.assertIn("while (RG_(ecx) > 0u)", stmts_scas)
        self.assertIn("if (_r == 0u) break;", stmts_scas)

        # f0 0f c1 08 = lock xadd dword ptr [eax], ecx
        ins_xadd = next(self.cs.disasm(b"\xf0\x0f\xc1\x08", 0x00401010))
        stmts_xadd = "\n".join(il.lift_instruction(ins_xadd))
        self.assertIn("PS_ATOMIC_FETCH_ADD32", stmts_xadd)

        # f0 0f b1 11 = lock cmpxchg dword ptr [ecx], edx
        ins_cas = next(self.cs.disasm(b"\xf0\x0f\xb1\x11", 0x00401020))
        stmts_cas = "\n".join(il.lift_instruction(ins_cas))
        self.assertIn("PS_ATOMIC_CAS32", stmts_cas)

    def test_authentic_securom_function_sub_01a01120_lifts_zero_unsupported(self) -> None:
        """Authentic .securom function sub_01a01120 must lift with 0 unsupported instructions."""
        cfg_path = WORKSPACE / "config" / "local.json"
        cat_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.json"
        if not cfg_path.is_file() or not cat_path.is_file():
            self.skipTest("Local nfs.exe / catalog.json not available")
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        exe_path = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
        if not exe_path.is_file():
            self.skipTest("nfs.exe not available")
        raw_exe = exe_path.read_bytes()
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))
        fl = FunctionLifter(raw_exe, catalog, enable_lregs=True)
        self.assertIn(0x01A01120, fl.functions)
        c_src = fl.lift_function(0x01A01120)
        self.assertNotIn("Unsupported:", c_src)
        self.assertIn("return;", c_src)


if __name__ == "__main__":
    unittest.main()
