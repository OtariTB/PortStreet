"""Unit and Integration Tests for SecuROM Trampoline and Prologue Analyzer.

Tests PE section parsing, stub classification, static jump resolution,
and integration against nfs.exe for all 2,153 trampoline sites.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from tools.trampoline_analyzer import (
    EXPECTED_NFS_EXE_SHA256,
    WORKSPACE,
    classify_stub_initial,
    find_trampoline_sites,
    get_section_for_va,
    is_function_entry_boundary,
    parse_pe_sections,
    resolve_plain_stub,
    va_to_offset,
)


class TestTrampolineAnalyzerUnit(unittest.TestCase):
    """Synthetic unit tests for stub classification and static resolution."""

    def setUp(self) -> None:
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

    def test_va_to_offset(self) -> None:
        self.assertEqual(va_to_offset(0x00401000), 0x00001000)
        self.assertEqual(va_to_offset(0x00400000), 0)
        self.assertEqual(va_to_offset(0x019B1000), 0x015B1000)

    def test_classify_vitality_call(self) -> None:
        # push 0x01a6448a (68 8a 44 a6 01)
        # call 0x01166690 (e8 06 22 70 ff from 0x01a64485)
        raw = b"\x68\x8a\x44\xa6\x01\xe8\x06\x22\x70\xff\x90\x90"
        cat = classify_stub_initial(raw, 0x01A64480, self.cs)
        self.assertEqual(cat, "vitality_call")

    def test_classify_vitality_obf_push(self) -> None:
        # push imm; push imm; push imm; pushfd; sub dword ptr [esp+4], 0xf040; popfd; ret
        raw = (
            b"\x68\xaa\x91\xa6\x01"  # push 0x1a691aa
            b"\x68\xe0\x4b\x40\x00"  # push 0x404be0
            b"\x68\xd0\x56\x17\x01"  # push 0x11756d0
            b"\x9c"                  # pushfd
            b"\x81\x6c\x24\x04\x40\xf0\x00\x00"  # sub dword ptr [esp+4], 0xf040
            b"\x9d"                  # popfd
            b"\xc3"                  # ret
        )
        cat = classify_stub_initial(raw, 0x01A69190, self.cs)
        self.assertEqual(cat, "vitality_obf_push")

    def test_classify_plain_x86(self) -> None:
        # push ebp; mov ebp, esp; sub esp, 0x20
        raw = b"\x55\x89\xe5\x83\xec\x20\x90\x90"
        cat = classify_stub_initial(raw, 0x01C01000, self.cs)
        self.assertEqual(cat, "plain_x86")

    def test_resolve_plain_jump(self) -> None:
        # Create dummy buffer with a jmp at stub_va = 0x01C00000 (offset = 0x01800000)
        stub_va = 0x01C00000
        off = va_to_offset(stub_va)
        buf = bytearray(off + 64)
        # jmp 0x00450000 -> relative displacement from 0x01C00005
        # e9 <disp32>
        disp = 0x00450000 - (stub_va + 5)
        buf[off : off + 5] = b"\xe9" + struct.pack("<i", disp)
        sub_type, dest, asm = resolve_plain_stub(bytes(buf), stub_va, self.cs)
        self.assertEqual(sub_type, "plain_jump")
        self.assertEqual(dest, 0x00450000)
        self.assertEqual(len(asm), 1)

    def test_resolve_plain_push_ret(self) -> None:
        stub_va = 0x01C00000
        off = va_to_offset(stub_va)
        buf = bytearray(off + 64)
        # push 0x0052b950; ret
        buf[off : off + 6] = b"\x68\x50\xb9\x52\x00\xc3"
        sub_type, dest, asm = resolve_plain_stub(bytes(buf), stub_va, self.cs)
        self.assertEqual(sub_type, "plain_push_ret")
        self.assertEqual(dest, 0x0052B950)

    def test_resolve_plain_function(self) -> None:
        stub_va = 0x01C00000
        off = va_to_offset(stub_va)
        buf = bytearray(off + 64)
        # push ecx; xor al, al; pop ecx; ret
        buf[off : off + 5] = b"\x51\x30\xc0\x59\xc3"
        sub_type, dest, asm = resolve_plain_stub(bytes(buf), stub_va, self.cs)
        self.assertEqual(sub_type, "plain_function")
        self.assertEqual(dest, stub_va)

    def test_function_entry_boundary(self) -> None:
        buf = bytearray(0x2000)
        site_va = 0x00401010
        off = va_to_offset(site_va)
        buf[off - 1] = 0xCC  # int3
        self.assertTrue(is_function_entry_boundary(bytes(buf), site_va))
        buf[off - 1] = 0x90  # nop
        self.assertTrue(is_function_entry_boundary(bytes(buf), site_va))
        buf[off - 1] = 0xC3  # ret
        self.assertTrue(is_function_entry_boundary(bytes(buf), site_va))
        buf[off - 1] = 0x55  # push ebp (not an end boundary)
        self.assertFalse(is_function_entry_boundary(bytes(buf), site_va))


class TestTrampolineAnalyzerIntegration(unittest.TestCase):
    """Integration test against nfs.exe verifying full 2,153 trampoline resolution."""

    @classmethod
    def setUpClass(cls) -> None:
        cfg_path = WORKSPACE / "config" / "local.json"
        if not cfg_path.is_file():
            raise unittest.SkipTest("config/local.json not found")
        cfg = json.loads(cfg_path.read_text())
        cls.exe_path = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
        if not cls.exe_path.is_file():
            raise unittest.SkipTest("nfs.exe not found")
        cls.raw_exe = cls.exe_path.read_bytes()
        cls.report_path = WORKSPACE / "research" / "local" / "phase1" / "securom_trampolines.json"

    def test_exe_sha256(self) -> None:
        import hashlib
        self.assertEqual(hashlib.sha256(self.raw_exe).hexdigest(), EXPECTED_NFS_EXE_SHA256)

    def test_pe_sections(self) -> None:
        sections = parse_pe_sections(self.raw_exe)
        names = [s[0] for s in sections]
        self.assertIn(".text", names)
        self.assertIn(".rdata", names)
        self.assertIn(".data", names)
        self.assertIn(".securom", names)

        securom = next(s for s in sections if s[0] == ".securom")
        self.assertEqual(securom[1], 0x019B1000)

    def test_find_all_sites_count(self) -> None:
        sites = find_trampoline_sites(self.raw_exe)
        self.assertEqual(len(sites), 2153)

    def test_saved_json_accuracy(self) -> None:
        if not self.report_path.is_file():
            self.skipTest("securom_trampolines.json report not present")
        data = json.loads(self.report_path.read_text())
        summary = data["summary"]

        self.assertEqual(summary["total_trampolines"], 2153)
        self.assertEqual(summary["types"]["vitality_call"], 934)
        self.assertEqual(summary["types"]["vitality_obf_push"], 919)
        self.assertEqual(summary["types"].get("plain_jump", 0), 0)
        self.assertEqual(summary["types"].get("plain_push_ret", 0), 0)
        self.assertEqual(summary["types"]["plain_function"], 300)

        # 934 + 919 = 1,853 ViTALiTY stubs
        self.assertEqual(
            summary["types"]["vitality_call"] + summary["types"]["vitality_obf_push"],
            1853,
        )
        # All 300 plain_x86 stubs in nfs.exe are full .securom functions
        self.assertEqual(
            summary["types"].get("plain_jump", 0)
            + summary["types"].get("plain_push_ret", 0)
            + summary["types"]["plain_function"],
            300,
        )

        # Target section verification (zero bogus 'ars' targets)
        self.assertEqual(summary["target_sections"][".text"], 1279)
        self.assertEqual(summary["target_sections"][".securom"], 874)
        self.assertNotIn("ars", summary["target_sections"])
        self.assertGreaterEqual(summary.get("securom_bridges_count", 0), 2153)

        # Exactly 2,153 entries in the list
        self.assertEqual(len(data["trampolines"]), 2153)

        # Every entry has valid target and prologue
        for t in data["trampolines"]:
            self.assertGreater(t["target_va"], 0x00400000)
            self.assertIn(t["target_section"], (".text", ".securom"))
            self.assertIsInstance(t["prologue_asm"], list)


if __name__ == "__main__":
    unittest.main()
