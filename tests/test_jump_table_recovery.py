"""Regression tests for native indirect jump-table recovery.

Validates that FunctionLifter correctly resolves intra-function jump tables
(e.g., in sub_00436460 and sub_0045cb40) into native C99 switch/goto constructs
rather than erroneous cross-function DISPATCH_TAIL calls.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM
from tools.lift_catalog import FunctionLifter, va_to_offset

WORKSPACE = Path(__file__).resolve().parent.parent

# Game executable
EXE_PATH = Path(r"C:\Users\tabat\OneDrive\Desktop\Need-for-Speed-Pro-Street-SteamRIP.com\Need For Spped - Pro Street\nfs.exe")
if not EXE_PATH.exists():
    EXE_PATH = Path(r"C:\Games\Pro Street\Need For Spped - Pro Street\nfs.exe")


class TestJumpTableRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_exe = EXE_PATH.read_bytes()
        cat_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.json"
        with open(cat_path, "r", encoding="utf-8") as f:
            cls.catalog = json.load(f)
        cls.lifter = FunctionLifter(cls.raw_exe, cls.catalog, enable_lregs=True, enable_flagabi=True)
        cls.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cls.cs.detail = True

    def test_sub_00436460_table_recognition(self) -> None:
        """sub_00436460 jump table at 0x004364d4 must be resolved with 4 entries."""
        fn = self.lifter.functions[0x00436460]
        block_starts = {b[0] for b in fn["blocks"]}

        off = va_to_offset(0x0043647a)
        ins = next(self.cs.disasm(self.raw_exe[off : off + 7], 0x0043647a))
        self.assertEqual(ins.mnemonic, "jmp")
        self.assertEqual(ins.operands[0].type, CS_OP_MEM)

        jt_info = self.lifter.resolve_jump_table(ins, block_starts, 0x00436460)
        self.assertIsNotNone(jt_info)
        table_va, idx_reg, entries = jt_info

        self.assertEqual(table_va, 0x004364d4)
        self.assertEqual(idx_reg, "esi")
        self.assertEqual(len(entries), 4)
        expected_entries = [0x004364a4, 0x00436481, 0x00436491, 0x004364a1]
        self.assertEqual(entries, expected_entries)

        # All targets must belong to function basic blocks
        for t in entries:
            self.assertIn(t, block_starts)

    def test_sub_0045cb40_table_recognition(self) -> None:
        """sub_0045cb40 jump table at 0x0045cd24 must be resolved with 11 entries."""
        fn = self.lifter.functions[0x0045cb40]
        block_starts = {b[0] for b in fn["blocks"]}

        off = va_to_offset(0x0045cc56)
        ins = next(self.cs.disasm(self.raw_exe[off : off + 7], 0x0045cc56))
        self.assertEqual(ins.mnemonic, "jmp")
        self.assertEqual(ins.operands[0].type, CS_OP_MEM)

        jt_info = self.lifter.resolve_jump_table(ins, block_starts, 0x0045cb40)
        self.assertIsNotNone(jt_info)
        table_va, idx_reg, entries = jt_info

        self.assertEqual(table_va, 0x0045cd24)
        self.assertEqual(idx_reg, "ebp")
        self.assertEqual(len(entries), 11)
        expected_entries = [
            0x0045ccb4, 0x0045ccab, 0x0045cca2, 0x0045cc99, 0x0045cc93,
            0x0045cc8a, 0x0045cc81, 0x0045cc78, 0x0045cc6f, 0x0045cc66,
            0x0045cc5d,
        ]
        self.assertEqual(entries, expected_entries)

        # All targets must belong to function basic blocks
        for t in entries:
            self.assertIn(t, block_starts)

    def test_lifted_code_sub_00436460(self) -> None:
        """sub_00436460 lifted code must emit switch/goto, trap on invalid selector, and no DISPATCH_TAIL for the table."""
        code = self.lifter.lift_function(0x00436460)
        self.assertIn("switch (RG_(esi)) {", code)
        self.assertIn("case 0: goto L_004364a4;", code)
        self.assertIn("case 1: goto L_00436481;", code)
        self.assertIn("case 2: goto L_00436491;", code)
        self.assertIn("case 3: goto L_004364a1;", code)
        self.assertIn("[JUMP_TABLE] FATAL: Out-of-bounds selector", code)
        self.assertIn("__builtin_trap();", code)
        self.assertNotIn("DISPATCH_TAIL(c, MR32(RG_(esi)*4+0x4364d4u));", code)

        # Reject silent returns in default branch
        def_idx = code.find("default:")
        self.assertNotEqual(def_idx, -1)
        def_block = code[def_idx : def_idx + 250]
        self.assertNotIn("return;", def_block)

    def test_lifted_code_sub_0045cb40(self) -> None:
        """sub_0045cb40 lifted code must emit switch/goto, trap on invalid selector, and no DISPATCH_TAIL for the table."""
        code = self.lifter.lift_function(0x0045cb40)
        self.assertIn("switch (RG_(ebp)) {", code)
        self.assertIn("case 0: goto L_0045ccb4;", code)
        self.assertIn("case 10: goto L_0045cc5d;", code)
        self.assertIn("[JUMP_TABLE] FATAL: Out-of-bounds selector", code)
        self.assertIn("__builtin_trap();", code)
        self.assertNotIn("DISPATCH_TAIL(c, MR32(RG_(ebp)*4+0x45cd24u));", code)

        # Reject silent returns in default branch
        def_idx = code.find("default:")
        self.assertNotEqual(def_idx, -1)
        def_block = code[def_idx : def_idx + 250]
        self.assertNotIn("return;", def_block)

    def test_shard_0001_contains_recovered_switches(self) -> None:
        """gen/shard_0001.c on disk must contain the switch-based implementations with trap."""
        shard_path = WORKSPACE / "gen" / "shard_0001.c"
        content = shard_path.read_text(encoding="utf-8")
        self.assertIn("Recovered intra-function jump table 0x004364d4 (4 targets)", content)
        self.assertIn("Recovered intra-function jump table 0x0045cd24 (11 targets)", content)
        self.assertIn("__builtin_trap();", content)
        self.assertNotIn("DISPATCH_TAIL(c, MR32(RG_(esi)*4+0x4364d4u));", content)
        self.assertNotIn("DISPATCH_TAIL(c, MR32(RG_(ebp)*4+0x45cd24u));", content)


if __name__ == "__main__":
    unittest.main()
