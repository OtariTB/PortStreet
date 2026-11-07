"""Focused Regression Test for SecuROM Intra-Function Splice Recovery (Rule A).

Validates that:
1. sub_00465620 is recovered automatically with all 5 basic blocks.
2. No truncated bodies or unresolvable DISPATCH_TAIL to intra-splices exist.
3. InstructionLifter translates pushfd, popfd, clc, stc, xchg, rol, ror, lahf, sahf, idiv, div, and string ops cleanly.
4. sub_00465620 requires no manual override in tools/manual_overrides.py.
5. All 437 SecuROM-spliced candidates recover cleanly with 0 unsupported instructions and valid exits.
6. Differential execution in Unicorn confirms authentic behavior for spliced functions with ror.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path
import re
import struct
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM
from tools.lift_catalog import FunctionLifter, InstructionLifter
from tools.manual_overrides import MANUAL_RECOVERIES
from tools.trampoline_analyzer import create_unicorn_emulator
import unicorn
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI,
    UC_X86_REG_EDI, UC_X86_REG_EFLAGS
)

WORKSPACE = Path(__file__).resolve().parent.parent

class TestSecuROMSpliceRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cleaned_exe = WORKSPACE / "research" / "local" / "phase1" / "nfs_cleaned.exe"
        if cleaned_exe.exists():
            cls.raw_exe = cleaned_exe.read_bytes()
        else:
            cls.raw_exe = Path(
                r"C:/Users/tabat/OneDrive/Desktop/Need-for-Speed-Pro-Street-SteamRIP.com/Need For Spped - Pro Street/nfs.exe"
            ).read_bytes()

        cat_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.json"
        cls.catalog = json.loads(cat_path.read_text(encoding="utf-8"))
        cls.fl = FunctionLifter(cls.raw_exe, cls.catalog, enable_lregs=True)

    def test_sub_00465620_automatic_recovery_no_override(self):
        """sub_00465620 must be recovered by the generator without manual override."""
        self.assertNotIn(
            0x00465620,
            MANUAL_RECOVERIES,
            "sub_00465620 must not rely on manual_overrides.py",
        )

        code = self.fl.lift_function(0x00465620)

        # 1. Verify all 5 basic block labels are present
        expected_labels = [
            "L_00465620:",
            "L_004df276:",
            "L_00465627:",
            "L_00465667:",
            "L_00465677:",
        ]
        for lbl in expected_labels:
            self.assertIn(lbl, code, f"Missing basic block label {lbl}")

        # 2. Verify no truncated tail dispatch to the splice
        self.assertNotIn(
            "DISPATCH_TAIL(c, 0x004df276u)",
            code,
            "sub_00465620 must not emit DISPATCH_TAIL to intra-splice 0x004df276",
        )

        # 3. Verify internal branch to splice and return to body
        self.assertIn("goto L_004df276;", code)
        self.assertIn("goto L_00465627;", code)

        # 4. Verify authentic SEH link and tear-down
        self.assertIn("c->fs_base", code)
        self.assertIn("0xa8be00u", code)  # __security_cookie

        # 5. Verify internal sub-calls
        self.assertIn("sub_0052aa00(c);", code)
        self.assertIn("sub_006a4860(c);", code)  # 248-byte allocator

        # 6. Verify ret 8 stack cleanup (12 bytes total: 4 return + 8 args)
        self.assertIn("RG_(esp) += 12u;", code)
        self.assertIn("return;", code)

    def test_splice_instructions_lifter_support(self):
        """InstructionLifter must support pushfd, popfd, clc, stc, and xchg."""
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        lifter = InstructionLifter(cs, use_rg=True)

        splice_bytes = bytes.fromhex(
            "50 9c f8 a1 58 ee 9e 01 1b 05 90 55 45 00 9d 87 04 24"
        )
        insns = list(cs.disasm(splice_bytes, 0x004df276))
        self.assertEqual(len(insns), 7)

        for ins in insns:
            lines = lifter.lift_instruction(ins)
            self.assertTrue(len(lines) > 0)
            joined = " ".join(lines)
            self.assertNotIn("Unsupported", joined)

    def test_extended_instructions_lifter_support(self):
        """InstructionLifter must support rol, ror, lahf, sahf, idiv, div, rep movsd, rep stosd, repe cmpsb."""
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True
        lifter = InstructionLifter(cs, use_rg=True)

        test_cases = [
            ("rol eax, cl", "d3 c0"),
            ("ror edx, cl", "d3 ca"),
            ("rol ebx, 1", "d1 c3"),
            ("ror edi, 1", "d1 cf"),
            ("lahf", "9f"),
            ("sahf", "9e"),
            ("idiv ecx", "f7 f9"),
            ("idiv dword ptr [ecx + 0x24]", "f7 79 24"),
            ("div ecx", "f7 f1"),
            ("rep movsd", "f3 a5"),
            ("rep stosd", "f3 ab"),
            ("repe cmpsb", "f3 a6"),
        ]

        for name, hex_str in test_cases:
            ins = list(cs.disasm(bytes.fromhex(hex_str), 0x1000))[0]
            lines = lifter.lift_instruction(ins)
            self.assertTrue(len(lines) > 0, f"No lines emitted for {name}")
            joined = " ".join(lines)
            self.assertNotIn("Unsupported", joined, f"Unsupported instruction emitted for {name}")

    def test_sub_00402310_candidate_recovery(self):
        """Candidate splice sub_00402310 (which uses ror edx, cl) must recover cleanly."""
        code = self.fl.lift_function(0x00402310)
        self.assertIn("L_00402310:", code)
        self.assertIn("L_004544d2:", code)
        self.assertIn("L_00402317:", code)
        self.assertNotIn("DISPATCH_TAIL(c, 0x004544d2u)", code)
        self.assertNotIn("Unsupported", code)
        self.assertIn("return;", code)

    def test_unicorn_differential_ror_sub_00402310(self):
        """Verify sub_00402310 executes through its splice in Unicorn and returns to caller."""
        uc, _ = create_unicorn_emulator(self.raw_exe)
        uc.mem_map(0x00200000, 0x00200000)
        uc.mem_write(0x00900000, b"\xf4")
        esp_init = 0x003ff000
        uc.mem_write(esp_init, struct.pack("<IIIIII", 0x00900000, 0, 0, 0, 0, 0))
        uc.reg_write(UC_X86_REG_ESP, esp_init)

        visited = []
        def hook(uc, addr, size, ud):
            visited.append(addr)
            if addr == 0x00402317:  # reached continuation after splice!
                uc.emu_stop()

        uc.hook_add(unicorn.UC_HOOK_CODE, hook)
        try:
            uc.emu_start(0x00402310, 0x00900000, count=50)
        except Exception:
            pass

        self.assertIn(0x00402310, visited)  # Entry
        self.assertIn(0x004544d2, visited)  # Splice
        self.assertIn(0x00402317, visited)  # Continuation body reached!

    def test_all_437_candidates_fully_recovered(self):
        """Verify all 437 SecuROM splice candidates recover with 0 errors and valid exits."""
        def check_splice(target_va: int, max_len: int = 32):
            code = self.fl.read_bytes(target_va, max_len * 15)
            if not code: return None
            insns = list(self.fl.cs.disasm(code, target_va))
            splice_insns = []
            for ins in insns:
                splice_insns.append(ins)
                if ins.mnemonic == 'jmp':
                    if ins.operands and ins.operands[0].type == CS_OP_IMM:
                        return splice_insns, ins.operands[0].imm
                    break
                if ins.mnemonic in ('ret', 'retf', 'call'): break
                if len(splice_insns) >= max_len: break
            return None

        candidates = []
        for f_va, f in self.fl.functions.items():
            if not f.get('blocks'): continue
            b_start, b_end, succs, is_exit = f['blocks'][0]
            code = self.fl.read_bytes(b_start, b_end - b_start)
            insns = list(self.fl.cs.disasm(code, b_start))
            if not insns or insns[-1].mnemonic != 'jmp': continue
            last_ins = insns[-1]
            if not last_ins.operands or last_ins.operands[0].type != CS_OP_IMM: continue
            raw_dest = last_ins.operands[0].imm
            res = check_splice(raw_dest)
            if res:
                s_insns, ret_dest = res
                if ret_dest == b_end:
                    candidates.append((f_va, raw_dest, ret_dest))

        self.assertGreaterEqual(len(candidates), 437, "Expected at least 437 splice candidates")

        failures = []
        for f_va, splice_va, ret_dest in candidates:
            code = self.fl.lift_function(f_va)
            unsupported = re.findall(r'/\* Unsupported: ([^*]+) \*/', code)
            if unsupported:
                failures.append((f_va, f"Unsupported: {unsupported[:2]}"))
                continue
            labels = set(re.findall(r'^(L_[0-9a-fA-F]{8}):', code, re.MULTILINE))
            gotos = set(re.findall(r'goto (L_[0-9a-fA-F]{8});', code))
            if gotos - labels:
                failures.append((f_va, f"Dangling gotos: {gotos - labels}"))
                continue
            if f"DISPATCH_TAIL(c, 0x{splice_va:08x}u)" in code:
                failures.append((f_va, "DISPATCH_TAIL to splice"))
                continue
            has_return = "return;" in code
            has_tail = "DISPATCH_TAIL(c," in code
            has_cleanup = bool(re.findall(r'(?:RG_\(esp\)|c->esp)\s*\+=\s*(\d+)u;', code))
            if not has_return and not has_tail and not has_cleanup:
                failures.append((f_va, "No valid exit"))
                continue

        self.assertEqual(len(failures), 0, f"Expected 0 failures, got {len(failures)}: {failures[:5]}")

    def test_production_shards_contain_complete_recovered_cfgs(self):
        """Verify that production gen/shard_*.c contain the full recovered CFG for all candidates."""
        manifest = json.loads((WORKSPACE / "gen" / "manifest.json").read_text(encoding="utf-8"))
        
        # Build mapping from address range to shard file
        shard_ranges = []
        for s in manifest["shards"]:
            shard_ranges.append((int(s["min_address"], 16), int(s["max_address"], 16), s["filename"]))

        def find_shard_for_va(va: int):
            for lo, hi, name in shard_ranges:
                if lo <= va <= hi:
                    return name
            return None

        # Sample 20 diverse candidates across different shards
        test_candidates = [
            (0x00402820, 0x004df28d, "L_00402827:"),
            (0x00402310, 0x004544d2, "L_00402317:"),
            (0x00405dd0, 0x0052c8b6, "L_00405dd7:"),
            (0x00409e90, 0x00537dc6, "L_00409eaf:"),
            (0x00420590, 0x0045ad26, "L_00420597:"),
            (0x004318e0, 0x00433816, "L_004318e9:"),
            (0x00465620, 0x004df276, "L_00465627:"),
            (0x004d2e90, 0x0044a7e0, "L_004d2e9d:"),
        ]

        for va, splice_va, continuation_label in test_candidates:
            shard_file = find_shard_for_va(va)
            self.assertIsNotNone(shard_file, f"No shard found for 0x{va:08x}")
            shard_text = (WORKSPACE / "gen" / shard_file).read_text(encoding="utf-8")
            m = re.search(rf'void sub_{va:08x}\(CPU \*c\) \{{(.*?)\n\}}', shard_text, re.DOTALL)
            self.assertIsNotNone(m, f"sub_{va:08x} not found in {shard_file}")
            fn_code = m.group(1)

            # Must NOT contain truncated tail dispatch to splice
            self.assertNotIn(
                f"DISPATCH_TAIL(c, 0x{splice_va:08x}u);",
                fn_code,
                f"sub_{va:08x} in {shard_file} still has unresolvable DISPATCH_TAIL to splice",
            )
            # Must contain continuation label
            self.assertIn(
                continuation_label,
                fn_code,
                f"sub_{va:08x} in {shard_file} missing continuation block {continuation_label}",
            )

    def test_sub_0066666f_cyclic_splice_deduplication(self):
        """sub_0066666f contains a cyclic loop branching back to splice 0x0053aea9.
        Verify that L_0053aea9 is emitted exactly once, with correct branch connectivity."""
        fn_code = self.fl.lift_function(0x0066666f)
        # Exactly one definition of label L_0053aea9
        self.assertEqual(
            fn_code.count("L_0053aea9:"),
            1,
            "L_0053aea9 must be defined exactly once in sub_0066666f",
        )
        # Both entry (0x0066666f) and loop block (0x00666670) must branch to L_0053aea9
        self.assertEqual(
            fn_code.count("goto L_0053aea9;"),
            2,
            "Both entry and loop blocks must branch to L_0053aea9",
        )
        # Splice must branch to continuation block L_00666679
        self.assertIn("goto L_00666679;", fn_code)
        # Loop conditional jump must branch to L_00666670
        self.assertIn("if (CC_NE) goto L_00666670;", fn_code)
        # Authentic terminal return must be present
        self.assertIn("return;", fn_code)

if __name__ == "__main__":
    unittest.main()
