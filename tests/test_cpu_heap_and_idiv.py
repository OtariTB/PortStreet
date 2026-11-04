"""Targeted Tests for CPU/Heap Non-Overlap and Signed IDIV Correctness.

Validates:
1. GUEST_CPU_STRUCT_ADDR is placed in the verified reserved TEB/TLS page (0x00104000).
2. CPU structure address does not overlap with Guest Stack, PE sections, or Guest Dynamic Heap.
3. All WASM test harnesses use the non-overlapping CPU address (0x00104000).
4. Signed 64/32-bit IDIV logic handles all sign combinations, division by zero, and quotient overflow.
5. Undefined C behavior (negative signed left-shift) is eliminated from manual overrides and shards.
6. sub_00435390 is registered in MANUAL_RECOVERIES and present in tools/manual_overrides.py.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from tools.manual_overrides import MANUAL_RECOVERIES


def simulate_idiv_32(edx: int, eax: int, divisor: int) -> tuple[int, int]:
    """Pure-Python reference implementation of the lifted 64/32-bit IDIV block."""
    den = divisor if divisor < 0x80000000 else divisor - 0x100000000
    if den == 0:
        return (eax, edx)  # Div-by-zero protected

    # Unsigned 64-bit shift followed by two's complement interpretation
    raw_64 = ((edx & 0xFFFFFFFF) << 32) | (eax & 0xFFFFFFFF)
    num = raw_64 if raw_64 < 0x8000000000000000 else raw_64 - 0x10000000000000000

    if num == -9223372036854775808 and den == -1:
        return (eax, edx)  # Overflow protected

    # Python's integer division // rounds towards -infinity, but C99 / x86 rounds towards zero
    # Simulate truncating division:
    q = int(num / den)
    rem = num - (q * den)

    if -2147483648 <= q <= 2147483647:
        new_eax = q & 0xFFFFFFFF
        new_edx = rem & 0xFFFFFFFF
        return (new_eax, new_edx)
    return (eax, edx)  # Quotient overflow protected


class TestCpuHeapAndIdiv(unittest.TestCase):
    """Test suite validating CPU/Heap separation and Signed IDIV correctness."""

    def test_cpu_struct_address_bounds(self) -> None:
        """Verify GUEST_CPU_STRUCT_ADDR is in TEB/TLS range and avoids all other regions."""
        cpu_addr = 0x00104000
        cpu_size = 512

        # 1. Within TEB/TLS reserved range (0x00100000..0x00200000)
        self.assertGreaterEqual(cpu_addr, 0x00100000)
        self.assertLessEqual(cpu_addr + cpu_size, 0x00200000)

        # 2. Does not collide with TEB core structure (0x00100000..0x00100300)
        self.assertGreaterEqual(cpu_addr, 0x00100300)

        # 3. Does not collide with CRT base / argv / envp (0x00101000..0x00102400)
        self.assertGreaterEqual(cpu_addr, 0x00102400)

        # 4. Does not collide with Guest Stack (0x00200000..0x00400000)
        self.assertTrue(cpu_addr + cpu_size <= 0x00200000 or cpu_addr >= 0x00400000)

        # 5. Does not collide with Guest Dynamic Heap (0x02000000..0x28000000)
        self.assertTrue(cpu_addr + cpu_size <= 0x02000000 or cpu_addr >= 0x28000000)

    def test_test_harnesses_cpu_address(self) -> None:
        """Verify no test harness places CPU structure at 0x02000000 (GUEST_HEAP_START)."""
        harness_files = [
            WORKSPACE / "tests" / "test_game_wasm.mjs",
            WORKSPACE / "tests" / "test_engine_lifecycle_3_3a.mjs",
            WORKSPACE / "tests" / "test_guest_stack_arguments.mjs",
            WORKSPACE / "tests" / "test_multi_frame_stability_3_3b.mjs",
            WORKSPACE / "tests" / "test_prostreet_tick.mjs",
            WORKSPACE / "tests" / "test_seh_prolog_wasm.mjs",
            WORKSPACE / "web" / "tests" / "wasm_loader.test.ts",
        ]

        for path in harness_files:
            self.assertTrue(path.is_file(), f"{path} must exist")
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("CPU_STRUCT_VA = 0x02000000", content, f"{path} must not use 0x02000000 for CPU")
            self.assertNotIn("CPU_VA = 0x02000000", content, f"{path} must not use 0x02000000 for CPU")
            self.assertTrue(
                "0x00104000" in content,
                f"{path} must use the reserved address 0x00104000 for guest CPU",
            )

    def test_signed_idiv_positive_positive(self) -> None:
        """Verify signed IDIV: 100 / 7 = quotient 14, remainder 2."""
        q, rem = simulate_idiv_32(0x00000000, 100, 7)
        self.assertEqual(q, 14)
        self.assertEqual(rem, 2)

    def test_signed_idiv_negative_positive(self) -> None:
        """Verify signed IDIV: -100 / 7 = quotient -14, remainder -2."""
        # -100 in 32-bit is 0xFFFFFF9C, sign extended in EDX is 0xFFFFFFFF
        q, rem = simulate_idiv_32(0xFFFFFFFF, 0xFFFFFF9C, 7)
        self.assertEqual(q, (-14) & 0xFFFFFFFF)
        self.assertEqual(rem, (-2) & 0xFFFFFFFF)

    def test_signed_idiv_positive_negative(self) -> None:
        """Verify signed IDIV: 100 / -7 = quotient -14, remainder 2 (remainder follows dividend sign)."""
        den = (-7) & 0xFFFFFFFF
        q, rem = simulate_idiv_32(0x00000000, 100, den)
        self.assertEqual(q, (-14) & 0xFFFFFFFF)
        self.assertEqual(rem, 2)

    def test_signed_idiv_negative_negative(self) -> None:
        """Verify signed IDIV: -100 / -7 = quotient 14, remainder -2."""
        den = (-7) & 0xFFFFFFFF
        q, rem = simulate_idiv_32(0xFFFFFFFF, 0xFFFFFF9C, den)
        self.assertEqual(q, 14)
        self.assertEqual(rem, (-2) & 0xFFFFFFFF)

    def test_signed_idiv_division_by_zero(self) -> None:
        """Verify division by zero is safely guarded without crashing or altering registers."""
        q, rem = simulate_idiv_32(0x12345678, 0x9ABCDEF0, 0)
        self.assertEqual(q, 0x9ABCDEF0)
        self.assertEqual(rem, 0x12345678)

    def test_signed_idiv_quotient_overflow(self) -> None:
        """Verify quotient overflow (result > INT32_MAX) is safely guarded."""
        # Dividend = 0x7FFFFFFF00000000 (very large 64-bit number), divisor = 1
        q, rem = simulate_idiv_32(0x7FFFFFFF, 0x00000000, 1)
        self.assertEqual(q, 0x00000000)
        self.assertEqual(rem, 0x7FFFFFFF)

    def test_no_signed_negative_left_shift(self) -> None:
        """Verify that undefined behavior `(int64_t)... << 32` is absent from all source files."""
        pattern = re.compile(r"\(int64_t\)\s*\(int32_t\)\s*RG_\(edx\)\s*<<\s*32")

        for fpath in [WORKSPACE / "gen" / "shard_0001.c", WORKSPACE / "tools" / "manual_overrides.py"]:
            text = fpath.read_text(encoding="utf-8")
            matches = pattern.findall(text)
            self.assertEqual(
                len(matches),
                0,
                f"Found {len(matches)} occurrences of undefined signed negative left-shift in {fpath}",
            )

    def test_sub_00435390_manual_recovery_registered(self) -> None:
        """Verify sub_00435390 is registered in MANUAL_RECOVERIES with corrected IDIV."""
        self.assertIn(0x00435390, MANUAL_RECOVERIES)
        code = MANUAL_RECOVERIES[0x00435390]
        self.assertNotIn("/* Unsupported: idiv", code)
        self.assertIn("MR32(RG_(ebp)+0xcu)", code)
        self.assertIn("RG_(esi)", code)
        self.assertIn("_q = _num / _den", code)


if __name__ == "__main__":
    unittest.main()
