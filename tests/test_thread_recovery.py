"""Focused structural and regression tests for authentic guest thread entrypoint recovery."""

import json
import re
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

class TestThreadRecovery(unittest.TestCase):
    def setUp(self):
        self.cat_path = ROOT_DIR / "research" / "local" / "phase1" / "catalog.json"
        self.fntab_h_path = ROOT_DIR / "gen" / "fntab.h"
        self.fntab_c_path = ROOT_DIR / "gen" / "fntab.c"
        self.shard22_path = ROOT_DIR / "gen" / "shard_0022.c"

    def test_recovered_thread_functions_in_catalog(self):
        """Verify sub_008976e4 and sub_008991ac are present in catalog.json with correct metadata."""
        with open(self.cat_path, "r", encoding="utf-8") as f:
            cat = json.load(f)

        func_map = {f["address"]: f for f in cat["functions"]}

        # 1. Entry thunk
        self.assertIn(0x008976e4, func_map, "sub_008976e4 missing from catalog.json")
        fn1 = func_map[0x008976e4]
        self.assertEqual(fn1["blocks"][0][0], 0x008976e4)
        self.assertEqual(fn1["blocks"][0][1], 0x0089770a)

        # 2. Worker loop
        self.assertIn(0x008991ac, func_map, "sub_008991ac missing from catalog.json")
        fn2 = func_map[0x008991ac]
        self.assertEqual(fn2["blocks"][0][0], 0x008991ac)

    def test_fntab_declarations_and_dispatch(self):
        """Verify fntab.h prototypes and fntab.c g_dtab bindings."""
        h_text = self.fntab_h_path.read_text(encoding="utf-8")
        self.assertIn("void sub_008976e4(CPU *c);", h_text)
        self.assertIn("void sub_008991ac(CPU *c);", h_text)

        c_text = self.fntab_c_path.read_text(encoding="utf-8")
        slot1 = 0x008976e4 - 0x00401000
        slot2 = 0x008991ac - 0x00401000
        self.assertIn(f"g_dtab[0x{slot1:08x}u] = sub_008976e4;", c_text)
        self.assertIn(f"g_dtab[0x{slot2:08x}u] = sub_008991ac;", c_text)

    def test_authentic_instructions_in_shard22(self):
        """Verify authentic assembly semantics in lifted C99 code."""
        code = self.shard22_path.read_text(encoding="utf-8")

        # Verify sub_008976e4 contains authentic mov [eax], 1 (acknowledgment write)
        self.assertIn("void sub_008976e4(CPU *c)", code)
        thunk_match = re.search(r"void sub_008976e4\(CPU \*c\) \{(.*?)\n\}", code, re.DOTALL)
        self.assertIsNotNone(thunk_match)
        thunk_body = thunk_match.group(1)
        self.assertIn("MR32(RG_(eax)) = (0x1u);", thunk_body)
        self.assertIn("DISPATCH_CALL(c, MR32(RG_(ebp)+0xfffffff8u));", thunk_body)

        # Verify sub_008991ac contains worker status set and SetEvent
        self.assertIn("void sub_008991ac(CPU *c)", code)
        worker_match = re.search(r"void sub_008991ac\(CPU \*c\) \{(.*?)\n\}", code, re.DOTALL)
        self.assertIsNotNone(worker_match)
        worker_body = worker_match.group(1)
        self.assertIn("MR32(RG_(esi)+0x4u) = (0x1u);", worker_body)
        self.assertIn("DISPATCH_CALL(c, MR32(0x967134u));", worker_body)

if __name__ == "__main__":
    unittest.main()
