"""Focused regression tests for automatic indirect callback discovery and registration."""

import glob
import json
import re
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

class TestCallbackRecovery(unittest.TestCase):
    def setUp(self):
        self.cat_path = ROOT_DIR / "research" / "local" / "phase1" / "catalog.json"
        self.fntab_h_path = ROOT_DIR / "gen" / "fntab.h"
        self.fntab_c_path = ROOT_DIR / "gen" / "fntab.c"

    def test_recovered_callbacks_in_catalog(self):
        """Verify the high-frequency array constructor callbacks are in catalog.json."""
        with open(self.cat_path, "r", encoding="utf-8") as f:
            cat = json.load(f)

        func_addrs = {f["address"] for f in cat["functions"]}

        # Test key callbacks that previously caused 9,148 unresolved events
        key_callbacks = [
            0x004b2f80,  # 9,000-hit constructor
            0x0049faf0,  # 47-hit constructor
            0x0075fb40,  # 41-hit constructor
            0x00722510,  # 16-hit constructor
            0x00428f30,  # 13-hit constructor
            0x004ad280,  # 11-hit constructor
            0x004a6f50,  # 5-hit constructor
            0x006d3370,  # 4-hit constructor
            0x00722310,  # 4-hit constructor
            0x007360a0,  # 4-hit constructor
            0x007222d0,  # 3-hit constructor
        ]

        for va in key_callbacks:
            self.assertIn(va, func_addrs, f"Callback 0x{va:08x} missing from catalog.json")

    def test_recovered_callbacks_in_fntab(self):
        """Verify declarations in fntab.h and g_dtab registrations in fntab.c."""
        with open(self.fntab_h_path, "r", encoding="utf-8") as f:
            fntab_h = f.read()
        with open(self.fntab_c_path, "r", encoding="utf-8") as f:
            fntab_c = f.read()

        key_callbacks = [
            0x004b2f80, 0x0049faf0, 0x0075fb40, 0x00722510,
            0x00428f30, 0x004ad280, 0x004a6f50, 0x006d3370,
            0x00722310, 0x007360a0, 0x007222d0
        ]

        for va in key_callbacks:
            fname = f"sub_{va:08x}"
            self.assertIn(f"void {fname}(CPU *c);", fntab_h, f"{fname} missing prototype in fntab.h")
            off = va - 0x00401000
            self.assertIn(f"g_dtab[0x{off:08x}u] = {fname};", fntab_c, f"{fname} missing in g_dtab in fntab.c")

        self.assertIn("fntab_init_recovered_callbacks();", fntab_c, "fntab_init_recovered_callbacks missing from fntab_init")

    def test_no_duplicate_shard_definitions(self):
        """Verify 0 duplicate function symbols across all 32 shard files."""
        all_defs = []
        for s in sorted((ROOT_DIR / "gen").glob("shard_*.c")):
            with open(s, "r", encoding="utf-8") as f:
                text = f.read()
            fns = re.findall(r"void (sub_[0-9a-fA-F]{8})\(CPU \*c\)", text)
            all_defs.extend(fns)

        self.assertEqual(len(all_defs), len(set(all_defs)), f"Found duplicate function definitions in shards!")

if __name__ == "__main__":
    unittest.main()
