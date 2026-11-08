"""Unit and integration tests for recovered worker thread pool routines and comparator helpers:
- 0x004641f0: Chunk string comparator (shard_0001.c)
- 0x00464230: Chunk integer key comparator (shard_0001.c)
- 0x004b0100: Worker Thread 0 entry callback (shard_0003.c)
- 0x009058d0: Worker Thread 2 companion C++ runnable entrypoint (shard_0024.c)
- 0x00909370: Worker queue dequeue helper (shard_0024.c)
- 0x00909550: Worker Thread 2 thread pool execution loop (shard_0024.c)
- 0x0090d650: Worker pool task initializer helper (shard_0024.c)
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

class TestWorkerPoolRoutines(unittest.TestCase):
    def test_catalog_membership(self):
        cat_path = ROOT / "research" / "local" / "phase1" / "catalog.json"
        with open(cat_path, "r", encoding="utf-8") as f:
            cat = json.load(f)
        addrs = {x["address"] for x in cat["functions"]}
        required = [0x004641f0, 0x00464230, 0x004b0100, 0x009058d0, 0x00909370, 0x00909550, 0x0090d650]
        for va in required:
            self.assertIn(va, addrs, f"Function 0x{va:08x} missing from catalog.json")

    def test_fntab_headers_and_dispatch(self):
        h_text = (ROOT / "gen" / "fntab.h").read_text(encoding="utf-8")
        c_text = (ROOT / "gen" / "fntab.c").read_text(encoding="utf-8")
        required = [0x004641f0, 0x00464230, 0x004b0100, 0x009058d0, 0x00909370, 0x00909550, 0x0090d650]
        for va in required:
            decl = f"void sub_{va:08x}(CPU *c);"
            self.assertIn(decl, h_text, f"Declaration {decl} missing from fntab.h")
            slot = va - 0x00401000
            entry = f"g_dtab[0x{slot:08x}u] = sub_{va:08x};"
            self.assertIn(entry, c_text, f"Dispatch entry {entry} missing from fntab.c")

    def test_shard_implementations(self):
        shard_map = {
            0x004641f0: ROOT / "gen" / "shard_0001.c",
            0x00464230: ROOT / "gen" / "shard_0001.c",
            0x004b0100: ROOT / "gen" / "shard_0003.c",
            0x009058d0: ROOT / "gen" / "shard_0024.c",
            0x00909370: ROOT / "gen" / "shard_0024.c",
            0x00909550: ROOT / "gen" / "shard_0024.c",
            0x0090d650: ROOT / "gen" / "shard_0024.c",
        }
        for va, shard_path in shard_map.items():
            text = shard_path.read_text(encoding="utf-8")
            fn_sig = f"void sub_{va:08x}(CPU *c)"
            self.assertIn(fn_sig, text, f"{fn_sig} missing from {shard_path.name}")

if __name__ == "__main__":
    unittest.main()
