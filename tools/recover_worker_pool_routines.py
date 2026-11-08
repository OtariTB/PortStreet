"""Additive recovery of 6 authentic game functions required for worker thread pool execution and chunk lookups:
- 0x004641f0: Chunk string comparator (shard_0001.c)
- 0x00464230: Chunk integer key comparator (shard_0001.c)
- 0x004b0100: Worker Thread 0 entry callback (shard_0003.c)
- 0x00909370: Worker queue dequeue helper (shard_0024.c)
- 0x00909550: Worker Thread 2 thread pool execution loop (shard_0024.c)
- 0x0090d650: Worker pool task initializer helper (shard_0024.c)
"""
import json
import re
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from tools.build_catalog import CatalogBuilder
from tools.lift_catalog import FunctionLifter

def run():
    # Detect game exe
    cfg_path = WORKSPACE / "config" / "local.json"
    nfs_path = None
    if cfg_path.exists():
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            p1 = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
            if p1.exists(): nfs_path = p1
            p2 = Path(cfg["game_root"]) / "nfs.exe"
            if p2.exists(): nfs_path = p2
        except Exception:
            pass

    if not nfs_path:
        default_paths = [
            Path(r"C:\Users\tabat\OneDrive\Desktop\Need-for-Speed-Pro-Street-SteamRIP.com\Need For Spped - Pro Street\nfs.exe"),
            Path(r"C:\Games\Pro Street\Need For Spped - Pro Street\nfs.exe"),
        ]
        for p in default_paths:
            if p.exists():
                nfs_path = p
                break

    assert nfs_path and nfs_path.exists(), f"nfs.exe not found: {nfs_path}"
    print(f"Using nfs.exe at: {nfs_path}")

    with open(nfs_path, "rb") as f:
        raw_exe = f.read()

    cat_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.json"
    with open(cat_path, "r", encoding="utf-8") as f:
        cat = json.load(f)

    builder = CatalogBuilder(raw_exe, {"trampolines": []})

    funcs_to_add = [
        0x004641f0,
        0x00464230,
        0x004b0100,
        0x00909370,
        0x00909550,
        0x0090d650,
    ]
    existing_addrs = {f["address"] for f in cat["functions"]}

    added_fns = []
    for va in funcs_to_add:
        fn, calls = builder.disassemble_function(va, set())
        assert fn and fn["address"] == va, f"Failed to disassemble 0x{va:08x}"
        if va not in existing_addrs:
            cat["functions"].append(fn)
            added_fns.append(va)

    cat["functions"].sort(key=lambda x: x["address"])
    with open(cat_path, "w", encoding="utf-8") as f:
        json.dump(cat, f, indent=2)
    print(f"Added {len(added_fns)} functions to catalog.json (total: {len(cat['functions'])})")

    # Lift the 6 functions
    flifter = FunctionLifter(raw_exe, cat, enable_lregs=True, enable_flagabi=True)
    lifted_codes = {va: flifter.lift_function(va) for va in funcs_to_add}

    # Map each function to target shard
    shard_map = {
        0x004641f0: WORKSPACE / "gen" / "shard_0001.c",
        0x00464230: WORKSPACE / "gen" / "shard_0001.c",
        0x004b0100: WORKSPACE / "gen" / "shard_0003.c",
        0x00909370: WORKSPACE / "gen" / "shard_0024.c",
        0x00909550: WORKSPACE / "gen" / "shard_0024.c",
        0x0090d650: WORKSPACE / "gen" / "shard_0024.c",
    }

    # Insert into shards
    for shard_path in sorted(set(shard_map.values())):
        shard_text = shard_path.read_text(encoding="utf-8")
        shard_vas = [va for va, p in shard_map.items() if p == shard_path]
        for va in shard_vas:
            code = lifted_codes[va]
            fn_name = f"sub_{va:08x}"
            if f"void {fn_name}(CPU *c)" in shard_text:
                pat = re.compile(rf"void {fn_name}\(CPU \*c\) \{{.*?^\}}", re.MULTILINE | re.DOTALL)
                shard_text = pat.sub(code.strip(), shard_text)
                print(f"Updated {fn_name} in {shard_path.name}")
            else:
                matches = list(re.finditer(r"^void sub_([0-9a-f]{8})\(CPU \*c\)", shard_text, re.MULTILINE))
                inserted = False
                for m in matches:
                    other_va = int(m.group(1), 16)
                    if other_va > va:
                        pos = m.start()
                        shard_text = shard_text[:pos] + code.strip() + "\n\n" + shard_text[pos:]
                        inserted = True
                        print(f"Inserted {fn_name} before sub_{other_va:08x} in {shard_path.name}")
                        break
                if not inserted:
                    shard_text = shard_text.rstrip() + "\n\n" + code.strip() + "\n"
                    print(f"Appended {fn_name} to {shard_path.name}")

        shard_path.write_text(shard_text, encoding="utf-8")

    # Update fntab.h
    fntab_h = WORKSPACE / "gen" / "fntab.h"
    h_text = fntab_h.read_text(encoding="utf-8")
    for va in funcs_to_add:
        decl = f"void sub_{va:08x}(CPU *c);"
        if decl not in h_text:
            matches = list(re.finditer(r"^void sub_([0-9a-f]{8})\(CPU \*c\);", h_text, re.MULTILINE))
            inserted = False
            for m in matches:
                other_va = int(m.group(1), 16)
                if other_va > va:
                    pos = m.start()
                    h_text = h_text[:pos] + decl + "\n" + h_text[pos:]
                    inserted = True
                    print(f"Inserted {decl} in fntab.h")
                    break
            if not inserted:
                h_text = h_text.replace("/* Master dispatch table", decl + "\n\n/* Master dispatch table")
                print(f"Appended {decl} in fntab.h")
    fntab_h.write_text(h_text, encoding="utf-8")

    # Update fntab.c
    fntab_c = WORKSPACE / "gen" / "fntab.c"
    c_text = fntab_c.read_text(encoding="utf-8")
    for va in funcs_to_add:
        slot = va - 0x00401000
        entry = f"    g_dtab[0x{slot:08x}u] = sub_{va:08x};"
        if entry.strip() not in c_text:
            matches = list(re.finditer(r"^\s+g_dtab\[0x([0-9a-f]{8})u\] = sub_[0-9a-f]{8};", c_text, re.MULTILINE))
            inserted = False
            for m in matches:
                other_slot = int(m.group(1), 16)
                if other_slot > slot:
                    pos = m.start()
                    c_text = c_text[:pos] + entry + "\n" + c_text[pos:]
                    inserted = True
                    print(f"Inserted {entry.strip()} in fntab.c")
                    break
            if not inserted:
                c_text = c_text.replace("void fntab_init(void)", entry + "\n}\n\nvoid fntab_init(void)")
                print(f"Appended {entry.strip()} in fntab.c")
    fntab_c.write_text(c_text, encoding="utf-8")

    # Update manifest.json function counts
    manifest_path = WORKSPACE / "gen" / "manifest.json"
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["total_functions"] = len(cat["functions"])
        for s in manifest["shards"]:
            sp = WORKSPACE / "gen" / s["filename"]
            s["function_count"] = len(re.findall(r"^void sub_[0-9a-f]{8}\(CPU \*c\)", sp.read_text(encoding="utf-8"), re.MULTILINE))
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print("Updated gen/manifest.json")

    print("\nRecovery of 6 authentic routines completed successfully!")

if __name__ == "__main__":
    run()
