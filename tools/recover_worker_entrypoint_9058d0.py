"""Additive recovery of authentic worker thread entrypoint 0x009058d0:
- 0x009058d0: Win32 ThreadProc companion wrapper for C++ runnable objects (shard_0024.c)
  Sets up SEH, initializes TLS, invokes runnable vtable[1], decrements atomic completion refcount,
  and restores execution state with stdcall 'ret 4' cleanup.
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

    va = 0x009058d0
    existing_addrs = {f["address"] for f in cat["functions"]}

    fn, calls = builder.disassemble_function(va, set())
    assert fn and fn["address"] == va, f"Failed to disassemble 0x{va:08x}"
    if va not in existing_addrs:
        cat["functions"].append(fn)
        cat["functions"].sort(key=lambda x: x["address"])
        with open(cat_path, "w", encoding="utf-8") as f:
            json.dump(cat, f, indent=2)
        print(f"Added 0x{va:08x} to catalog.json (total: {len(cat['functions'])})")
    else:
        print(f"0x{va:08x} already in catalog.json")

    # Lift the function
    flifter = FunctionLifter(raw_exe, cat, enable_lregs=True, enable_flagabi=True)
    code = flifter.lift_function(va)

    # Shard is shard_0024.c
    shard_path = WORKSPACE / "gen" / "shard_0024.c"
    shard_text = shard_path.read_text(encoding="utf-8")
    fn_name = f"sub_{va:08x}"

    if f"void {fn_name}(CPU *c)" in shard_text:
        pat = re.compile(rf"void {fn_name}\(CPU \*c\) \{{.*?^\}}", re.MULTILINE | re.DOTALL)
        shard_text = pat.sub(code.strip(), shard_text)
        print(f"Updated {fn_name} in {shard_path.name}")
    else:
        # Insert before sub_00905982
        target_str = "void sub_00905982(CPU *c)"
        if target_str in shard_text:
            pos = shard_text.index(target_str)
            shard_text = shard_text[:pos] + code.strip() + "\n\n" + shard_text[pos:]
            print(f"Inserted {fn_name} before sub_00905982 in {shard_path.name}")
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

    print("\nRecovery of 0x009058d0 completed successfully!")

if __name__ == "__main__":
    run()
