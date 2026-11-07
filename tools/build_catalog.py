"""Master Control-Flow Recovery and Function Catalog Builder for NFS ProStreet.

Disassembles the entire code range (.text + .securom function bodies) in nfs.exe,
recovers basic blocks, control-flow graphs (CFGs), switch jump tables (jmp [reg*4 + table]),
and direct/indirect call cross-references.

Produces research/local/phase1/catalog.json conforming to the proven
'nfsu-catalog-bridge-v1' schema used by the static lifter.

The original game binary is opened strictly read-only.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time
from typing import Any, Sequence

WORKSPACE = Path(__file__).resolve().parent.parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM
from capstone.x86 import *

from tools.clean_drm import (
    EXPECTED_NFS_EXE_SHA256,
    apply_countdown_nops,
    find_countdown_stubs,
    parse_text_section,
)
from tools.trampoline_analyzer import parse_pe_sections, va_to_offset


def normalize_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize catalog according to the nfsu-catalog-bridge-v1 schema."""
    base = int(catalog["image_base"])
    lo = int(catalog["code_start"])
    hi = int(catalog["code_end"])
    if not base <= lo < hi:
        raise ValueError(f"Invalid image/code bounds: base=0x{base:08x}, lo=0x{lo:08x}, hi=0x{hi:08x}")

    functions = []
    seen_entries = set()

    for item in catalog["functions"]:
        entry = int(item["address"])
        if entry in seen_entries:
            raise ValueError(f"Duplicate function address: 0x{entry:08x}")
        if not lo <= entry < hi:
            raise ValueError(f"Function address outside code range: 0x{entry:08x}")
        seen_entries.add(entry)

        blocks = []
        starts = set()
        for raw in item["blocks"]:
            if len(raw) != 4:
                raise ValueError("Expected [start, end, successors, is_exit]")
            b_start, b_end = int(raw[0]), int(raw[1])
            if not lo <= b_start < b_end <= hi:
                raise ValueError(f"Invalid block bounds: 0x{b_start:08x}..0x{b_end:08x}")
            if b_start in starts:
                raise ValueError(f"Duplicate block start: 0x{b_start:08x}")
            if raw[3] not in (0, 1):
                raise ValueError(f"Invalid exit marker: {raw[3]}")
            starts.add(b_start)
            succs = sorted({int(a) for a in raw[2]})
            blocks.append([b_start, b_end, succs, int(raw[3])])

        if entry not in starts:
            raise ValueError(f"Function 0x{entry:08x} has no entry block starting at 0x{entry:08x}")

        blocks.sort()
        functions.append({
            "address": entry,
            "blocks": blocks,
            "entry_kind": item.get("entry_kind", "start"),
            "is_thunk": bool(item.get("is_thunk", False)),
            "calls_to": sorted({int(a) for a in item.get("calls_to", [])}),
            "jump_targets": sorted({int(a) for a in item.get("jump_targets", [])}),
        })

    functions.sort(key=lambda f: f["address"])
    external_calls = sorted({
        a for f in functions for a in f["calls_to"] if a not in seen_entries
    })

    return {
        "schema": "nfsu-catalog-bridge-v1",
        "image_base": base,
        "code_start": lo,
        "code_end": hi,
        "functions": functions,
        "unresolved_calls": external_calls,
        "binary_identity": "verified-sha256:" + EXPECTED_NFS_EXE_SHA256,
    }


class CatalogBuilder:
    """Disassembles and builds the master function catalog."""

    def __init__(self, raw_exe: bytes, trampoline_data: dict[str, Any]) -> None:
        self.raw_exe = raw_exe
        self.sections = parse_pe_sections(raw_exe)

        # Parse and clean .text section
        img_base, text_va, roff, text_bytes = parse_text_section(raw_exe)
        self.image_base = img_base
        self.text_va = text_va
        self.text_size = len(text_bytes)
        self.text_end = text_va + self.text_size

        stubs = find_countdown_stubs(text_va, roff, text_bytes)
        self.cleaned_text = bytes(apply_countdown_nops(text_bytes, stubs))

        # Find .securom section bounds
        securom_sec = next((s for s in self.sections if s[0] == ".securom"), None)
        if securom_sec:
            self.securom_va = securom_sec[1]
            self.securom_end = self.securom_va + securom_sec[2]
        else:
            self.securom_va = 0x019B1000
            self.securom_end = 0x01F687E2

        # Overall valid code range
        self.code_start = self.text_va
        self.code_end = max(self.text_end, self.securom_end)

        # Capstone disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

        # Trampoline maps: site_va -> target_va
        self.trampolines = trampoline_data.get("trampolines", [])
        self.trampoline_map = {t["site_va"]: t["target_va"] for t in self.trampolines}

    def in_code(self, va: int) -> bool:
        """Check if VA is in valid executable code sections (.text or .securom)."""
        return (self.text_va <= va < self.text_end) or (self.securom_va <= va < self.securom_end)

    def read_code_bytes(self, va: int, count: int = 15) -> bytes:
        """Read instruction bytes from cleaned .text or raw .securom."""
        if self.text_va <= va < self.text_end:
            off = va - self.text_va
            return self.cleaned_text[off : off + count]
        if self.securom_va <= va < self.securom_end:
            off = va - self.image_base
            return self.raw_exe[off : off + count]
        return b""

    def harvest_initial_seeds(self) -> set[int]:
        """Harvest confirmed reachable function entry points."""
        seeds = set()

        # 1. PE entry point
        pe_off = struct.unpack_from("<I", self.raw_exe, 0x3C)[0]
        ep_rva = struct.unpack_from("<I", self.raw_exe, pe_off + 24 + 16)[0]
        seeds.add(self.image_base + ep_rva)

        # 2. Main function at 0x004afee0
        seeds.add(0x004AFEE0)

        # 3. Static initializers: _initterm (0x00967608..0x0096a1f4)
        for va in range(0x00967608, 0x0096A1F4, 4):
            target = struct.unpack_from("<I", self.raw_exe, va_to_offset(va))[0]
            if self.in_code(target):
                seeds.add(target)

        # 4. Data pointers in .rdata and .data (vtables, callbacks, handlers)
        for sec_va, sec_sz in [(0x00967000, 0x000E3000), (0x00A4A000, 0x005C6000)]:
            sec_off = va_to_offset(sec_va)
            for i in range(0, sec_sz - 3, 4):
                val = struct.unpack_from("<I", self.raw_exe, sec_off + i)[0]
                if self.in_code(val):
                    seeds.add(val)

        # 5. Trampoline resolved targets
        for t in self.trampolines:
            target = t["target_va"]
            if self.in_code(target):
                seeds.add(target)

        # 6. Indirect constructor and destructor callbacks passed to iterator routines
        text_off = va_to_offset(self.text_va)
        text_data = self.raw_exe[text_off : text_off + self.text_size]
        iterator_targets = {0x00401000, 0x00828652, 0x0082858A}
        for i in range(len(text_data) - 5):
            if text_data[i] == 0xE8:
                rel = struct.unpack_from('<i', text_data, i + 1)[0]
                target_fn = self.text_va + i + 5 + rel
                if target_fn in iterator_targets:
                    site_va = self.text_va + i
                    pre_bytes = text_data[max(0, i - 50) : i]
                    pre_va = site_va - len(pre_bytes)
                    try:
                        insns = list(self.cs.disasm(pre_bytes, pre_va))
                    except Exception:
                        insns = []
                    pushes = []
                    for ins in reversed(insns):
                        if ins.mnemonic.startswith("push"):
                            pushes.append(ins)
                        elif ins.mnemonic in ("call", "ret"):
                            break
                        if len(pushes) >= 5:
                            break

                    if target_fn in (0x00401000, 0x00828652):
                        if len(pushes) >= 4 and pushes[3].operands and pushes[3].operands[0].type == X86_OP_IMM:
                            ctor = pushes[3].operands[0].imm
                            if self.in_code(ctor):
                                seeds.add(ctor)
                        if len(pushes) >= 5 and pushes[4].operands and pushes[4].operands[0].type == X86_OP_IMM:
                            dtor = pushes[4].operands[0].imm
                            if self.in_code(dtor):
                                seeds.add(dtor)
                    elif target_fn == 0x0082858A:
                        if len(pushes) >= 4 and pushes[3].operands and pushes[3].operands[0].type == X86_OP_IMM:
                            dtor = pushes[3].operands[0].imm
                            if self.in_code(dtor):
                                seeds.add(dtor)

        return seeds

    def disassemble_function(
        self,
        entry_va: int,
        known_functions: set[int],
        max_insns: int = 4000,
    ) -> tuple[dict[str, Any] | None, set[int]]:
        """Disassemble a function, return (function_dict, new_called_seeds)."""
        queue = deque([entry_va])
        visited_pcs = set()
        insns_by_va = {}
        calls = set()
        jumps = set()
        leaders = {entry_va}
        switch_targets: dict[int, list[int]] = {}
        valid = True

        while queue:
            curr = queue.popleft()
            if curr in visited_pcs or not self.in_code(curr):
                continue

            pc = curr
            while self.in_code(pc):
                if pc in insns_by_va:
                    break

                b = self.read_code_bytes(pc, 15)
                try:
                    i = next(self.cs.disasm(b, pc))
                except StopIteration:
                    valid = False
                    break

                insns_by_va[pc] = i
                visited_pcs.add(pc)
                m = i.mnemonic
                next_pc = pc + i.size

                # Call instructions
                if m == "call":
                    if i.operands and i.operands[0].type == X86_OP_IMM:
                        dest = i.operands[0].imm
                        dest = self.trampoline_map.get(dest, dest)
                        if self.in_code(dest):
                            calls.add(dest)

                # Return instructions
                if m in ("ret", "retf"):
                    break

                # Unconditional jumps
                if m == "jmp":
                    if i.operands and i.operands[0].type == X86_OP_IMM:
                        dest = i.operands[0].imm
                        dest = self.trampoline_map.get(dest, dest)
                        jumps.add(dest)
                        # Treat jump to another known function as tail call; otherwise internal branch
                        if dest not in known_functions and self.in_code(dest) and abs(dest - entry_va) < 0x8000:
                            leaders.add(dest)
                            queue.append(dest)
                    elif i.operands and i.operands[0].type == X86_OP_MEM:
                        # Switch table: jmp dword ptr [reg*4 + table]
                        mem = i.operands[0].mem
                        if mem.scale == 4 and mem.disp and self.in_code(mem.disp):
                            tbl_va = mem.disp
                            tbl_targets = []
                            for k in range(128):
                                t_off = va_to_offset(tbl_va) + k * 4
                                if t_off + 4 > len(self.raw_exe):
                                    break
                                target = struct.unpack_from("<I", self.raw_exe, t_off)[0]
                                if self.in_code(target):
                                    tbl_targets.append(target)
                                else:
                                    break
                            if tbl_targets:
                                switch_targets[pc] = tbl_targets
                                for t in tbl_targets:
                                    jumps.add(t)
                                    leaders.add(t)
                                    queue.append(t)
                    break

                # Conditional branches
                if m.startswith("j") or m in ("jecxz", "jcxz", "loop", "loope", "loopne"):
                    if i.operands and i.operands[0].type == X86_OP_IMM:
                        dest = i.operands[0].imm
                        dest = self.trampoline_map.get(dest, dest)
                        jumps.add(dest)
                        if self.in_code(dest):
                            leaders.add(dest)
                            queue.append(dest)
                    leaders.add(next_pc)
                    queue.append(next_pc)
                    break

                # Consecutive int3 padding
                if m == "int3":
                    off2 = pc + i.size - self.text_va
                    if 0 <= off2 and off2 + 3 <= len(self.cleaned_text):
                        if self.cleaned_text[off2 : off2 + 3] == b"\xcc\xcc\xcc":
                            break

                if m in ("hlt", "ud2"):
                    break

                if len(insns_by_va) > max_insns:
                    valid = False
                    break

                pc = next_pc

        if not valid or not insns_by_va or entry_va not in insns_by_va:
            return None, calls

        # Ensure function has at least one valid exit or jump
        has_exit = any(i.mnemonic in ("ret", "retf", "hlt", "ud2") for i in insns_by_va.values()) or any(
            i.mnemonic == "jmp" for i in insns_by_va.values()
        )
        if not has_exit:
            return None, calls

        # Build basic blocks
        sorted_leaders = sorted(l for l in leaders if l in insns_by_va)
        blocks = []
        for l_va in sorted_leaders:
            pc = l_va
            blk_insns = []
            is_exit = 0
            succs = []

            while pc in insns_by_va:
                ins = insns_by_va[pc]
                blk_insns.append(ins)
                m = ins.mnemonic
                next_pc = pc + ins.size

                if ins.address in switch_targets:
                    succs = sorted(set(switch_targets[ins.address]))
                    break

                if m in ("ret", "retf", "hlt", "ud2"):
                    is_exit = 1
                    break

                if m == "jmp":
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        dest = ins.operands[0].imm
                        dest = self.trampoline_map.get(dest, dest)
                        if dest in insns_by_va:
                            succs.append(dest)
                    break

                if m.startswith("j") or m in ("jecxz", "jcxz", "loop", "loope", "loopne"):
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        dest = ins.operands[0].imm
                        dest = self.trampoline_map.get(dest, dest)
                        if dest in insns_by_va:
                            succs.append(dest)
                    if next_pc in insns_by_va:
                        succs.append(next_pc)
                    break

                if next_pc in sorted_leaders:
                    succs.append(next_pc)
                    break

                pc = next_pc

            if blk_insns:
                b_start = blk_insns[0].address
                b_end = blk_insns[-1].address + blk_insns[-1].size
                blocks.append([b_start, b_end, sorted(set(succs)), is_exit])

        is_thunk = len(blocks) == 1 and len(insns_by_va) <= 2 and any(i.mnemonic == "jmp" for i in insns_by_va.values())
        func_dict = {
            "address": entry_va,
            "blocks": blocks,
            "entry_kind": "start",
            "is_thunk": is_thunk,
            "calls_to": sorted(calls),
            "jump_targets": sorted(jumps),
        }
        return func_dict, calls

    def build_catalog(self) -> dict[str, Any]:
        """Harvest seeds and recursively discover all functions."""
        seeds = self.harvest_initial_seeds()
        queue = deque(sorted(seeds))
        discovered: dict[int, dict[str, Any]] = {}
        all_known_entries = set(seeds)

        t0 = time.time()
        processed = 0

        while queue:
            entry_va = queue.popleft()
            if entry_va in discovered:
                continue

            func_dict, new_calls = self.disassemble_function(entry_va, all_known_entries)
            if func_dict:
                discovered[entry_va] = func_dict
                for call_dest in new_calls:
                    if call_dest not in all_known_entries and self.in_code(call_dest):
                        all_known_entries.add(call_dest)
                        queue.append(call_dest)

            processed += 1
            if processed % 5000 == 0:
                print(
                    f"Catalog discovery progress: {len(discovered)} valid functions "
                    f"({processed} seeds processed, queue: {len(queue)}, {time.time()-t0:.2f}s)"
                )

        print(f"Total discovered functions: {len(discovered)}. Normalizing and validating catalog...")
        raw_catalog = {
            "schema": "nfsu-catalog-bridge-v1",
            "image_base": self.image_base,
            "code_start": self.code_start,
            "code_end": self.code_end,
            "functions": list(discovered.values()),
        }

        normalized = normalize_catalog(raw_catalog)
        return normalized


def generate_catalog_files(
    raw_exe: bytes,
    trampoline_data: dict[str, Any],
    output_catalog_path: Path,
    output_meta_path: Path | None = None,
) -> dict[str, Any]:
    """Build and save catalog.json and metadata."""
    builder = CatalogBuilder(raw_exe, trampoline_data)
    catalog = builder.build_catalog()

    output_catalog_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f)

    summary = {
        "schema": catalog["schema"],
        "total_functions": len(catalog["functions"]),
        "total_basic_blocks": sum(len(f["blocks"]) for f in catalog["functions"]),
        "unresolved_calls": len(catalog["unresolved_calls"]),
        "image_base": hex(catalog["image_base"]),
        "code_bounds": f"{hex(catalog['code_start'])}..{hex(catalog['code_end'])}",
        "catalog_file_size": output_catalog_path.stat().st_size,
    }

    if output_meta_path:
        meta = {
            "summary": summary,
            "image_sha256": EXPECTED_NFS_EXE_SHA256,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        output_meta_path.write_text(json.dumps(meta, indent=2))

    return summary


def main() -> None:
    cfg_path = WORKSPACE / "config" / "local.json"
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Missing config file: {cfg_path}")
    cfg = json.loads(cfg_path.read_text())

    exe_path = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
    if not exe_path.is_file():
        raise FileNotFoundError(f"Missing game executable: {exe_path}")

    raw_exe = exe_path.read_bytes()
    actual_hash = hashlib.sha256(raw_exe).hexdigest()
    if actual_hash != EXPECTED_NFS_EXE_SHA256:
        raise ValueError(f"Hash mismatch: expected {EXPECTED_NFS_EXE_SHA256}, got {actual_hash}")

    t_path = WORKSPACE / "research" / "local" / "phase1" / "securom_trampolines.json"
    if not t_path.is_file():
        raise FileNotFoundError(f"Missing trampoline database: {t_path}")
    t_data = json.loads(t_path.read_text())

    cat_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.json"
    meta_path = WORKSPACE / "research" / "local" / "phase1" / "catalog.metadata.json"

    print(f"Building master function catalog for {exe_path.name}...")
    t0 = time.time()
    summary = generate_catalog_files(raw_exe, t_data, cat_path, meta_path)
    elapsed = time.time() - t0

    print(f"\nCatalog successfully generated in {elapsed:.2f}s:")
    print(json.dumps(summary, indent=2))
    print(f"Catalog saved to: {cat_path}")


if __name__ == "__main__":
    main()
