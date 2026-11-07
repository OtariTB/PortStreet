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
    patch_all_countdown_stubs,
)
from tools.manual_overrides import ADDITIONAL_FUNCTIONS
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

        # Capstone disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

        # Clean countdown stubs across both .text and .securom
        self.cleaned_exe = patch_all_countdown_stubs(raw_exe, cs=self.cs)
        stubs = find_countdown_stubs(text_va, roff, text_bytes, cs=self.cs)
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

        # Trampoline maps: site_va / stub_va -> target_va (with multi-hop resolution)
        self.trampolines = trampoline_data.get("trampolines", [])
        self.securom_bridges = trampoline_data.get("securom_bridges", [])
        raw_map: dict[int, int] = {}
        for t in self.trampolines:
            s_va = int(t["site_va"])
            t_va = int(t["target_va"])
            raw_map[s_va] = t_va
            if "stub_va" in t and int(t["stub_va"]) != t_va:
                raw_map.setdefault(int(t["stub_va"]), t_va)
        for b in self.securom_bridges:
            s_va = int(b["site_va"])
            t_va = int(b["target_va"])
            raw_map.setdefault(s_va, t_va)
            if "stub_va" in b and int(b["stub_va"]) != t_va:
                raw_map.setdefault(int(b["stub_va"]), t_va)

        self.trampoline_map: dict[int, int] = {}
        for s_va in raw_map:
            visited_chain = set()
            cur = s_va
            while cur in raw_map and cur not in visited_chain:
                visited_chain.add(cur)
                cur = raw_map[cur]
            self.trampoline_map[s_va] = cur

    def in_code(self, va: int) -> bool:
        """Check if VA is in valid executable code sections (.text or .securom)."""
        return (self.text_va <= va < self.text_end) or (self.securom_va <= va < self.securom_end)

    def read_code_bytes(self, va: int, count: int = 15) -> bytes:
        """Read instruction bytes from cleaned .text or cleaned .securom."""
        if self.text_va <= va < self.text_end:
            off = va - self.text_va
            return self.cleaned_text[off : off + count]
        if self.securom_va <= va < self.securom_end:
            off = va - self.image_base
            return self.cleaned_exe[off : off + count]
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

        # 5. Trampoline & SecuROM bridge resolved targets + manual overrides
        for t in self.trampolines:
            target = int(t["target_va"])
            target = self.trampoline_map.get(target, target)
            if self.in_code(target):
                seeds.add(target)
        for b in self.securom_bridges:
            target = int(b["target_va"])
            target = self.trampoline_map.get(target, target)
            if self.in_code(target):
                seeds.add(target)
        for va in ADDITIONAL_FUNCTIONS:
            if self.in_code(va):
                seeds.add(va)

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
        max_insns: int = 12000,
    ) -> tuple[dict[str, Any] | None, set[int]]:
        """Disassemble a function, return (function_dict, new_discovered_seeds)."""
        if self.read_code_bytes(entry_va, 4) == b"\x00\x00\x00\x00":
            return None, set()
        queue = deque([entry_va])
        visited_pcs = set()
        insns_by_va = {}
        calls = set()
        tail_seeds = set()
        jumps = set()
        leaders = {entry_va}
        switch_targets: dict[int, list[int]] = {}
        obf_call_cont: dict[int, int] = {}
        obf_jmp_dest: dict[int, int] = {}
        int3_exits: set[int] = set()
        valid = True

        def _push_imm(ins_obj: Any) -> int | None:
            if (
                ins_obj is not None
                and ins_obj.mnemonic == "push"
                and ins_obj.operands
                and ins_obj.operands[0].type == X86_OP_IMM
            ):
                return ins_obj.operands[0].imm & 0xFFFFFFFF
            return None

        while queue:
            curr = queue.popleft()
            if curr in visited_pcs or not self.in_code(curr):
                continue

            pc = curr
            prev_ins = None
            prev2_ins = None
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
                        dest = i.operands[0].imm & 0xFFFFFFFF
                        dest = self.trampoline_map.get(dest, dest)
                        if self.in_code(dest):
                            calls.add(dest)

                # Return instructions (including SecuROM P2 obfuscated call & P3 push-ret jump)
                if m in ("ret", "retf"):
                    if m == "ret" and not i.operands and pc not in leaders:
                        cal_imm = _push_imm(prev_ins)
                        ret_imm = _push_imm(prev2_ins) if (prev_ins is not None and prev_ins.address not in leaders) else None
                        if (
                            cal_imm is not None
                            and ret_imm is not None
                            and self.in_code(ret_imm)
                            and 0 <= (ret_imm - next_pc) <= 64
                        ):
                            # P2: push imm_ret; push imm_callee; ret (followed by 4..16 bytes junk)
                            cal_dest = self.trampoline_map.get(cal_imm, cal_imm)
                            if self.in_code(cal_dest):
                                calls.add(cal_dest)
                            obf_call_cont[pc] = ret_imm
                            leaders.add(ret_imm)
                            queue.append(ret_imm)
                            break
                        if cal_imm is not None and self.in_code(cal_imm):
                            # P3: standalone push imm_target; ret
                            dest = self.trampoline_map.get(cal_imm, cal_imm)
                            jumps.add(dest)
                            obf_jmp_dest[pc] = dest
                            if dest not in known_functions and self.in_code(dest) and abs(dest - entry_va) < 0x8000:
                                leaders.add(dest)
                                queue.append(dest)
                            elif self.in_code(dest):
                                tail_seeds.add(dest)
                            break
                    break

                # Unconditional jumps (including SecuROM P1 obfuscated call & intra-function ff 25)
                if m == "jmp":
                    ret_imm = _push_imm(prev_ins) if pc not in leaders else None
                    if ret_imm is not None and self.in_code(ret_imm) and 0 <= (ret_imm - next_pc) <= 64:
                        # P1: push imm_ret; jmp <callee> (followed by 4..16 bytes junk)
                        if pc in self.trampoline_map:
                            cal_dest = self.trampoline_map[pc]
                            if self.in_code(cal_dest):
                                calls.add(cal_dest)
                        elif i.operands and i.operands[0].type == X86_OP_IMM:
                            raw_cal = i.operands[0].imm & 0xFFFFFFFF
                            cal_dest = self.trampoline_map.get(raw_cal, raw_cal)
                            if self.in_code(cal_dest):
                                calls.add(cal_dest)
                        obf_call_cont[pc] = ret_imm
                        leaders.add(ret_imm)
                        queue.append(ret_imm)
                        break

                    if pc in self.trampoline_map:
                        dest = self.trampoline_map[pc]
                        jumps.add(dest)
                        obf_jmp_dest[pc] = dest
                        if dest not in known_functions and self.in_code(dest) and abs(dest - entry_va) < 0x8000:
                            leaders.add(dest)
                            queue.append(dest)
                        elif self.in_code(dest):
                            tail_seeds.add(dest)
                    elif i.operands and i.operands[0].type == X86_OP_IMM:
                        raw_d = i.operands[0].imm & 0xFFFFFFFF
                        dest = self.trampoline_map.get(raw_d, raw_d)
                        jumps.add(dest)
                        obf_jmp_dest[pc] = dest
                        if dest not in known_functions and self.in_code(dest) and abs(dest - entry_va) < 0x8000:
                            leaders.add(dest)
                            queue.append(dest)
                        elif self.in_code(dest):
                            tail_seeds.add(dest)
                    elif i.operands and i.operands[0].type == X86_OP_MEM:
                        # Switch table: jmp dword ptr [reg*4 + table]
                        mem = i.operands[0].mem
                        if mem.scale == 4 and mem.disp and mem.base == 0 and mem.index != 0 and self.in_code(mem.disp):
                            tbl_va = mem.disp
                            tbl_targets = []
                            for k in range(256):
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
                if m.startswith("j") or m in ("jecxz", "jcxz", "loop", "loope", "loopne", "loopz", "loopnz"):
                    if i.operands and i.operands[0].type == X86_OP_IMM:
                        raw_d = i.operands[0].imm & 0xFFFFFFFF
                        dest = self.trampoline_map.get(raw_d, raw_d)
                        jumps.add(dest)
                        if self.in_code(dest) and abs(dest - entry_va) < 0x8000 and dest not in known_functions:
                            leaders.add(dest)
                            queue.append(dest)
                        elif self.in_code(dest):
                            if dest in known_functions or abs(dest - entry_va) >= 0x8000:
                                tail_seeds.add(dest)
                            else:
                                leaders.add(dest)
                                queue.append(dest)
                    leaders.add(next_pc)
                    queue.append(next_pc)
                    break

                # Consecutive int3 padding
                if m == "int3":
                    if self.read_code_bytes(next_pc, 2) == b"\xcc\xcc":
                        if pc != entry_va:
                            int3_exits.add(pc)
                        break

                if m in ("hlt", "ud2"):
                    break

                if len(insns_by_va) > max_insns:
                    valid = False
                    break

                prev2_ins = prev_ins
                prev_ins = i
                pc = next_pc

        if not valid or not insns_by_va or entry_va not in insns_by_va:
            return None, calls | tail_seeds

        # Ensure function has at least one valid exit, jump, or noreturn call+int3 padding
        has_exit = (
            any(
                i.mnemonic in ("ret", "retf", "hlt", "ud2") and i.address not in obf_call_cont
                for i in insns_by_va.values()
            )
            or any(
                i.mnemonic == "jmp" and i.address not in obf_call_cont
                for i in insns_by_va.values()
            )
            or (
                bool(int3_exits)
                and any(i.mnemonic == "call" or i.address in obf_call_cont for i in insns_by_va.values())
            )
        )
        if not has_exit:
            return None, calls | tail_seeds

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

                if ins.address in obf_call_cont:
                    cont_va = obf_call_cont[ins.address]
                    if cont_va in insns_by_va:
                        succs.append(cont_va)
                    break

                if ins.address in obf_jmp_dest:
                    dest = obf_jmp_dest[ins.address]
                    if dest in insns_by_va:
                        succs.append(dest)
                    break

                if ins.address in switch_targets:
                    succs = sorted(t for t in set(switch_targets[ins.address]) if t in insns_by_va)
                    break

                if m in ("ret", "retf", "hlt", "ud2") or ins.address in int3_exits:
                    is_exit = 1
                    break

                if m == "jmp":
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        raw_d = ins.operands[0].imm & 0xFFFFFFFF
                        dest = self.trampoline_map.get(raw_d, raw_d)
                        if dest in insns_by_va:
                            succs.append(dest)
                    break

                if m.startswith("j") or m in ("jecxz", "jcxz", "loop", "loope", "loopne", "loopz", "loopnz"):
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        raw_d = ins.operands[0].imm & 0xFFFFFFFF
                        dest = self.trampoline_map.get(raw_d, raw_d)
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

        is_thunk = (
            len(blocks) == 1
            and len(insns_by_va) <= 2
            and any(i.mnemonic == "jmp" or i.address in obf_jmp_dest for i in insns_by_va.values())
        )
        func_dict = {
            "address": entry_va,
            "blocks": blocks,
            "entry_kind": "start",
            "is_thunk": is_thunk,
            "calls_to": sorted(calls),
            "jump_targets": sorted(jumps),
        }
        return func_dict, calls | tail_seeds

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

        # Pass 2: Recover uncovered .text IAT thunks and immediate-referenced callbacks/threads
        # (e.g. Render Thread sub_004b0100 pushed as immediate to _beginthreadex in main()).
        if self.text_size >= 0x10000:
            covered_pcs: set[int] = set()
            for fn in discovered.values():
                for bs, be, _, _ in fn["blocks"]:
                    covered_pcs.update(range(bs, be))

            text_limit = min(self.text_end, 0x00966080)
            le_refs: set[int] = set()
            raw_len = len(self.cleaned_exe)
            scan_start = min(va_to_offset(self.text_va), raw_len)
            for i in range(scan_start, max(scan_start, raw_len - 4)):
                v = struct.unpack_from("<I", self.cleaned_exe, i)[0]
                if self.text_va <= v < text_limit:
                    le_refs.add(v)
                b0 = self.cleaned_exe[i]
                if b0 in (0xE8, 0xE9) and i + 5 <= raw_len:
                    rel = struct.unpack_from("<i", self.cleaned_exe, i + 1)[0]
                    t = self.image_base + i + 5 + rel
                    if self.text_va <= t < text_limit:
                        le_refs.add(t)

            pass2_seeds: list[int] = []
            # 2a. Uncovered .text jmp dword ptr [IAT] thunks
            for va in range(self.text_va, text_limit - 6):
                if va in covered_pcs or va in all_known_entries:
                    continue
                b6 = self.read_code_bytes(va, 6)
                if len(b6) == 6 and b6[0] == 0xFF and b6[1] == 0x25:
                    iat_va = struct.unpack_from("<I", b6, 2)[0]
                    if 0x00967000 <= iat_va <= 0x00967660:
                        all_known_entries.add(va)
                        pass2_seeds.append(va)

            # 2b. Uncovered 16-byte aligned or post-0xCC .text functions referenced in image
            for va in sorted(le_refs):
                if va in covered_pcs or va in all_known_entries:
                    continue
                b1 = self.read_code_bytes(va, 1)
                if not b1 or b1[0] in (0x00, 0xCC, 0x90):
                    continue
                prev1 = self.read_code_bytes(va - 1, 1) if va > self.text_va else b"\xCC"
                if (va & 0xF) == 0 or prev1 == b"\xCC":
                    all_known_entries.add(va)
                    pass2_seeds.append(va)

            queue.extend(pass2_seeds)
            while queue:
                entry_va = queue.popleft()
                if entry_va in discovered or entry_va in covered_pcs:
                    continue
                func_dict, new_calls = self.disassemble_function(entry_va, all_known_entries)
                if func_dict:
                    discovered[entry_va] = func_dict
                    for bs, be, _, _ in func_dict["blocks"]:
                        covered_pcs.update(range(bs, be))
                    for call_dest in new_calls:
                        if call_dest not in all_known_entries and self.in_code(call_dest):
                            all_known_entries.add(call_dest)
                            queue.append(call_dest)

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
