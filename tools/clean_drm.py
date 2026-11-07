"""DRM Countdown Stub Analyzer and Neutralizer for NFS ProStreet.

Scans the original .text section for all SecuROM v7.35 countdown trigger sites:
    dec dword ptr [0x01a6xxxx]   (6 bytes: ff 0d xx xx a6 01)
    je 0x01a6xxxx                (6 bytes: 0f 84 xx xx xx xx)
Replaces them in memory with 12 NOP (0x90) bytes.

The original game binary is opened strictly read-only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Sequence

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXPECTED_NFS_EXE_SHA256 = "ee8a71c7c1e42923deb728e39a89317645cbcf26fc87cc48d3e07ade4dce2f72"
WORKSPACE = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class CountdownStub:
    va: int
    offset_in_text: int
    file_offset: int
    counter_address: int
    jump_target: int
    original_hex: str
    stub_length: int = 12


def parse_text_section(raw_exe: bytes) -> tuple[int, int, int, bytes]:
    """Parse .text section parameters: (image_base, text_va, raw_offset, text_bytes)."""
    if len(raw_exe) < 0x40 or raw_exe[:2] != b"MZ":
        raise ValueError("Invalid DOS header")
    pe_off = struct.unpack_from("<I", raw_exe, 0x3C)[0]
    if raw_exe[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    num_sections = struct.unpack_from("<H", raw_exe, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", raw_exe, pe_off + 20)[0]
    image_base = struct.unpack_from("<I", raw_exe, pe_off + 24 + 28)[0]
    sec_table = pe_off + 24 + opt_hdr_size

    for i in range(num_sections):
        sec = raw_exe[sec_table + i * 40 : sec_table + (i + 1) * 40]
        name = sec[:8].split(b"\x00")[0].decode("latin1")
        if name == ".text":
            vsize, rva, rsize, roff = struct.unpack_from("<4I", sec, 8)
            text_va = image_base + rva
            text_bytes = raw_exe[roff : roff + rsize]
            return image_base, text_va, roff, text_bytes

    raise ValueError(".text section not found in PE image")


def find_countdown_stubs(
    text_va: int,
    text_raw_offset: int,
    text_bytes: bytes,
    cs: Cs | None = None,
) -> list[CountdownStub]:
    """Locate and validate all countdown check stubs using Capstone disassembly."""
    if cs is None:
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

    stubs: list[CountdownStub] = []
    offset = 0
    limit = len(text_bytes) - 12

    while offset <= limit:
        idx = text_bytes.find(b"\xff\x0d", offset)
        if idx == -1 or idx > limit:
            break

        # Check candidate counter address in disp32
        counter_addr = struct.unpack_from("<I", text_bytes, idx + 2)[0]
        if (counter_addr & 0xFFFF0000) == 0x01A60000:
            va = text_va + idx
            chunk = text_bytes[idx : idx + 12]
            insns = list(cs.disasm(chunk, va))

            # Must disassemble as exactly two instructions:
            # 1. dec dword ptr [0x01a6xxxx] (6 bytes)
            # 2. je / jz rel32 (6 bytes)
            if len(insns) == 2:
                i0, i1 = insns
                if (
                    i0.size == 6
                    and i0.mnemonic == "dec"
                    and "0x1a6" in i0.op_str
                    and i1.size == 6
                    and i1.mnemonic in ("je", "jz")
                ):
                    rel = struct.unpack_from("<i", chunk, 8)[0]
                    target = va + 12 + rel
                    stubs.append(
                        CountdownStub(
                            va=va,
                            offset_in_text=idx,
                            file_offset=text_raw_offset + idx,
                            counter_address=counter_addr,
                            jump_target=target,
                            original_hex=chunk.hex(),
                            stub_length=12,
                        )
                    )

        offset = idx + 1

    return stubs


def apply_countdown_nops(text_bytes: bytes, stubs: Sequence[CountdownStub]) -> bytearray:
    """Return a copy of text_bytes with all countdown stubs replaced with 12 NOPs."""
    patched = bytearray(text_bytes)
    nop12 = b"\x90" * 12
    for stub in stubs:
        start = stub.offset_in_text
        end = start + stub.stub_length
        assert patched[start:end] == bytes.fromhex(stub.original_hex), f"Mismatch at 0x{stub.va:08x}"
        patched[start:end] = nop12
    return patched


def patch_all_countdown_stubs(raw_exe: bytes, cs: Cs | None = None) -> bytes:
    """Return a copy of a PE image with countdown stubs NOPped in both .text and .securom.

    Non-PE synthetic test buffers are returned unchanged.
    """
    if len(raw_exe) < 0x40 or raw_exe[:2] != b"MZ":
        return raw_exe
    pe_off = struct.unpack_from("<I", raw_exe, 0x3C)[0]
    if pe_off < 0 or pe_off + 24 > len(raw_exe) or raw_exe[pe_off : pe_off + 4] != b"PE\x00\x00":
        return raw_exe

    num_sections = struct.unpack_from("<H", raw_exe, pe_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", raw_exe, pe_off + 20)[0]
    image_base = struct.unpack_from("<I", raw_exe, pe_off + 24 + 28)[0]
    sec_table = pe_off + 24 + opt_hdr_size
    if sec_table + num_sections * 40 > len(raw_exe):
        return raw_exe

    if cs is None:
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

    patched: bytearray | None = None
    for i in range(num_sections):
        sec = raw_exe[sec_table + i * 40 : sec_table + (i + 1) * 40]
        name = sec[:8].split(b"\x00")[0].decode("latin1")
        if name not in (".text", ".securom"):
            continue
        vsize, rva, rsize, roff = struct.unpack_from("<4I", sec, 8)
        scan_size = min(rsize, len(raw_exe) - roff) if roff < len(raw_exe) else 0
        if scan_size < 12:
            continue
        sec_va = image_base + rva
        sec_bytes = raw_exe[roff : roff + scan_size]
        stubs = find_countdown_stubs(sec_va, roff, sec_bytes, cs=cs)
        if stubs:
            if patched is None:
                patched = bytearray(raw_exe)
            patched[roff : roff + scan_size] = apply_countdown_nops(sec_bytes, stubs)

    return bytes(patched) if patched is not None else raw_exe


def main() -> int:
    cfg_path = WORKSPACE / "config/local.json"
    if not cfg_path.exists():
        raise SystemExit(f"Configuration file not found: {cfg_path}")

    cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
    exe_path = Path(cfg["game_root"]) / "Need For Spped - Pro Street" / "nfs.exe"
    if not exe_path.exists():
        raise SystemExit(f"nfs.exe not found at: {exe_path}")

    # Read strictly read-only
    raw_exe = exe_path.read_bytes()
    sha256 = hashlib.sha256(raw_exe).hexdigest()
    print(f"Reading target executable: {exe_path}")
    print(f"Size: {len(raw_exe):,} bytes, SHA-256: {sha256}")

    image_base, text_va, text_raw_offset, text_bytes = parse_text_section(raw_exe)
    print(f".text VA: 0x{text_va:08x}, Raw Offset: 0x{text_raw_offset:08x}, Size: {len(text_bytes):,} bytes")

    stubs = find_countdown_stubs(text_va, text_raw_offset, text_bytes)
    print(f"Discovered and verified {len(stubs)} DRM countdown stubs.")

    # Generate patched memory copy
    patched_text = apply_countdown_nops(text_bytes, stubs)
    assert len(patched_text) == len(text_bytes)
    print(f"Neutralized {len(stubs)} stubs ({len(stubs) * 12} bytes converted to NOP).")

    # Save research report to local ignored directory
    out_dir = WORKSPACE / "research/local/phase1"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / "drm_countdown_stubs.json"
    report_data = {
        "source": str(exe_path),
        "source_sha256": sha256,
        "is_baseline_binary": (sha256 == EXPECTED_NFS_EXE_SHA256),
        "stub_count": len(stubs),
        "total_nop_bytes": len(stubs) * 12,
        "stubs": [asdict(s) for s in stubs],
    }
    report_file.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    print(f"Report saved to: {report_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

