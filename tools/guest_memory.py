"""Checked Linear Guest Memory Container and PE Section Loader for NFS ProStreet.

Loads authentic PE sections (.text, .rdata, .data, .tls, .rsrc) from nfs.exe
into a 1:1 linear memory buffer, matching the WebAssembly linear address space:
- 0x00000000..0x00100000: Null-guard protection.
- 0x00100000..0x00200000: TEB & TLS.
- 0x00200000..0x00400000: 2 MB Guest stack.
- 0x00401000..0x00967000: .text (code).
- 0x00967000..0x00a4a000: .rdata (vtables, strings, IAT, initializer tables).
- 0x00a4a000..0x01010000: .data (global variables & zero-initialized BSS).
- 0x01010000..0x01011000: .tls.
- 0x01011000..0x010ea000: .rsrc (34 .fx shaders, resources).
- 0x02000000..0x28000000: Dynamic guest heap (VirtualAlloc arena).
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import struct
from typing import Sequence

IMAGE_BASE = 0x00400000
GUEST_MEMORY_LIMIT = 0x28000000  # 640 MB
HEAP_START = 0x02000000          # 32 MB mark
HEAP_LIMIT = 0x27800000          # Allocator upper bound (632 MB, leaves 8 MB D3D9 reservation)
D3D9_RESERVE_START = 0x27800000
D3D9_RESERVE_END = 0x28000000
STACK_TOP = 0x003FF000           # Initial ESP


class MemoryLoaderError(Exception):
    """Raised on invalid PE section structure or memory violation."""


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    flags: int

    @property
    def end_va(self) -> int:
        return self.virtual_address + self.virtual_size

    @property
    def is_readable(self) -> bool:
        return bool(self.flags & 0x40000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.flags & 0x80000000)

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & 0x20000000)


def parse_pe_sections(raw_exe: bytes) -> tuple[int, tuple[PESection, ...]]:
    """Parse PE image base and section table with strict bounds validation."""
    if len(raw_exe) < 0x40 or raw_exe[:2] != b"MZ":
        raise MemoryLoaderError("Invalid DOS header")
    pe_off = struct.unpack_from("<I", raw_exe, 0x3C)[0]
    if pe_off + 0x18 > len(raw_exe) or raw_exe[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise MemoryLoaderError("Invalid PE header offset or signature")

    machine, num_sections = struct.unpack_from("<HH", raw_exe, pe_off + 4)
    if machine != 0x014C:  # IMAGE_FILE_MACHINE_I386
        raise MemoryLoaderError(f"Unsupported machine architecture: 0x{machine:04x}")
    if num_sections < 1 or num_sections > 96:
        raise MemoryLoaderError(f"Unreasonable section count: {num_sections}")

    opt_hdr_size = struct.unpack_from("<H", raw_exe, pe_off + 20)[0]
    opt_magic = struct.unpack_from("<H", raw_exe, pe_off + 24)[0]
    if opt_magic != 0x010B:  # PE32
        raise MemoryLoaderError(f"Unsupported optional header magic: 0x{opt_magic:04x}")

    image_base = struct.unpack_from("<I", raw_exe, pe_off + 24 + 28)[0]
    sec_table = pe_off + 24 + opt_hdr_size
    if sec_table + num_sections * 40 > len(raw_exe):
        raise MemoryLoaderError("Section table extends beyond file boundary")

    sections: list[PESection] = []
    for i in range(num_sections):
        sec_bytes = raw_exe[sec_table + i * 40 : sec_table + (i + 1) * 40]
        raw_name = sec_bytes[:8].split(b"\x00")[0]
        name = raw_name.decode("latin1", errors="replace")
        vsize, rva, rsize, roff = struct.unpack_from("<4I", sec_bytes, 8)
        flags = struct.unpack_from("<I", sec_bytes, 36)[0]

        va = image_base + rva
        if rsize > 0 and (roff + rsize > len(raw_exe)):
            raise MemoryLoaderError(f"Section {name} raw data extends beyond file bounds")

        sections.append(
            PESection(
                name=name,
                virtual_address=va,
                virtual_size=vsize,
                raw_offset=roff,
                raw_size=rsize,
                flags=flags,
            )
        )

    # Validate non-overlapping virtual address space
    sorted_secs = sorted(sections, key=lambda s: s.virtual_address)
    for a, b in zip(sorted_secs, sorted_secs[1:]):
        if a.end_va > b.virtual_address:
            raise MemoryLoaderError(f"Overlapping sections: {a.name} and {b.name}")

    return image_base, tuple(sections)


class GuestMemory:
    """Checked linear memory container for 32-bit guest x86 execution."""

    def __init__(self, size: int = 64 * 1024 * 1024) -> None:
        if size < 1024 * 1024 or size > GUEST_MEMORY_LIMIT:
            raise MemoryLoaderError(f"Unsupported guest memory size: 0x{size:x}")
        self.size = size
        self.buffer = bytearray(size)
        self.sections: tuple[PESection, ...] = ()
        self.image_base: int = 0
        self.heap_cur: int = HEAP_START

    def ensure_capacity(self, min_capacity: int) -> None:
        if min_capacity > GUEST_MEMORY_LIMIT:
            raise MemoryLoaderError(f"Capacity 0x{min_capacity:08x} exceeds limit 0x{GUEST_MEMORY_LIMIT:08x}")
        if min_capacity > self.size:
            new_size = (min_capacity + 0x00FFFFFF) & ~0x00FFFFFF
            new_size = min(new_size, GUEST_MEMORY_LIMIT)
            self.buffer.extend(b"\x00" * (new_size - self.size))
            self.size = new_size

    def check_bounds(self, va: int, length: int) -> None:
        if va < 0 or va + length > self.size:
            raise MemoryLoaderError(f"Guest access 0x{va:08x}..0x{va+length:08x} exceeds bounds (0..0x{self.size:08x})")

    def load_pe_sections(
        self,
        raw_exe: bytes,
        included_section_names: Sequence[str] | None = None,
    ) -> tuple[PESection, ...]:
        """Loads initialized section data into guest linear memory at authentic VAs, zeroing uninitialized regions."""
        self.image_base, all_sections = parse_pe_sections(raw_exe)
        loaded = []
        for sec in all_sections:
            if included_section_names is None or sec.name in included_section_names:
                # Ensure memory buffer is large enough for this section
                if sec.end_va > self.size:
                    new_size = (sec.end_va + 0x00FFFFFF) & ~0x00FFFFFF
                    if new_size > GUEST_MEMORY_LIMIT:
                        raise MemoryLoaderError(f"Section {sec.name} exceeds guest memory limit 0x{GUEST_MEMORY_LIMIT:08x}")
                    self.buffer.extend(b"\x00" * (new_size - self.size))
                    self.size = new_size

                self.check_bounds(sec.virtual_address, sec.virtual_size)
                # Copy initialized raw data
                init_len = min(sec.raw_size, sec.virtual_size)
                if init_len > 0 and sec.raw_offset > 0:
                    self.buffer[sec.virtual_address : sec.virtual_address + init_len] = raw_exe[
                        sec.raw_offset : sec.raw_offset + init_len
                    ]
                # Zero uninitialized BSS region
                if sec.virtual_size > init_len:
                    self.buffer[sec.virtual_address + init_len : sec.end_va] = b"\x00" * (sec.virtual_size - init_len)
                loaded.append(sec)
        self.sections = tuple(loaded)
        return self.sections

    def read_u8(self, va: int) -> int:
        self.check_bounds(va, 1)
        return self.buffer[va]

    def read_u16(self, va: int) -> int:
        self.check_bounds(va, 2)
        return struct.unpack_from("<H", self.buffer, va)[0]

    def read_u32(self, va: int) -> int:
        self.check_bounds(va, 4)
        return struct.unpack_from("<I", self.buffer, va)[0]

    def read_u64(self, va: int) -> int:
        self.check_bounds(va, 8)
        return struct.unpack_from("<Q", self.buffer, va)[0]

    def read_f32(self, va: int) -> float:
        self.check_bounds(va, 4)
        return struct.unpack_from("<f", self.buffer, va)[0]

    def read_f64(self, va: int) -> float:
        self.check_bounds(va, 8)
        return struct.unpack_from("<d", self.buffer, va)[0]

    def write_u8(self, va: int, val: int) -> None:
        self.check_bounds(va, 1)
        self.buffer[va] = val & 0xFF

    def write_u16(self, va: int, val: int) -> None:
        self.check_bounds(va, 2)
        struct.pack_into("<H", self.buffer, va, val & 0xFFFF)

    def write_u32(self, va: int, val: int) -> None:
        self.check_bounds(va, 4)
        struct.pack_into("<I", self.buffer, va, val & 0xFFFFFFFF)

    def write_u64(self, va: int, val: int) -> None:
        self.check_bounds(va, 8)
        struct.pack_into("<Q", self.buffer, va, val & 0xFFFFFFFFFFFFFFFF)

    def read_bytes(self, va: int, length: int) -> bytes:
        self.check_bounds(va, length)
        return bytes(self.buffer[va : va + length])

    def write_bytes(self, va: int, data: bytes) -> None:
        self.check_bounds(va, len(data))
        self.buffer[va : va + len(data)] = data

    def read_cstring(self, va: int, max_len: int = 1024) -> str:
        parts = []
        for i in range(max_len):
            b = self.read_u8(va + i)
            if b == 0:
                break
            parts.append(b)
        return bytes(parts).decode("latin1", errors="replace")

    def virtual_alloc(self, target_va: int, size: int) -> int:
        aligned_size = (size + 0xFFF) & ~0xFFF
        if target_va == 0:
            self.heap_cur = (self.heap_cur + 0xFFFF) & ~0xFFFF
            target_va = self.heap_cur
            self.heap_cur += aligned_size

        if target_va + aligned_size > HEAP_LIMIT:
            raise MemoryLoaderError("VirtualAlloc exceeded reservation limit")
        if target_va + aligned_size > self.size:
            new_size = (target_va + aligned_size + 0x00FFFFFF) & ~0x00FFFFFF
            if new_size > GUEST_MEMORY_LIMIT:
                raise MemoryLoaderError(f"VirtualAlloc exceeded memory limit 0x{GUEST_MEMORY_LIMIT:08x}")
            self.buffer.extend(b"\x00" * (new_size - self.size))
            self.size = new_size

        self.check_bounds(target_va, aligned_size)
        self.buffer[target_va : target_va + aligned_size] = b"\x00" * aligned_size
        return target_va

    def heap_alloc(self, size: int, alignment: int = 8) -> int:
        if alignment < 1:
            alignment = 8
        self.heap_cur = (self.heap_cur + (alignment - 1)) & ~(alignment - 1)
        va = self.heap_cur
        self.heap_cur += size
        if va + size > HEAP_LIMIT:
            raise MemoryLoaderError("Heap exceeded reservation limit")
        if va + size > self.size:
            new_size = (va + size + 0x00FFFFFF) & ~0x00FFFFFF
            if new_size > GUEST_MEMORY_LIMIT:
                raise MemoryLoaderError(f"Heap allocation exceeded limit 0x{GUEST_MEMORY_LIMIT:08x}")
            self.buffer.extend(b"\x00" * (new_size - self.size))
            self.size = new_size
        return va

