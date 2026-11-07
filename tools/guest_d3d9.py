"""Direct3D 9 Command Stream & COM Interface Python Model for NFS ProStreet.

Mirrors runtime/d3d9_cmd.h, runtime/d3d9.h, and runtime/d3d9.c, providing
serialization, ring buffer FIFO validation, and IDirect3D9 / IDirect3DDevice9
COM vtable dispatch emulation.
"""
from __future__ import annotations

from dataclasses import dataclass
import enum
import struct
from typing import Any, Dict, List, Optional, Tuple

D3D9_RING_MAGIC = 0x39443344
D3D9_RING_VERSION = 1
D3D9_RING_DEFAULT_CAPACITY = 4 * 1024 * 1024
D3D9_RING_HEADER_SIZE = 64
D3D9_CMD_HEADER_SIZE = 8
D3D_CMD_HEADER_SIZE = 8

# ---------------------------------------------------------------------------
# Direct3D 9 Memory Layout Constants
# ---------------------------------------------------------------------------
D3D9_DIRECT3DCREATE9_IAT_VA = 0x009675BC
D3DX9_D3DXVEC3TRANSFORM_IAT_VA = 0x009675DC
D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA = 0x009675F4
D3D9_METHOD_BASE_VA = 0x00966500
D3D9_DEVICE_METHOD_BASE_VA = 0x00966600

D3D9_VTABLE_VA = 0x27801000
D3D9_INSTANCE_VA = 0x27801080
D3D9_DEVICE_VTABLE_VA = 0x27801100
D3D9_DEVICE_INSTANCE_VA = 0x27801300
D3D9_RING_BUFFER_VA = 0x27810000

D3D_SDK_VERSION = 32

D3D_OK = 0x00000000
D3DERR_NOTAVAILABLE = 0x8876086A
D3DERR_INVALIDCALL = 0x8876086C
E_NOINTERFACE = 0x80004002
E_POINTER = 0x80004003

IID_IUNKNOWN = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
])
IID_IDIRECT3D9 = bytes([
    0xCA, 0xCB, 0xBD, 0x81, 0xD4, 0x64, 0x6D, 0x42,
    0xAE, 0x8D, 0xAD, 0x01, 0x47, 0xF4, 0x27, 0x5C,
])
IID_IDIRECT3DDEVICE9 = bytes([
    0x96, 0x3B, 0x22, 0xD0, 0x7A, 0xBF, 0xFD, 0x43,
    0x92, 0xBD, 0xA4, 0x3B, 0x0D, 0x82, 0xB9, 0xEB,
])


class D3DCommandType(enum.IntEnum):
    NOP = 0
    CLEAR = 1
    BEGIN_SCENE = 2
    END_SCENE = 3
    PRESENT = 4
    SET_RENDER_STATE = 5
    SET_SAMPLER_STATE = 6
    SET_TEXTURE = 7
    SET_TRANSFORM = 8
    SET_VIEWPORT = 9
    SET_STREAM_SOURCE = 10
    SET_INDICES = 11
    DRAW_PRIMITIVE = 12
    DRAW_INDEXED_PRIMITIVE = 13
    CREATE_VERTEX_BUFFER = 14
    CREATE_INDEX_BUFFER = 15
    CREATE_TEXTURE = 16
    UPDATE_TEXTURE = 17
    DESTROY_RESOURCE = 18
    SET_VERTEX_DECLARATION = 19
    SET_VERTEX_SHADER = 20
    SET_PIXEL_SHADER = 21
    SET_VS_CONSTANTS = 22
    SET_PS_CONSTANTS = 23
    SET_SCISSOR_RECT = 24
    UPDATE_VERTEX_BUFFER = 25
    DESTROY_VERTEX_BUFFER = 26
    UPDATE_INDEX_BUFFER = 27
    DESTROY_INDEX_BUFFER = 28
    CREATE_VERTEX_DECLARATION = 29


@dataclass
class D3DRingHeader:
    magic: int = D3D9_RING_MAGIC
    version: int = D3D9_RING_VERSION
    head: int = 0
    tail: int = 0
    capacity: int = 0
    frame_index: int = 0
    dropped_frames: int = 0
    flags: int = 1

    def pack(self) -> bytes:
        return struct.pack(
            "<8I8I",
            self.magic,
            self.version,
            self.head,
            self.tail,
            self.capacity,
            self.frame_index,
            self.dropped_frames,
            self.flags,
            *[0] * 8,
        )

    @classmethod
    def unpack(cls, buf: bytes) -> D3DRingHeader:
        fields = struct.unpack_from("<8I", buf, 0)
        return cls(
            magic=fields[0],
            version=fields[1],
            head=fields[2],
            tail=fields[3],
            capacity=fields[4],
            frame_index=fields[5],
            dropped_frames=fields[6],
            flags=fields[7],
        )


class D3DRingBuffer:
    """Simulates the lock-free shared memory command ring buffer."""

    def __init__(self, capacity: int = 1024 * 1024):
        self.capacity = capacity
        self.total_size = D3D9_RING_HEADER_SIZE + capacity
        self.buf = bytearray(self.total_size)
        self.hdr = D3DRingHeader(capacity=capacity)
        self._write_header()

    def _write_header(self) -> None:
        self.buf[0:D3D9_RING_HEADER_SIZE] = self.hdr.pack()

    def _sync_header(self) -> None:
        self.hdr = D3DRingHeader.unpack(bytes(self.buf[0:D3D9_RING_HEADER_SIZE]))

    @property
    def available_space(self) -> int:
        head = self.hdr.head
        tail = self.hdr.tail
        if head >= tail:
            return self.hdr.capacity - (head - tail) - 1
        return tail - head - 1

    @property
    def pending_bytes(self) -> int:
        head = self.hdr.head
        tail = self.hdr.tail
        if head >= tail:
            return head - tail
        return self.hdr.capacity - (tail - head)

    def write_command(self, cmd_type: D3DCommandType, payload: bytes, flags: int = 0) -> bool:
        aligned_payload_len = (len(payload) + 3) & ~3
        packet_len = D3D9_CMD_HEADER_SIZE + aligned_payload_len

        if self.available_space < packet_len:
            self.hdr.dropped_frames += 1
            self._write_header()
            return False

        header_bytes = struct.pack("<HHI", int(cmd_type), flags, aligned_payload_len)
        packet_bytes = header_bytes + payload + b"\x00" * (aligned_payload_len - len(payload))

        head = self.hdr.head
        capacity = self.hdr.capacity
        data_base = D3D9_RING_HEADER_SIZE

        first_chunk = min(packet_len, capacity - head)
        self.buf[data_base + head : data_base + head + first_chunk] = packet_bytes[:first_chunk]

        if first_chunk < packet_len:
            second_chunk = packet_len - first_chunk
            self.buf[data_base : data_base + second_chunk] = packet_bytes[first_chunk:]
            self.hdr.head = second_chunk
        else:
            self.hdr.head = (head + packet_len) % capacity

        self._write_header()
        return True

    def read_command(self) -> Optional[Tuple[D3DCommandType, int, bytes]]:
        if self.pending_bytes < D3D9_CMD_HEADER_SIZE:
            return None

        tail = self.hdr.tail
        capacity = self.hdr.capacity
        data_base = D3D9_RING_HEADER_SIZE

        if tail + D3D9_CMD_HEADER_SIZE <= capacity:
            hdr_bytes = bytes(self.buf[data_base + tail : data_base + tail + D3D9_CMD_HEADER_SIZE])
        else:
            first = capacity - tail
            hdr_bytes = (
                bytes(self.buf[data_base + tail : data_base + capacity])
                + bytes(self.buf[data_base : data_base + (D3D9_CMD_HEADER_SIZE - first)])
            )

        cmd_raw, flags, payload_len = struct.unpack("<HHI", hdr_bytes)
        packet_len = D3D9_CMD_HEADER_SIZE + payload_len

        if self.pending_bytes < packet_len:
            return None

        payload_start = (tail + D3D9_CMD_HEADER_SIZE) % capacity
        if payload_start + payload_len <= capacity:
            payload = bytes(self.buf[data_base + payload_start : data_base + payload_start + payload_len])
        else:
            first = capacity - payload_start
            payload = (
                bytes(self.buf[data_base + payload_start : data_base + capacity])
                + bytes(self.buf[data_base : data_base + (payload_len - first)])
            )

        self.hdr.tail = (tail + packet_len) % capacity
        self._write_header()
        return D3DCommandType(cmd_raw), flags, payload

    def read_all_commands(self) -> List[Tuple[D3DCommandType, int, bytes]]:
        cmds = []
        while True:
            cmd = self.read_command()
            if cmd is None:
                break
            cmds.append(cmd)
        return cmds


# ---------------------------------------------------------------------------
# Command Payload Encoders & Decoders
# ---------------------------------------------------------------------------

def encode_clear(flags: int, color: int, z: float, stencil: int, count: int = 0) -> bytes:
    return struct.pack("<2If2I", flags, color, z, stencil, count)


def decode_clear(payload: bytes) -> Dict[str, Any]:
    flags, color, z, stencil, count = struct.unpack("<2If2I", payload[:20])
    return {"flags": flags, "color": color, "z": z, "stencil": stencil, "count": count}


def encode_set_render_state(state: int, value: int) -> bytes:
    return struct.pack("<2I", state, value)


def decode_set_render_state(payload: bytes) -> Dict[str, Any]:
    state, value = struct.unpack("<2I", payload[:8])
    return {"state": state, "value": value}


def encode_set_viewport(x: int, y: int, width: int, height: int, min_z: float, max_z: float) -> bytes:
    return struct.pack("<4I2f", x, y, width, height, min_z, max_z)


def decode_set_viewport(payload: bytes) -> Dict[str, Any]:
    x, y, width, height, min_z, max_z = struct.unpack("<4I2f", payload[:24])
    return {"x": x, "y": y, "width": width, "height": height, "min_z": min_z, "max_z": max_z}


def encode_draw_primitive(primitive_type: int, start_vertex: int, primitive_count: int) -> bytes:
    return struct.pack("<3I", primitive_type, start_vertex, primitive_count)


def decode_draw_primitive(payload: bytes) -> Dict[str, Any]:
    pt, sv, pc = struct.unpack("<3I", payload[:12])
    return {"primitive_type": pt, "start_vertex": sv, "primitive_count": pc}


def encode_draw_indexed_primitive(
    primitive_type: int,
    base_vertex_index: int,
    min_vertex_index: int,
    num_vertices: int,
    start_index: int,
    primitive_count: int,
) -> bytes:
    return struct.pack(
        "<Ii4I",
        primitive_type,
        base_vertex_index,
        min_vertex_index,
        num_vertices,
        start_index,
        primitive_count,
    )


def decode_draw_indexed_primitive(payload: bytes) -> Dict[str, Any]:
    pt, bvi, mvi, nv, si, pc = struct.unpack("<Ii4I", payload[:24])
    return {
        "primitive_type": pt,
        "base_vertex_index": bvi,
        "min_vertex_index": mvi,
        "num_vertices": nv,
        "start_index": si,
        "primitive_count": pc,
    }


def encode_present(x: int = 0, y: int = 0, w: int = 0, h: int = 0) -> bytes:
    return struct.pack("<4I", x, y, w, h)


def decode_present(payload: bytes) -> Dict[str, Any]:
    x, y, w, h = struct.unpack("<4I", payload[:16])
    return {"src_rect_x": x, "src_rect_y": y, "src_rect_w": w, "src_rect_h": h}


def encode_create_vertex_buffer(
    buffer_id: int, length: int, usage: int = 0, fvf: int = 0, pool: int = 0
) -> bytes:
    return struct.pack("<5I", buffer_id, length, usage, fvf, pool)


def decode_create_vertex_buffer(payload: bytes) -> Dict[str, Any]:
    buffer_id, length, usage, fvf, pool = struct.unpack("<5I", payload[:20])
    return {
        "buffer_id": buffer_id,
        "length": length,
        "usage": usage,
        "fvf": fvf,
        "pool": pool,
    }


def encode_update_vertex_buffer(buffer_id: int, offset: int, data: bytes) -> bytes:
    return struct.pack("<3I", buffer_id, offset, len(data)) + data


def decode_update_vertex_buffer(payload: bytes) -> Dict[str, Any]:
    buffer_id, offset, size = struct.unpack("<3I", payload[:12])
    data = payload[12 : 12 + size]
    return {
        "buffer_id": buffer_id,
        "offset": offset,
        "size": size,
        "data": data,
    }


def encode_set_stream_source(
    stream_number: int, buffer_id: int, offset: int, stride: int
) -> bytes:
    return struct.pack("<4I", stream_number, buffer_id, offset, stride)


def decode_set_stream_source(payload: bytes) -> Dict[str, Any]:
    stream_number, buffer_id, offset, stride = struct.unpack("<4I", payload[:16])
    return {
        "stream_number": stream_number,
        "buffer_id": buffer_id,
        "offset": offset,
        "stride": stride,
    }


def encode_destroy_vertex_buffer(buffer_id: int) -> bytes:
    return struct.pack("<I", buffer_id)


def decode_destroy_vertex_buffer(payload: bytes) -> Dict[str, Any]:
    (buffer_id,) = struct.unpack("<I", payload[:4])
    return {"buffer_id": buffer_id}


def encode_create_index_buffer(
    buffer_id: int, length: int, usage: int = 0, fmt: int = 101, pool: int = 0
) -> bytes:
    return struct.pack("<5I", buffer_id, length, usage, fmt, pool)


def decode_create_index_buffer(payload: bytes) -> Dict[str, Any]:
    buffer_id, length, usage, fmt, pool = struct.unpack("<5I", payload[:20])
    return {
        "buffer_id": buffer_id,
        "length": length,
        "usage": usage,
        "format": fmt,
        "pool": pool,
    }


def encode_update_index_buffer(buffer_id: int, offset: int, data: bytes) -> bytes:
    return struct.pack("<3I", buffer_id, offset, len(data)) + data


def decode_update_index_buffer(payload: bytes) -> Dict[str, Any]:
    buffer_id, offset, size = struct.unpack("<3I", payload[:12])
    data = payload[12 : 12 + size]
    return {
        "buffer_id": buffer_id,
        "offset": offset,
        "size": size,
        "data": data,
    }


def encode_set_indices(buffer_id: int) -> bytes:
    return struct.pack("<I", buffer_id)


def decode_set_indices(payload: bytes) -> Dict[str, Any]:
    (buffer_id,) = struct.unpack("<I", payload[:4])
    return {"buffer_id": buffer_id}


def encode_destroy_index_buffer(buffer_id: int) -> bytes:
    return struct.pack("<I", buffer_id)


def decode_destroy_index_buffer(payload: bytes) -> Dict[str, Any]:
    (buffer_id,) = struct.unpack("<I", payload[:4])
    return {"buffer_id": buffer_id}


def encode_create_vertex_declaration(
    decl_id: int, elements: List[Tuple[int, int, int, int, int, int]]
) -> bytes:
    out = [struct.pack("<2I", decl_id, len(elements))]
    for stream, offset, dtype, method, usage, usage_index in elements:
        out.append(struct.pack("<2H4B", stream, offset, dtype, method, usage, usage_index))
    return b"".join(out)


def decode_create_vertex_declaration(payload: bytes) -> Dict[str, Any]:
    decl_id, count = struct.unpack("<2I", payload[:8])
    elements = []
    for i in range(count):
        base = 8 + i * 8
        stream, offset, dtype, method, usage, usage_index = struct.unpack(
            "<2H4B", payload[base : base + 8]
        )
        elements.append(
            {
                "stream": stream,
                "offset": offset,
                "type": dtype,
                "method": method,
                "usage": usage,
                "usage_index": usage_index,
            }
        )
    return {"decl_id": decl_id, "element_count": count, "elements": elements}


def encode_set_vertex_declaration(decl_id: int) -> bytes:
    return struct.pack("<I", decl_id)


def decode_set_vertex_declaration(payload: bytes) -> Dict[str, Any]:
    (decl_id,) = struct.unpack("<I", payload[:4])
    return {"decl_id": decl_id}


def encode_create_texture(
    texture_id: int,
    width: int,
    height: int,
    levels: int = 1,
    usage: int = 0,
    fmt: int = 21,
    pool: int = 0,
) -> bytes:
    return struct.pack("<7I", texture_id, width, height, levels, usage, fmt, pool)


def decode_create_texture(payload: bytes) -> Dict[str, Any]:
    texture_id, width, height, levels, usage, fmt, pool = struct.unpack("<7I", payload[:28])
    return {
        "texture_id": texture_id,
        "width": width,
        "height": height,
        "levels": levels,
        "usage": usage,
        "format": fmt,
        "pool": pool,
    }


def encode_update_texture(
    texture_id: int,
    level: int,
    pitch: int,
    width: int,
    height: int,
    data: bytes,
) -> bytes:
    return struct.pack("<6I", texture_id, level, pitch, len(data), width, height) + data


def decode_update_texture(payload: bytes) -> Dict[str, Any]:
    texture_id, level, pitch, data_bytes, width, height = struct.unpack("<6I", payload[:24])
    data = payload[24 : 24 + data_bytes]
    return {
        "texture_id": texture_id,
        "level": level,
        "pitch": pitch,
        "data_bytes": data_bytes,
        "width": width,
        "height": height,
        "data": data,
    }


def encode_set_texture(stage: int, texture_id: int) -> bytes:
    return struct.pack("<2I", stage, texture_id)


def decode_set_texture(payload: bytes) -> Dict[str, Any]:
    stage, texture_id = struct.unpack("<2I", payload[:8])
    return {"stage": stage, "texture_id": texture_id}


def encode_set_sampler_state(sampler: int, stype: int, value: int) -> bytes:
    return struct.pack("<3I", sampler, stype, value)


def decode_set_sampler_state(payload: bytes) -> Dict[str, Any]:
    sampler, stype, value = struct.unpack("<3I", payload[:12])
    return {"sampler": sampler, "type": stype, "value": value}


# ---------------------------------------------------------------------------
# Method Names Lists
# ---------------------------------------------------------------------------
D3D9_METHODS: List[str] = [
    "QueryInterface",
    "AddRef",
    "Release",
    "RegisterSoftwareDevice",
    "GetAdapterCount",
    "GetAdapterIdentifier",
    "GetAdapterModeCount",
    "EnumAdapterModes",
    "GetAdapterDisplayMode",
    "CheckDeviceType",
    "CheckDeviceFormat",
    "CheckDeviceMultiSampleType",
    "CheckDepthStencilMatch",
    "CheckDeviceFormatConversion",
    "GetDeviceCaps",
    "GetAdapterMonitor",
    "CreateDevice",
]

D3D9_DEVICE_METHODS: List[str] = [
    "QueryInterface",
    "AddRef",
    "Release",
    "TestCooperativeLevel",
    "GetAvailableTextureMem",
    "EvictManagedResources",
    "GetDirect3D",
    "GetDeviceCaps",
    "GetDisplayMode",
    "GetCreationParameters",
    "SetCursorProperties",
    "SetCursorPosition",
    "ShowCursor",
    "CreateAdditionalSwapChain",
    "GetSwapChain",
    "GetNumberOfSwapChains",
    "Reset",
    "Present",
    "GetBackBuffer",
    "GetRasterStatus",
    "SetDialogBoxMode",
    "SetGammaRamp",
    "GetGammaRamp",
    "CreateTexture",
    "CreateVolumeTexture",
    "CreateCubeTexture",
    "CreateVertexBuffer",
    "CreateIndexBuffer",
    "CreateRenderTarget",
    "CreateDepthStencilSurface",
    "UpdateSurface",
    "UpdateTexture",
    "GetRenderTargetData",
    "GetFrontBufferData",
    "StretchRect",
    "ColorFill",
    "CreateOffscreenPlainSurface",
    "SetRenderTarget",
    "GetRenderTarget",
    "SetDepthStencilSurface",
    "GetDepthStencilSurface",
    "BeginScene",
    "EndScene",
    "Clear",
    "SetTransform",
    "GetTransform",
    "MultiplyTransform",
    "SetViewport",
    "GetViewport",
    "SetMaterial",
    "GetMaterial",
    "SetLight",
    "GetLight",
    "LightEnable",
    "GetLightEnable",
    "SetClipPlane",
    "GetClipPlane",
    "SetRenderState",
    "GetRenderState",
    "CreateStateBlock",
    "BeginStateBlock",
    "EndStateBlock",
    "SetClipStatus",
    "GetClipStatus",
    "GetTexture",
    "SetTexture",
    "GetTextureStageState",
    "SetTextureStageState",
    "GetSamplerState",
    "SetSamplerState",
    "ValidateDevice",
    "SetPaletteEntries",
    "GetPaletteEntries",
    "SetCurrentTexturePalette",
    "GetCurrentTexturePalette",
    "SetScissorRect",
    "GetScissorRect",
    "SetSoftwareVertexProcessing",
    "GetSoftwareVertexProcessing",
    "SetNPatchMode",
    "GetNPatchMode",
    "DrawPrimitive",
    "DrawIndexedPrimitive",
    "DrawPrimitiveUP",
    "DrawIndexedPrimitiveUP",
    "ProcessVertices",
    "CreateVertexDeclaration",
    "SetVertexDeclaration",
    "GetVertexDeclaration",
    "SetFVF",
    "GetFVF",
    "CreateVertexShader",
    "SetVertexShader",
    "GetVertexShader",
    "SetVertexShaderConstantF",
    "GetVertexShaderConstantF",
    "SetVertexShaderConstantI",
    "GetVertexShaderConstantI",
    "SetVertexShaderConstantB",
    "GetVertexShaderConstantB",
    "SetStreamSource",
    "GetStreamSource",
    "SetStreamSourceFreq",
    "GetStreamSourceFreq",
    "SetIndices",
    "GetIndices",
    "CreatePixelShader",
    "SetPixelShader",
    "GetPixelShader",
    "SetPixelShaderConstantF",
    "GetPixelShaderConstantF",
    "SetPixelShaderConstantI",
    "GetPixelShaderConstantI",
    "SetPixelShaderConstantB",
    "GetPixelShaderConstantB",
    "DrawRectPatch",
    "DrawTriPatch",
    "DeletePatch",
    "CreateQuery",
]


# ---------------------------------------------------------------------------
# Python Simulation Model for Direct3D 9
# ---------------------------------------------------------------------------
class GuestD3D9:
    """Python emulation model for Direct3D 9 and Direct3DDevice9 COM interfaces."""

    def __init__(self, memory: Any):
        self.mem = memory
        self.ref_count = 0
        self.active = False
        self.device_ref_count = 0
        self.device_active = False
        self.dtab: Dict[int, Any] = {}
        self.ring = D3DRingBuffer(capacity=D3D9_RING_DEFAULT_CAPACITY)

        self.next_resource_id = 1
        self.bound_stream0_stride = 0
        self.bound_stream0_buf = 0
        self.bound_indices_id = 0
        self.render_states: Dict[int, int] = {}
        self.textures: Dict[int, int] = {}
        self.viewport = (0, 0, 1280, 720, 0.0, 1.0)

    def init_iat(self) -> None:
        """Binds Direct3DCreate9, D3DXMatrixTranspose, IDirect3D9, and IDirect3DDevice9 into guest memory and dtab."""
        if hasattr(self.mem, "ensure_capacity"):
            self.mem.ensure_capacity(0x28000000)
        # 1. Bind Direct3DCreate9, D3DXVec3Transform, and D3DXMatrixTranspose IAT slots in .rdata
        self.mem.write_u32(D3D9_DIRECT3DCREATE9_IAT_VA, D3D9_DIRECT3DCREATE9_IAT_VA)
        self.dtab[D3D9_DIRECT3DCREATE9_IAT_VA] = self.shim_Direct3DCreate9
        self.mem.write_u32(D3DX9_D3DXVEC3TRANSFORM_IAT_VA, D3DX9_D3DXVEC3TRANSFORM_IAT_VA)
        self.dtab[D3DX9_D3DXVEC3TRANSFORM_IAT_VA] = self.shim_D3DXVec3Transform
        self.mem.write_u32(D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA, D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA)
        self.dtab[D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA] = self.shim_D3DXMatrixTranspose

        # 2. Setup IDirect3D9 Vtable at 0x02001000 in heap
        for i in range(len(D3D9_METHODS)):
            m_va = D3D9_METHOD_BASE_VA + i * 4
            self.mem.write_u32(D3D9_VTABLE_VA + i * 4, m_va)

        # 3. Setup IDirect3D9 instance at 0x02001080 in heap
        self.mem.write_u32(D3D9_INSTANCE_VA, D3D9_VTABLE_VA)
        self.mem.write_u32(D3D9_INSTANCE_VA + 4, 1)

        # 4. Setup IDirect3DDevice9 Vtable at 0x02001100 in heap
        for i in range(len(D3D9_DEVICE_METHODS)):
            m_va = D3D9_DEVICE_METHOD_BASE_VA + i * 4
            self.mem.write_u32(D3D9_DEVICE_VTABLE_VA + i * 4, m_va)

        # 5. Setup IDirect3DDevice9 instance at 0x02001300 in heap
        self.mem.write_u32(D3D9_DEVICE_INSTANCE_VA, D3D9_DEVICE_VTABLE_VA)
        self.mem.write_u32(D3D9_DEVICE_INSTANCE_VA + 4, 0)

        # 6. Bind all 17 IDirect3D9 methods into dtab
        for i, name in enumerate(D3D9_METHODS):
            m_va = D3D9_METHOD_BASE_VA + i * 4
            self.dtab[m_va] = getattr(self, f"shim_{name}")

        # 7. Bind all 119 IDirect3DDevice9 methods into dtab
        for i, name in enumerate(D3D9_DEVICE_METHODS):
            m_va = D3D9_DEVICE_METHOD_BASE_VA + i * 4
            self.dtab[m_va] = getattr(self, f"dev_shim_{name}")

        self.ref_count = 1
        self.active = True

    # --- IDirect3D9 Shims ---

    def shim_Direct3DCreate9(self, c: Any) -> None:
        sdk_version = self.mem.read_u32(c.esp)
        c.esp += 4
        if sdk_version < 31 or sdk_version > 32:
            c.eax = 0
            return

        self.ref_count = 1
        self.active = True
        self.mem.write_u32(D3D9_INSTANCE_VA, D3D9_VTABLE_VA)
        self.mem.write_u32(D3D9_INSTANCE_VA + 4, self.ref_count)
        c.eax = D3D9_INSTANCE_VA

    def shim_D3DXVec3Transform(self, c: Any) -> None:
        p_out = self.mem.read_u32(c.esp)
        p_v = self.mem.read_u32(c.esp + 4)
        p_m = self.mem.read_u32(c.esp + 8)
        c.esp += 12

        if p_out == 0 or p_v == 0 or p_m == 0:
            c.eax = 0
            return

        # Check bounds: must fall within valid guest memory (above null guard 0x00100000, within heap limit 0x28000000)
        if (p_out < 0x00100000 or p_out + 16 > 0x28000000 or
            p_v < 0x00100000 or p_v + 12 > 0x28000000 or
            p_m < 0x00100000 or p_m + 64 > 0x28000000):
            c.eax = 0
            return

        def read_f(addr: int) -> float:
            return struct.unpack('<f', struct.pack('<I', self.mem.read_u32(addr)))[0]

        def write_f(addr: int, val: float) -> None:
            self.mem.write_u32(addr, struct.unpack('<I', struct.pack('<f', val))[0])

        # Read inputs into local variables before writing to safely handle overlap (p_out == p_v)
        vx = read_f(p_v + 0)
        vy = read_f(p_v + 4)
        vz = read_f(p_v + 8)

        # Row-vector multiplication: [x, y, z, 1] * M
        rx = vx * read_f(p_m + 0)  + vy * read_f(p_m + 16) + vz * read_f(p_m + 32) + read_f(p_m + 48)
        ry = vx * read_f(p_m + 4)  + vy * read_f(p_m + 20) + vz * read_f(p_m + 36) + read_f(p_m + 52)
        rz = vx * read_f(p_m + 8)  + vy * read_f(p_m + 24) + vz * read_f(p_m + 40) + read_f(p_m + 56)
        rw = vx * read_f(p_m + 12) + vy * read_f(p_m + 28) + vz * read_f(p_m + 44) + read_f(p_m + 60)

        write_f(p_out + 0, rx)
        write_f(p_out + 4, ry)
        write_f(p_out + 8, rz)
        write_f(p_out + 12, rw)

        c.eax = p_out

    def shim_D3DXMatrixTranspose(self, c: Any) -> None:
        p_out = self.mem.read_u32(c.esp)
        p_m = self.mem.read_u32(c.esp + 4)
        c.esp += 8

        if p_out == 0 or p_m == 0:
            c.eax = 0
            return

        # Check bounds: must fall within valid guest memory (above null guard 0x00100000, within heap limit 0x28000000)
        if p_out < 0x00100000 or p_out + 64 > 0x28000000 or p_m < 0x00100000 or p_m + 64 > 0x28000000:
            c.eax = 0
            return

        # Copy 16 32-bit floats (64 bytes) to safely handle in-place transposition (p_out == p_m)
        temp = [self.mem.read_u32(p_m + i * 4) for i in range(16)]
        for r in range(4):
            for col in range(4):
                self.mem.write_u32(p_out + (r * 4 + col) * 4, temp[col * 4 + r])

        c.eax = p_out

    def shim_QueryInterface(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        p_riid = self.mem.read_u32(c.esp + 4)
        ppv_obj = self.mem.read_u32(c.esp + 8)
        c.esp += 12

        if ppv_obj == 0:
            c.eax = E_POINTER
            return

        riid_bytes = self.mem.read_bytes(p_riid, 16) if p_riid != 0 else b""
        if riid_bytes in (IID_IUNKNOWN, IID_IDIRECT3D9):
            self.mem.write_u32(ppv_obj, p_this)
            self.ref_count += 1
            self.mem.write_u32(p_this + 4, self.ref_count)
            c.eax = D3D_OK
        else:
            self.mem.write_u32(ppv_obj, 0)
            c.eax = E_NOINTERFACE

    def shim_AddRef(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        c.esp += 4
        self.ref_count += 1
        if p_this != 0:
            self.mem.write_u32(p_this + 4, self.ref_count)
        c.eax = self.ref_count

    def shim_Release(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        c.esp += 4
        if self.ref_count > 0:
            self.ref_count -= 1
        if self.ref_count == 0:
            self.active = False
        if p_this != 0:
            self.mem.write_u32(p_this + 4, self.ref_count)
        c.eax = self.ref_count

    def shim_RegisterSoftwareDevice(self, c: Any) -> None:
        c.esp += 8
        c.eax = D3DERR_NOTAVAILABLE

    def shim_GetAdapterCount(self, c: Any) -> None:
        c.esp += 4
        c.eax = 1

    def shim_GetAdapterIdentifier(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        flags = self.mem.read_u32(c.esp + 8)
        p_id = self.mem.read_u32(c.esp + 12)
        c.esp += 16

        if adapter != 0 or p_id == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        # Authentic 1,100-byte D3DADAPTER_IDENTIFIER9 structure
        self.mem.write_bytes(p_id, b"\x00" * 1100)
        self.mem.write_bytes(p_id, b"d3d9.dll\x00")
        self.mem.write_bytes(p_id + 512, b"PortSpeed WebGPU / WebGL2 D3D9 Adapter\x00")
        self.mem.write_bytes(p_id + 1024, b"\\\\.\\DISPLAY1\x00")
        self.mem.write_u32(p_id + 1056, 0)
        self.mem.write_u32(p_id + 1060, 0x00010000)
        self.mem.write_u32(p_id + 1064, 0x10DE)  # VendorId = NVIDIA
        self.mem.write_u32(p_id + 1068, 0x0402)  # DeviceId
        self.mem.write_u32(p_id + 1072, 0)       # SubSysId
        self.mem.write_u32(p_id + 1076, 0)       # Revision

        # DeviceIdentifier GUID at offset 1080 (16 bytes)
        dev_guid = bytes([
            0x3E, 0x1E, 0xB7, 0xD7, 0x42, 0x47, 0xCF, 0x11,
            0x82, 0x6E, 0x01, 0x20, 0x02, 0xC2, 0xCB, 0x35
        ])
        self.mem.write_bytes(p_id + 1080, dev_guid)
        self.mem.write_u32(p_id + 1096, 0)       # WHQLLevel

        c.eax = D3D_OK

    def shim_GetAdapterModeCount(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        fmt = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        c.eax = 4 if (adapter == 0 and fmt in (21, 22)) else 0

    def shim_EnumAdapterModes(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        fmt = self.mem.read_u32(c.esp + 8)
        mode = self.mem.read_u32(c.esp + 12)
        p_mode = self.mem.read_u32(c.esp + 16)
        c.esp += 20

        modes = [(800, 600), (1024, 768), (1280, 720), (1920, 1080)]
        if adapter != 0 or p_mode == 0 or mode >= len(modes):
            c.eax = D3DERR_INVALIDCALL
            return

        w, h = modes[mode]
        self.mem.write_u32(p_mode + 0, w)
        self.mem.write_u32(p_mode + 4, h)
        self.mem.write_u32(p_mode + 8, 60)
        self.mem.write_u32(p_mode + 12, fmt)
        c.eax = D3D_OK

    def shim_GetAdapterDisplayMode(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        p_mode = self.mem.read_u32(c.esp + 8)
        c.esp += 12

        if adapter != 0 or p_mode == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        self.mem.write_u32(p_mode + 0, 1280)
        self.mem.write_u32(p_mode + 4, 720)
        self.mem.write_u32(p_mode + 8, 60)
        self.mem.write_u32(p_mode + 12, 22)
        c.eax = D3D_OK

    def shim_CheckDeviceType(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        dev_type = self.mem.read_u32(c.esp + 8)
        c.esp += 24
        c.eax = D3D_OK if (adapter == 0 and dev_type in (1, 2)) else D3DERR_NOTAVAILABLE

    def shim_CheckDeviceFormat(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        check_format = self.mem.read_u32(c.esp + 24)
        c.esp += 28
        supported = {
            20, 21, 22, 23, 75, 77, 80, 101, 102,
            0x31545844, 0x32545844, 0x33545844, 0x34545844, 0x35545844,
        }
        c.eax = D3D_OK if (adapter == 0 and check_format in supported) else D3DERR_NOTAVAILABLE

    def shim_CheckDeviceMultiSampleType(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        ms_type = self.mem.read_u32(c.esp + 20)
        p_quality = self.mem.read_u32(c.esp + 24)
        c.esp += 28

        if adapter == 0 and ms_type == 0:
            if p_quality != 0:
                self.mem.write_u32(p_quality, 1)
            c.eax = D3D_OK
        else:
            if p_quality != 0:
                self.mem.write_u32(p_quality, 0)
            c.eax = D3DERR_NOTAVAILABLE

    def shim_CheckDepthStencilMatch(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        c.esp += 24
        c.eax = D3D_OK if adapter == 0 else D3DERR_NOTAVAILABLE

    def shim_CheckDeviceFormatConversion(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        src_fmt = self.mem.read_u32(c.esp + 12)
        dst_fmt = self.mem.read_u32(c.esp + 16)
        c.esp += 20
        c.eax = D3D_OK if (adapter == 0 and src_fmt == dst_fmt) else D3DERR_NOTAVAILABLE

    def shim_GetDeviceCaps(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        p_caps = self.mem.read_u32(c.esp + 12)
        c.esp += 16

        if adapter != 0 or p_caps == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        self.mem.write_bytes(p_caps, b"\x00" * 304)
        self.mem.write_u32(p_caps + 0, 1)
        self.mem.write_u32(p_caps + 8, 0x00020000)
        self.mem.write_u32(p_caps + 12, 0xE0020000)
        self.mem.write_u32(p_caps + 24, 0x001BBE50)
        self.mem.write_u32(p_caps + 72, 4096)
        self.mem.write_u32(p_caps + 76, 4096)
        self.mem.write_u32(p_caps + 216, 0xFFFE0300)
        self.mem.write_u32(p_caps + 224, 0xFFFF0300)
        c.eax = D3D_OK

    def shim_GetAdapterMonitor(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        c.eax = 0x00010001 if adapter == 0 else 0

    def shim_CreateDevice(self, c: Any) -> None:
        adapter = self.mem.read_u32(c.esp + 4)
        devtype = self.mem.read_u32(c.esp + 8)
        p_pp = self.mem.read_u32(c.esp + 20)
        pp_device = self.mem.read_u32(c.esp + 24)
        c.esp += 28

        if adapter != 0 or p_pp == 0 or pp_device == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        if devtype not in (1, 2):
            c.eax = D3DERR_NOTAVAILABLE
            return

        self.device_ref_count = 1
        self.device_active = True

        self.mem.write_u32(D3D9_DEVICE_INSTANCE_VA, D3D9_DEVICE_VTABLE_VA)
        self.mem.write_u32(D3D9_DEVICE_INSTANCE_VA + 4, self.device_ref_count)
        self.mem.write_u32(pp_device, D3D9_DEVICE_INSTANCE_VA)

        # Set initial viewport
        w = self.mem.read_u32(p_pp + 0) or 1280
        h = self.mem.read_u32(p_pp + 4) or 720
        self.viewport = (0, 0, w, h, 0.0, 1.0)
        self.ring.write_command(D3DCommandType.SET_VIEWPORT, encode_set_viewport(*self.viewport))
        self.mem.write_bytes(D3D9_RING_BUFFER_VA, self.ring.hdr.pack())

        c.eax = D3D_OK

    # --- IDirect3DDevice9 Shims (119 methods) ---

    def dev_shim_QueryInterface(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        p_riid = self.mem.read_u32(c.esp + 4)
        ppv_obj = self.mem.read_u32(c.esp + 8)
        c.esp += 12

        if ppv_obj == 0:
            c.eax = E_POINTER
            return

        riid_bytes = self.mem.read_bytes(p_riid, 16) if p_riid != 0 else b""
        if riid_bytes in (IID_IUNKNOWN, IID_IDIRECT3DDEVICE9):
            self.mem.write_u32(ppv_obj, p_this)
            self.device_ref_count += 1
            self.mem.write_u32(p_this + 4, self.device_ref_count)
            c.eax = D3D_OK
        else:
            self.mem.write_u32(ppv_obj, 0)
            c.eax = E_NOINTERFACE

    def dev_shim_AddRef(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        c.esp += 4
        self.device_ref_count += 1
        if p_this != 0:
            self.mem.write_u32(p_this + 4, self.device_ref_count)
        c.eax = self.device_ref_count

    def dev_shim_Release(self, c: Any) -> None:
        p_this = self.mem.read_u32(c.esp)
        c.esp += 4
        if self.device_ref_count > 0:
            self.device_ref_count -= 1
        if self.device_ref_count == 0:
            self.device_active = False
        if p_this != 0:
            self.mem.write_u32(p_this + 4, self.device_ref_count)
        c.eax = self.device_ref_count

    def dev_shim_TestCooperativeLevel(self, c: Any) -> None:
        c.esp += 4
        c.eax = D3D_OK

    def dev_shim_GetAvailableTextureMem(self, c: Any) -> None:
        c.esp += 4
        c.eax = 512 * 1024 * 1024

    def dev_shim_EvictManagedResources(self, c: Any) -> None:
        c.esp += 4
        c.eax = D3D_OK

    def dev_shim_GetDirect3D(self, c: Any) -> None:
        pp_d3d = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if pp_d3d != 0:
            self.mem.write_u32(pp_d3d, D3D9_INSTANCE_VA)
            self.ref_count += 1
            self.mem.write_u32(D3D9_INSTANCE_VA + 4, self.ref_count)
        c.eax = D3D_OK

    def dev_shim_GetDeviceCaps(self, c: Any) -> None:
        p_caps = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_caps != 0:
            self.mem.write_bytes(p_caps, b"\x00" * 304)
            self.mem.write_u32(p_caps + 0, 1)
            self.mem.write_u32(p_caps + 8, 0x00020000)
            self.mem.write_u32(p_caps + 12, 0xE0020000)
            self.mem.write_u32(p_caps + 24, 0x001BBE50)
            self.mem.write_u32(p_caps + 72, 4096)
            self.mem.write_u32(p_caps + 76, 4096)
            self.mem.write_u32(p_caps + 216, 0xFFFE0300)
            self.mem.write_u32(p_caps + 224, 0xFFFF0300)
        c.eax = D3D_OK

    def dev_shim_GetDisplayMode(self, c: Any) -> None:
        p_mode = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if p_mode != 0:
            self.mem.write_u32(p_mode + 0, 1280)
            self.mem.write_u32(p_mode + 4, 720)
            self.mem.write_u32(p_mode + 8, 60)
            self.mem.write_u32(p_mode + 12, 22)
        c.eax = D3D_OK

    def dev_shim_GetCreationParameters(self, c: Any) -> None:
        p_params = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_params != 0:
            self.mem.write_u32(p_params + 0, 0)
            self.mem.write_u32(p_params + 4, 1)
            self.mem.write_u32(p_params + 8, 0x00010001)
            self.mem.write_u32(p_params + 12, 0x00000040)
        c.eax = D3D_OK

    def dev_shim_SetCursorProperties(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetCursorPosition(self, c: Any) -> None: c.esp += 16
    def dev_shim_ShowCursor(self, c: Any) -> None: c.esp += 8; c.eax = 1
    def dev_shim_CreateAdditionalSwapChain(self, c: Any) -> None: c.esp += 12; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_GetSwapChain(self, c: Any) -> None: c.esp += 12; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_GetNumberOfSwapChains(self, c: Any) -> None: c.esp += 4; c.eax = 1

    def dev_shim_Reset(self, c: Any) -> None:
        p_pp = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_pp != 0:
            w = self.mem.read_u32(p_pp + 0) or 1280
            h = self.mem.read_u32(p_pp + 4) or 720
            self.viewport = (0, 0, w, h, 0.0, 1.0)
            self.ring.write_command(D3DCommandType.SET_VIEWPORT, encode_set_viewport(*self.viewport))
        c.eax = D3D_OK

    def dev_shim_Present(self, c: Any) -> None:
        p_src = self.mem.read_u32(c.esp + 4)
        c.esp += 20
        w = self.viewport[2]
        h = self.viewport[3]
        if p_src != 0:
            w = self.mem.read_u32(p_src + 8) or w
            h = self.mem.read_u32(p_src + 12) or h
        self.ring.write_command(D3DCommandType.PRESENT, encode_present(0, 0, w, h))
        self.ring.hdr.frame_index += 1
        c.eax = D3D_OK

    def dev_shim_GetBackBuffer(self, c: Any) -> None:
        pp_back = self.mem.read_u32(c.esp + 16)
        c.esp += 20
        if pp_back != 0:
            self.mem.write_u32(pp_back, 0x27804000)
        c.eax = D3D_OK

    def dev_shim_GetRasterStatus(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_SetDialogBoxMode(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetGammaRamp(self, c: Any) -> None: c.esp += 16
    def dev_shim_GetGammaRamp(self, c: Any) -> None: c.esp += 12

    def dev_shim_CreateTexture(self, c: Any) -> None:
        w = self.mem.read_u32(c.esp + 4)
        h = self.mem.read_u32(c.esp + 8)
        levels = self.mem.read_u32(c.esp + 12)
        usage = self.mem.read_u32(c.esp + 16)
        fmt = self.mem.read_u32(c.esp + 20)
        pool = self.mem.read_u32(c.esp + 24)
        pp_tex = self.mem.read_u32(c.esp + 28)
        c.esp += 36

        if pp_tex == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        tex_id = self.next_resource_id
        self.next_resource_id += 1
        handle = 0x27805000 + (tex_id * 32)
        self.mem.write_u32(pp_tex, handle)

        payload = struct.pack("<7I", tex_id, w, h, levels, usage, fmt, pool)
        self.ring.write_command(D3DCommandType.CREATE_TEXTURE, payload)
        c.eax = D3D_OK

    def dev_shim_CreateVolumeTexture(self, c: Any) -> None: c.esp += 40; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_CreateCubeTexture(self, c: Any) -> None: c.esp += 32; c.eax = D3DERR_NOTAVAILABLE

    def dev_shim_CreateVertexBuffer(self, c: Any) -> None:
        length = self.mem.read_u32(c.esp + 4)
        usage = self.mem.read_u32(c.esp + 8)
        fvf = self.mem.read_u32(c.esp + 12)
        pool = self.mem.read_u32(c.esp + 16)
        pp_vb = self.mem.read_u32(c.esp + 20)
        c.esp += 28

        if pp_vb == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        buf_id = self.next_resource_id
        self.next_resource_id += 1
        handle = 0x27802000 + (buf_id * 32)
        self.mem.write_u32(pp_vb, handle)

        payload = struct.pack("<5I", buf_id, length, usage, fvf, pool)
        self.ring.write_command(D3DCommandType.CREATE_VERTEX_BUFFER, payload)
        c.eax = D3D_OK

    def dev_shim_CreateIndexBuffer(self, c: Any) -> None:
        length = self.mem.read_u32(c.esp + 4)
        usage = self.mem.read_u32(c.esp + 8)
        fmt = self.mem.read_u32(c.esp + 12)
        pool = self.mem.read_u32(c.esp + 16)
        pp_ib = self.mem.read_u32(c.esp + 20)
        c.esp += 28

        if pp_ib == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        buf_id = self.next_resource_id
        self.next_resource_id += 1
        handle = 0x27803000 + (buf_id * 32)
        self.mem.write_u32(pp_ib, handle)

        payload = struct.pack("<5I", buf_id, length, usage, fmt, pool)
        self.ring.write_command(D3DCommandType.CREATE_INDEX_BUFFER, payload)
        c.eax = D3D_OK

    def dev_shim_CreateRenderTarget(self, c: Any) -> None: c.esp += 36; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_CreateDepthStencilSurface(self, c: Any) -> None: c.esp += 36; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_UpdateSurface(self, c: Any) -> None: c.esp += 20; c.eax = D3D_OK
    def dev_shim_UpdateTexture(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetRenderTargetData(self, c: Any) -> None: c.esp += 12; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_GetFrontBufferData(self, c: Any) -> None: c.esp += 12; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_StretchRect(self, c: Any) -> None: c.esp += 24; c.eax = D3D_OK
    def dev_shim_ColorFill(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_CreateOffscreenPlainSurface(self, c: Any) -> None: c.esp += 28; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_SetRenderTarget(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetRenderTarget(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_SetDepthStencilSurface(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetDepthStencilSurface(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_BeginScene(self, c: Any) -> None:
        c.esp += 4
        self.ring.write_command(D3DCommandType.BEGIN_SCENE, b"")
        c.eax = D3D_OK

    def dev_shim_EndScene(self, c: Any) -> None:
        c.esp += 4
        self.ring.write_command(D3DCommandType.END_SCENE, b"")
        c.eax = D3D_OK

    def dev_shim_Clear(self, c: Any) -> None:
        count = self.mem.read_u32(c.esp + 4)
        flags = self.mem.read_u32(c.esp + 12)
        color = self.mem.read_u32(c.esp + 16)
        z = struct.unpack("<f", struct.pack("<I", self.mem.read_u32(c.esp + 20)))[0]
        stencil = self.mem.read_u32(c.esp + 24)
        c.esp += 28

        self.ring.write_command(D3DCommandType.CLEAR, encode_clear(flags, color, z, stencil, count))
        c.eax = D3D_OK

    def dev_shim_SetTransform(self, c: Any) -> None:
        state = self.mem.read_u32(c.esp + 4)
        p_mat = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if p_mat != 0:
            payload = struct.pack("<I", state) + self.mem.read_bytes(p_mat, 64)
            self.ring.write_command(D3DCommandType.SET_TRANSFORM, payload)
        c.eax = D3D_OK

    def dev_shim_GetTransform(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_MultiplyTransform(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK

    def dev_shim_SetViewport(self, c: Any) -> None:
        p_vp = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_vp != 0:
            vp_bytes = self.mem.read_bytes(p_vp, 24)
            self.viewport = struct.unpack("<4I2f", vp_bytes)
            self.ring.write_command(D3DCommandType.SET_VIEWPORT, vp_bytes)
        c.eax = D3D_OK

    def dev_shim_GetViewport(self, c: Any) -> None:
        p_vp = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_vp != 0:
            self.mem.write_bytes(p_vp, struct.pack("<4I2f", *self.viewport))
        c.eax = D3D_OK

    def dev_shim_SetMaterial(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetMaterial(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetLight(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetLight(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_LightEnable(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetLightEnable(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_SetClipPlane(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetClipPlane(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK

    def dev_shim_SetRenderState(self, c: Any) -> None:
        state = self.mem.read_u32(c.esp + 4)
        val = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        self.render_states[state] = val
        self.ring.write_command(D3DCommandType.SET_RENDER_STATE, encode_set_render_state(state, val))
        c.eax = D3D_OK

    def dev_shim_GetRenderState(self, c: Any) -> None:
        state = self.mem.read_u32(c.esp + 4)
        p_val = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if p_val != 0:
            self.mem.write_u32(p_val, self.render_states.get(state, 0))
        c.eax = D3D_OK

    def dev_shim_CreateStateBlock(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_BeginStateBlock(self, c: Any) -> None: c.esp += 4; c.eax = D3D_OK
    def dev_shim_EndStateBlock(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetClipStatus(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetClipStatus(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_GetTexture(self, c: Any) -> None:
        stage = self.mem.read_u32(c.esp + 4)
        pp_tex = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if pp_tex != 0:
            self.mem.write_u32(pp_tex, self.textures.get(stage, 0))
        c.eax = D3D_OK

    def dev_shim_SetTexture(self, c: Any) -> None:
        stage = self.mem.read_u32(c.esp + 4)
        p_tex = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        self.textures[stage] = p_tex
        tex_id = (p_tex - 0x27805000) // 32 if p_tex >= 0x27805000 else 0
        payload = struct.pack("<2I", stage, tex_id)
        self.ring.write_command(D3DCommandType.SET_TEXTURE, payload)
        c.eax = D3D_OK

    def dev_shim_GetTextureStageState(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetTextureStageState(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_GetSamplerState(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK

    def dev_shim_SetSamplerState(self, c: Any) -> None:
        sampler = self.mem.read_u32(c.esp + 4)
        stype = self.mem.read_u32(c.esp + 8)
        val = self.mem.read_u32(c.esp + 12)
        c.esp += 16
        payload = struct.pack("<3I", sampler, stype, val)
        self.ring.write_command(D3DCommandType.SET_SAMPLER_STATE, payload)
        c.eax = D3D_OK

    def dev_shim_ValidateDevice(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetPaletteEntries(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetPaletteEntries(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_SetCurrentTexturePalette(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetCurrentTexturePalette(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_SetScissorRect(self, c: Any) -> None:
        p_rect = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        if p_rect != 0:
            self.ring.write_command(D3DCommandType.SET_SCISSOR_RECT, self.mem.read_bytes(p_rect, 16))
        c.eax = D3D_OK

    def dev_shim_GetScissorRect(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetSoftwareVertexProcessing(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetSoftwareVertexProcessing(self, c: Any) -> None: c.esp += 4; c.eax = 0
    def dev_shim_SetNPatchMode(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetNPatchMode(self, c: Any) -> None: c.esp += 4; c.eax = 0

    def dev_shim_DrawPrimitive(self, c: Any) -> None:
        pt = self.mem.read_u32(c.esp + 4)
        start = self.mem.read_u32(c.esp + 8)
        count = self.mem.read_u32(c.esp + 12)
        c.esp += 16

        # Strict validation: must have bound stream 0 and count > 0
        if count == 0 or self.bound_stream0_stride == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        self.ring.write_command(D3DCommandType.DRAW_PRIMITIVE, encode_draw_primitive(pt, start, count))
        c.eax = D3D_OK

    def dev_shim_DrawIndexedPrimitive(self, c: Any) -> None:
        pt = self.mem.read_u32(c.esp + 4)
        base = self.mem.read_i32(c.esp + 8) if hasattr(self.mem, "read_i32") else struct.unpack("<i", struct.pack("<I", self.mem.read_u32(c.esp + 8)))[0]
        min_idx = self.mem.read_u32(c.esp + 12)
        num_v = self.mem.read_u32(c.esp + 16)
        start = self.mem.read_u32(c.esp + 20)
        count = self.mem.read_u32(c.esp + 24)
        c.esp += 28

        # Strict validation: must have bound indices and stream 0 and count > 0
        if count == 0 or self.bound_indices_id == 0 or self.bound_stream0_stride == 0:
            c.eax = D3DERR_INVALIDCALL
            return

        self.ring.write_command(
            D3DCommandType.DRAW_INDEXED_PRIMITIVE,
            encode_draw_indexed_primitive(pt, base, min_idx, num_v, start, count),
        )
        c.eax = D3D_OK

    def dev_shim_DrawPrimitiveUP(self, c: Any) -> None: c.esp += 20; c.eax = D3D_OK
    def dev_shim_DrawIndexedPrimitiveUP(self, c: Any) -> None: c.esp += 36; c.eax = D3D_OK
    def dev_shim_ProcessVertices(self, c: Any) -> None: c.esp += 28; c.eax = D3D_OK

    def dev_shim_CreateVertexDeclaration(self, c: Any) -> None:
        pp_decl = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if pp_decl != 0:
            self.mem.write_u32(pp_decl, 0x27806000 + (self.next_resource_id * 16))
            self.next_resource_id += 1
        c.eax = D3D_OK

    def dev_shim_SetVertexDeclaration(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetVertexDeclaration(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_SetFVF(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK
    def dev_shim_GetFVF(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_CreateVertexShader(self, c: Any) -> None:
        pp_s = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if pp_s != 0:
            self.mem.write_u32(pp_s, 0x27807000 + (self.next_resource_id * 16))
            self.next_resource_id += 1
        c.eax = D3D_OK

    def dev_shim_SetVertexShader(self, c: Any) -> None:
        p_s = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        self.ring.write_command(D3DCommandType.SET_VERTEX_SHADER, struct.pack("<I", p_s))
        c.eax = D3D_OK

    def dev_shim_GetVertexShader(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_SetVertexShaderConstantF(self, c: Any) -> None:
        reg = self.mem.read_u32(c.esp + 4)
        p_d = self.mem.read_u32(c.esp + 8)
        cnt = self.mem.read_u32(c.esp + 12)
        c.esp += 16
        if p_d != 0 and cnt > 0:
            payload = struct.pack("<2I", reg, cnt) + self.mem.read_bytes(p_d, cnt * 16)
            self.ring.write_command(D3DCommandType.SET_VS_CONSTANTS, payload)
        c.eax = D3D_OK

    def dev_shim_GetVertexShaderConstantF(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetVertexShaderConstantI(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_GetVertexShaderConstantI(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetVertexShaderConstantB(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_GetVertexShaderConstantB(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK

    def dev_shim_SetStreamSource(self, c: Any) -> None:
        stream = self.mem.read_u32(c.esp + 4)
        p_vb = self.mem.read_u32(c.esp + 8)
        offset = self.mem.read_u32(c.esp + 12)
        stride = self.mem.read_u32(c.esp + 16)
        c.esp += 20

        buf_id = (p_vb - 0x27802000) // 32 if p_vb >= 0x27802000 else 0
        if stream == 0:
            self.bound_stream0_buf = buf_id
            self.bound_stream0_stride = stride

        payload = struct.pack("<4I", stream, buf_id, offset, stride)
        self.ring.write_command(D3DCommandType.SET_STREAM_SOURCE, payload)
        c.eax = D3D_OK

    def dev_shim_GetStreamSource(self, c: Any) -> None: c.esp += 20; c.eax = D3D_OK
    def dev_shim_SetStreamSourceFreq(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK
    def dev_shim_GetStreamSourceFreq(self, c: Any) -> None: c.esp += 12; c.eax = D3D_OK

    def dev_shim_SetIndices(self, c: Any) -> None:
        p_ib = self.mem.read_u32(c.esp + 4)
        c.esp += 8

        self.bound_indices_id = (p_ib - 0x27803000) // 32 if p_ib >= 0x27803000 else 0
        payload = struct.pack("<I", self.bound_indices_id)
        self.ring.write_command(D3DCommandType.SET_INDICES, payload)
        c.eax = D3D_OK

    def dev_shim_GetIndices(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_CreatePixelShader(self, c: Any) -> None:
        pp_s = self.mem.read_u32(c.esp + 8)
        c.esp += 12
        if pp_s != 0:
            self.mem.write_u32(pp_s, 0x27808000 + (self.next_resource_id * 16))
            self.next_resource_id += 1
        c.eax = D3D_OK

    def dev_shim_SetPixelShader(self, c: Any) -> None:
        p_s = self.mem.read_u32(c.esp + 4)
        c.esp += 8
        self.ring.write_command(D3DCommandType.SET_PIXEL_SHADER, struct.pack("<I", p_s))
        c.eax = D3D_OK

    def dev_shim_GetPixelShader(self, c: Any) -> None: c.esp += 8; c.eax = D3D_OK

    def dev_shim_SetPixelShaderConstantF(self, c: Any) -> None:
        reg = self.mem.read_u32(c.esp + 4)
        p_d = self.mem.read_u32(c.esp + 8)
        cnt = self.mem.read_u32(c.esp + 12)
        c.esp += 16
        if p_d != 0 and cnt > 0:
            payload = struct.pack("<2I", reg, cnt) + self.mem.read_bytes(p_d, cnt * 16)
            self.ring.write_command(D3DCommandType.SET_PS_CONSTANTS, payload)
        c.eax = D3D_OK

    def dev_shim_GetPixelShaderConstantF(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetPixelShaderConstantI(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_GetPixelShaderConstantI(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_SetPixelShaderConstantB(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_GetPixelShaderConstantB(self, c: Any) -> None: c.esp += 16; c.eax = D3D_OK
    def dev_shim_DrawRectPatch(self, c: Any) -> None: c.esp += 16; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_DrawTriPatch(self, c: Any) -> None: c.esp += 16; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_DeletePatch(self, c: Any) -> None: c.esp += 8; c.eax = D3DERR_NOTAVAILABLE
    def dev_shim_CreateQuery(self, c: Any) -> None: c.esp += 12; c.eax = D3DERR_NOTAVAILABLE
