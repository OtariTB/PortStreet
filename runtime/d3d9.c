/* Need for Speed ProStreet - Direct3D 9 COM Interface Shim Implementation.
 *
 * Implements Direct3DCreate9 entrypoint, IDirect3D9 COM vtable (17 methods),
 * and IDirect3DDevice9 COM vtable (119 methods) with lock-free ring buffer command
 * serialization and authentic Win32 __stdcall stack discipline.
 */
#include "d3d9.h"
#include <string.h>
#include <stdio.h>

/* Static Reference Counts and State */
static uint32_t s_d3d9_ref_count = 0;
static bool     s_d3d9_active = false;

static uint32_t s_device_ref_count = 0;
static bool     s_device_active = false;

/* Resource Tracking */
static uint32_t s_next_resource_id = 1u;
static uint32_t s_bound_indices_id = 0u;

typedef struct {
    uint32_t buffer_id;
    uint32_t offset;
    uint32_t stride;
} d3d9_stream_t;

static d3d9_stream_t s_streams[16];
static uint32_t      s_textures[16];
static uint32_t      s_render_states[256];
static d3d9_cmd_set_viewport_t s_viewport = { 0, 0, 1280, 720, 0.0f, 1.0f };

/* Standard COM Interface GUIDs (16 bytes each) */
static const uint8_t s_guid_iunknown[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

/* {81BDCBCA-64D4-426d-AE8D-AD0147F4275C} */
static const uint8_t s_guid_idirect3d9[16] = {
    0xCA, 0xCB, 0xBD, 0x81, 0xD4, 0x64, 0x6D, 0x42,
    0xAE, 0x8D, 0xAD, 0x01, 0x47, 0xF4, 0x27, 0x5C
};

/* {D0223B96-BF7A-43fd-92BD-A43B0D82B9EB} */
static const uint8_t s_guid_idirect3ddevice9[16] = {
    0x96, 0x3B, 0x22, 0xD0, 0x7A, 0xBF, 0xFD, 0x43,
    0x92, 0xBD, 0xA4, 0x3B, 0x0D, 0x82, 0xB9, 0xEB
};

/* Standard Display Modes */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_rate;
    uint32_t format;
} d3d9_mode_t;

static const d3d9_mode_t s_display_modes[4] = {
    { 800,  600,  60, D3DFMT_X8R8G8B8 },
    { 1024, 768,  60, D3DFMT_X8R8G8B8 },
    { 1280, 720,  60, D3DFMT_X8R8G8B8 },
    { 1920, 1080, 60, D3DFMT_X8R8G8B8 }
};

static bool is_format_supported(uint32_t fmt) {
    switch (fmt) {
        case D3DFMT_R8G8B8:
        case D3DFMT_A8R8G8B8:
        case D3DFMT_X8R8G8B8:
        case D3DFMT_R5G6B5:
        case D3DFMT_D24S8:
        case 77: /* D3DFMT_D24X8 */
        case 80: /* D3DFMT_D16 */
        case D3DFMT_INDEX16:
        case D3DFMT_INDEX32:
        case D3DFMT_DXT1:
        case D3DFMT_DXT2:
        case D3DFMT_DXT3:
        case D3DFMT_DXT4:
        case D3DFMT_DXT5:
            return true;
        default:
            return false;
    }
}

/* --------------------------------------------------------------------------
 * Ring Buffer Helpers
 * -------------------------------------------------------------------------- */
static bool emit_cmd(uint16_t cmd_type, const void *payload, uint32_t payload_bytes) {
    if (!GUEST_MEM_READY) return false;
    d3d9_ring_header_t *hdr = (d3d9_ring_header_t *)(g_mem + D3D9_RING_BUFFER_VA);
    if (hdr->magic != D3D9_RING_MAGIC) return false;

    uint32_t aligned_len = (payload_bytes + 3u) & ~3u;
    uint32_t packet_len = 8u + aligned_len;

    if (d3d9_ring_available(hdr) < packet_len) {
        hdr->dropped_frames++;
        return false;
    }

    uint8_t *data_base = g_mem + D3D9_RING_BUFFER_VA + D3D9_RING_HEADER_SIZE;
    uint32_t head = hdr->head;
    uint32_t capacity = hdr->capacity;

    /* Write 8-byte command header */
    d3d9_cmd_header_t chdr;
    chdr.cmd_type = cmd_type;
    chdr.flags = 0;
    chdr.payload_bytes = aligned_len;

    uint8_t packet_hdr[8];
    memcpy(packet_hdr, &chdr, 8);

    /* Helper: circular copy */
    uint32_t pos = head;
    for (uint32_t i = 0; i < 8; ++i) {
        data_base[(pos + i) % capacity] = packet_hdr[i];
    }
    pos = (pos + 8) % capacity;

    if (payload && payload_bytes > 0) {
        const uint8_t *src = (const uint8_t *)payload;
        for (uint32_t i = 0; i < payload_bytes; ++i) {
            data_base[(pos + i) % capacity] = src[i];
        }
        for (uint32_t i = payload_bytes; i < aligned_len; ++i) {
            data_base[(pos + i) % capacity] = 0;
        }
    }

    hdr->head = (head + packet_len) % capacity;
    return true;
}

/* --------------------------------------------------------------------------
 * Direct3DCreate9 (Authentic IAT Entrypoint at 0x009675bc)
 * -------------------------------------------------------------------------- */
void d3d9_shim_Direct3DCreate9(CPU *c) {
    uint32_t sdk_version = MR32(c->esp);
    printf("[D3D9] Direct3DCreate9 called (sdk_version=%u)\n", sdk_version); fflush(stdout);
    c->esp += 4; /* __stdcall pop 1 arg */

    /* Reject any invalid SDK version (ProStreet passes 0x20 = 32) */
    if (sdk_version < 31u || sdk_version > 32u) {
        c->eax = 0u;
        return;
    }

    s_d3d9_ref_count = 1u;
    s_d3d9_active = true;

    if (GUEST_MEM_READY) {
        /* Write instance vtable pointer and reference count into heap */
        MR32(D3D9_INSTANCE_VA) = D3D9_VTABLE_VA;
        MR32(D3D9_INSTANCE_VA + 4u) = s_d3d9_ref_count;
    }

    c->eax = D3D9_INSTANCE_VA;
}

/* --------------------------------------------------------------------------
 * D3DXVec3Transform (d3dx9_34.dll IAT Entrypoint at 0x009675dc)
 * D3DXVECTOR4* WINAPI D3DXVec3Transform(D3DXVECTOR4 *pOut, const D3DXVECTOR3 *pV, const D3DXMATRIX *pM)
 * Transforms (x, y, z, 1) by matrix pM using Direct3D row-vector conventions: V * M.
 * -------------------------------------------------------------------------- */
void d3d9_shim_D3DXVec3Transform(CPU *c) {
    uint32_t pOut = MR32(c->esp);
    uint32_t pV = MR32(c->esp + 4u);
    uint32_t pM = MR32(c->esp + 8u);
    c->esp += 12u; /* __stdcall pop 3 args (12 bytes) */

    if (g_mem == NULL || !guest_is_valid_va(pOut, 16u) || !guest_is_valid_va(pV, 12u) || !guest_is_valid_va(pM, 64u)) {
        c->eax = 0u;
        return;
    }

    /* Read all inputs into local variables before writing to safely handle overlap (pOut == pV) */
    float vx = MRF32(pV + 0u);
    float vy = MRF32(pV + 4u);
    float vz = MRF32(pV + 8u);

    /* Row-vector multiplication: [x, y, z, 1] * M
     * out.x = x*m11 + y*m21 + z*m31 + 1*m41
     * out.y = x*m12 + y*m22 + z*m32 + 1*m42
     * out.z = x*m13 + y*m23 + z*m33 + 1*m43
     * out.w = x*m14 + y*m24 + z*m34 + 1*m44
     */
    float rx = vx * MRF32(pM + 0u)  + vy * MRF32(pM + 16u) + vz * MRF32(pM + 32u) + MRF32(pM + 48u);
    float ry = vx * MRF32(pM + 4u)  + vy * MRF32(pM + 20u) + vz * MRF32(pM + 36u) + MRF32(pM + 52u);
    float rz = vx * MRF32(pM + 8u)  + vy * MRF32(pM + 24u) + vz * MRF32(pM + 40u) + MRF32(pM + 56u);
    float rw = vx * MRF32(pM + 12u) + vy * MRF32(pM + 28u) + vz * MRF32(pM + 44u) + MRF32(pM + 60u);

    MRF32(pOut + 0u)  = rx;
    MRF32(pOut + 4u)  = ry;
    MRF32(pOut + 8u)  = rz;
    MRF32(pOut + 12u) = rw;

    c->eax = pOut;
}

/* --------------------------------------------------------------------------
 * D3DXMatrixTranspose (d3dx9_34.dll IAT Entrypoint at 0x009675f4)
 * D3DXMATRIX* WINAPI D3DXMatrixTranspose(D3DXMATRIX *pOut, const D3DXMATRIX *pM)
 * -------------------------------------------------------------------------- */
void d3d9_shim_D3DXMatrixTranspose(CPU *c) {
    uint32_t pOut = MR32(c->esp);
    uint32_t pM = MR32(c->esp + 4u);
    c->esp += 8u; /* __stdcall pop 2 args (8 bytes) */

    if (g_mem == NULL || !guest_is_valid_va(pOut, 64u) || !guest_is_valid_va(pM, 64u)) {
        c->eax = 0u;
        return;
    }

    /* Safely support in-place transposition (pOut == pM) by copying input matrix to temporary buffer */
    uint32_t temp[16];
    for (int i = 0; i < 16; ++i) {
        temp[i] = MR32(pM + (uint32_t)(i * 4));
    }

    /* Transpose 4x4 row-major matrix: out[row][col] = in[col][row] */
    for (int r = 0; r < 4; ++r) {
        for (int col = 0; col < 4; ++col) {
            MR32(pOut + (uint32_t)((r * 4 + col) * 4)) = temp[col * 4 + r];
        }
    }

    c->eax = pOut;
}

/* --------------------------------------------------------------------------
 * IDirect3D9 COM Vtable Methods (17 methods)
 * -------------------------------------------------------------------------- */

/* Method 0: QueryInterface(this, riid, ppvObj) */
void d3d9_shim_QueryInterface(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    uint32_t pRiid = MR32(c->esp + 4u);
    uint32_t ppvObj = MR32(c->esp + 8u);
    c->esp += 12;

    if (ppvObj == 0) {
        c->eax = E_POINTER;
        return;
    }

    if (pRiid != 0 && GUEST_MEM_READY) {
        const uint8_t *riid = g_mem + pRiid;
        if (memcmp(riid, s_guid_iunknown, 16) == 0 ||
            memcmp(riid, s_guid_idirect3d9, 16) == 0) {
            MR32(ppvObj) = pThis;
            s_d3d9_ref_count++;
            if (GUEST_MEM_READY) {
                MR32(pThis + 4u) = s_d3d9_ref_count;
            }
            c->eax = D3D_OK;
            return;
        }
    }

    MR32(ppvObj) = 0u;
    c->eax = E_NOINTERFACE;
}

/* Method 1: AddRef(this) */
void d3d9_shim_AddRef(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    c->esp += 4;

    s_d3d9_ref_count++;
    if (GUEST_MEM_READY && pThis != 0) {
        MR32(pThis + 4u) = s_d3d9_ref_count;
    }
    c->eax = s_d3d9_ref_count;
}

/* Method 2: Release(this) */
void d3d9_shim_Release(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    c->esp += 4;

    if (s_d3d9_ref_count > 0) {
        s_d3d9_ref_count--;
    }
    if (s_d3d9_ref_count == 0) {
        s_d3d9_active = false;
    }
    if (GUEST_MEM_READY && pThis != 0) {
        MR32(pThis + 4u) = s_d3d9_ref_count;
    }
    c->eax = s_d3d9_ref_count;
}

/* Method 3: RegisterSoftwareDevice(this, pInitializeFunction) */
void d3d9_shim_RegisterSoftwareDevice(CPU *c) {
    c->esp += 8;
    c->eax = D3DERR_NOTAVAILABLE;
}

/* Method 4: GetAdapterCount(this) */
void d3d9_shim_GetAdapterCount(CPU *c) {
    c->esp += 4;
    c->eax = 1u;
}

/* Method 5: GetAdapterIdentifier(this, Adapter, Flags, pIdentifier) */
void d3d9_shim_GetAdapterIdentifier(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t pId     = MR32(c->esp + 12u);
    c->esp += 16;

    if (adapter != 0 || pId == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    /* Zero authentic 1,100-byte D3DADAPTER_IDENTIFIER9 structure */
    memset(g_mem + pId, 0, 1100);

    /* Driver [512 bytes] at offset 0 */
    const char *driver = "d3d9.dll";
    memcpy(g_mem + pId, driver, strlen(driver) + 1);

    /* Description [512 bytes] at offset 512 */
    const char *desc = "PortSpeed WebGPU / WebGL2 D3D9 Adapter";
    memcpy(g_mem + pId + 512, desc, strlen(desc) + 1);

    /* DeviceName [32 bytes] at offset 1024 */
    const char *dev_name = "\\\\.\\DISPLAY1";
    memcpy(g_mem + pId + 1024, dev_name, strlen(dev_name) + 1);

    /* DriverVersion (8 bytes) at offset 1056 */
    *(uint64_t *)(g_mem + pId + 1056) = 0x0001000000000000ULL;

    /* VendorId at offset 1064, DeviceId at 1068 */
    MR32(pId + 1064) = 0x10DEu;     /* VendorId = NVIDIA generic */
    MR32(pId + 1068) = 0x0402u;     /* DeviceId */
    MR32(pId + 1072) = 0u;          /* SubSysId */
    MR32(pId + 1076) = 0u;          /* Revision */

    /* DeviceIdentifier GUID at offset 1080 (16 bytes) */
    const uint8_t dev_guid[16] = {
        0x3E, 0x1E, 0xB7, 0xD7, 0x42, 0x47, 0xCF, 0x11,
        0x82, 0x6E, 0x01, 0x20, 0x02, 0xC2, 0xCB, 0x35
    };
    memcpy(g_mem + pId + 1080, dev_guid, 16);
    MR32(pId + 1096) = 0u;          /* WHQLLevel */

    c->eax = D3D_OK;
}

/* Method 6: GetAdapterModeCount(this, Adapter, Format) */
void d3d9_shim_GetAdapterModeCount(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t format  = MR32(c->esp + 8u);
    c->esp += 12;

    if (adapter == 0 && (format == D3DFMT_X8R8G8B8 || format == D3DFMT_A8R8G8B8)) {
        c->eax = 4u;
        return;
    }
    c->eax = 0u;
}

/* Method 7: EnumAdapterModes(this, Adapter, Format, Mode, pMode) */
void d3d9_shim_EnumAdapterModes(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t format  = MR32(c->esp + 8u);
    uint32_t mode    = MR32(c->esp + 12u);
    uint32_t pMode   = MR32(c->esp + 16u);
    c->esp += 20;

    if (adapter != 0 || pMode == 0 || mode >= 4 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    MR32(pMode + 0u)  = s_display_modes[mode].width;
    MR32(pMode + 4u)  = s_display_modes[mode].height;
    MR32(pMode + 8u)  = s_display_modes[mode].refresh_rate;
    MR32(pMode + 12u) = format;

    c->eax = D3D_OK;
}

/* Method 8: GetAdapterDisplayMode(this, Adapter, pMode) */
void d3d9_shim_GetAdapterDisplayMode(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t pMode   = MR32(c->esp + 8u);
    c->esp += 12;

    if (adapter != 0 || pMode == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    MR32(pMode + 0u)  = 1280u;
    MR32(pMode + 4u)  = 720u;
    MR32(pMode + 8u)  = 60u;
    MR32(pMode + 12u) = D3DFMT_X8R8G8B8;

    c->eax = D3D_OK;
}

/* Method 9: CheckDeviceType(this, Adapter, DevType, AdapterFormat, BackBufferFormat, bWindowed) */
void d3d9_shim_CheckDeviceType(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t devtype = MR32(c->esp + 8u);
    c->esp += 24;

    if (adapter == 0 && (devtype == 1u || devtype == 2u)) {
        c->eax = D3D_OK;
    } else {
        c->eax = D3DERR_NOTAVAILABLE;
    }
}

/* Method 10: CheckDeviceFormat(this, Adapter, DeviceType, AdapterFormat, Usage, RType, CheckFormat) */
void d3d9_shim_CheckDeviceFormat(CPU *c) {
    uint32_t adapter     = MR32(c->esp + 4u);
    uint32_t check_format = MR32(c->esp + 24u);
    c->esp += 28;

    if (adapter == 0 && is_format_supported(check_format)) {
        c->eax = D3D_OK;
    } else {
        c->eax = D3DERR_NOTAVAILABLE;
    }
}

/* Method 11: CheckDeviceMultiSampleType(this, Adapter, DeviceType, SurfaceFormat, Windowed, MultiSampleType, pQualityLevels) */
void d3d9_shim_CheckDeviceMultiSampleType(CPU *c) {
    uint32_t adapter  = MR32(c->esp + 4u);
    uint32_t ms_type  = MR32(c->esp + 20u);
    uint32_t pQuality = MR32(c->esp + 24u);
    c->esp += 28;

    if (adapter == 0 && ms_type == 0u) {
        if (pQuality != 0 && GUEST_MEM_READY) {
            MR32(pQuality) = 1u;
        }
        c->eax = D3D_OK;
    } else {
        if (pQuality != 0 && GUEST_MEM_READY) {
            MR32(pQuality) = 0u;
        }
        c->eax = D3DERR_NOTAVAILABLE;
    }
}

/* Method 12: CheckDepthStencilMatch(this, Adapter, DeviceType, AdapterFormat, RenderTargetFormat, DepthStencilFormat) */
void d3d9_shim_CheckDepthStencilMatch(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    c->esp += 24;

    if (adapter == 0) {
        c->eax = D3D_OK;
    } else {
        c->eax = D3DERR_NOTAVAILABLE;
    }
}

/* Method 13: CheckDeviceFormatConversion(this, Adapter, DeviceType, SourceFormat, TargetFormat) */
void d3d9_shim_CheckDeviceFormatConversion(CPU *c) {
    uint32_t adapter   = MR32(c->esp + 4u);
    uint32_t src_format = MR32(c->esp + 12u);
    uint32_t dst_format = MR32(c->esp + 16u);
    c->esp += 20;

    if (adapter == 0 && src_format == dst_format) {
        c->eax = D3D_OK;
    } else {
        c->eax = D3DERR_NOTAVAILABLE;
    }
}

/* Method 14: GetDeviceCaps(this, Adapter, DeviceType, pCaps) */
void d3d9_shim_GetDeviceCaps(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    uint32_t pCaps   = MR32(c->esp + 12u);
    c->esp += 16;

    if (adapter != 0 || pCaps == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    memset(g_mem + pCaps, 0, 304);
    MR32(pCaps + 0u)  = 1u;           /* DeviceType = D3DDEVTYPE_HAL */
    MR32(pCaps + 4u)  = 0u;           /* AdapterOrdinal = 0 */
    MR32(pCaps + 8u)  = 0x00020000u;  /* Caps */
    MR32(pCaps + 12u) = 0xE0020000u;  /* Caps2: Dynamic textures + Autogen mipmaps */
    MR32(pCaps + 16u) = 0x00000020u;  /* Caps3 */
    MR32(pCaps + 20u) = 0x8000000Fu;  /* PresentationIntervals */
    MR32(pCaps + 24u) = 0x001BBE50u;  /* DevCaps: PureDevice, HWTransformAndLight */
    MR32(pCaps + 28u) = 0x002FCEF2u;  /* PrimitiveMiscCaps */
    MR32(pCaps + 32u) = 0x07732191u;  /* RasterCaps */
    MR32(pCaps + 36u) = 0x000000FFu;  /* ZCmpCaps */
    MR32(pCaps + 40u) = 0x00003FFFu;  /* SrcBlendCaps */
    MR32(pCaps + 44u) = 0x00003FFFu;  /* DestBlendCaps */
    MR32(pCaps + 48u) = 0x000000FFu;  /* AlphaCmpCaps */
    MR32(pCaps + 52u) = 0x00084208u;  /* ShadeCaps */
    MR32(pCaps + 56u) = 0x0001ECC5u;  /* TextureCaps */
    MR32(pCaps + 60u) = 0x03030700u;  /* TextureFilterCaps */

    MR32(pCaps + 72u) = 4096u;        /* MaxTextureWidth */
    MR32(pCaps + 76u) = 4096u;        /* MaxTextureHeight */
    MR32(pCaps + 80u) = 2048u;        /* MaxVolumeExtent */
    MR32(pCaps + 84u) = 8192u;        /* MaxTextureRepeat */
    MR32(pCaps + 88u) = 4096u;        /* MaxTextureAspectRatio */
    MR32(pCaps + 92u) = 16u;          /* MaxAnisotropy */

    MR32(pCaps + 216u) = 0xFFFE0300u; /* VertexShaderVersion (VS 3.0) */
    MR32(pCaps + 220u) = 256u;        /* MaxVertexShaderConst */
    MR32(pCaps + 224u) = 0xFFFF0300u; /* PixelShaderVersion (PS 3.0) */
    MR32(pCaps + 256u) = 16u;         /* MaxStreams */
    MR32(pCaps + 260u) = 255u;        /* MaxStreamStride */

    c->eax = D3D_OK;
}

/* Method 15: GetAdapterMonitor(this, Adapter) */
void d3d9_shim_GetAdapterMonitor(CPU *c) {
    uint32_t adapter = MR32(c->esp + 4u);
    c->esp += 8;

    if (adapter == 0) {
        c->eax = 0x00010001u;
    } else {
        c->eax = 0u;
    }
}

/* Method 16: CreateDevice(this, Adapter, DeviceType, hFocusWindow, BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface) */
void d3d9_shim_CreateDevice(CPU *c) {
    printf("[D3D9] CreateDevice called!\n"); fflush(stdout);
    uint32_t adapter    = MR32(c->esp + 4u);
    uint32_t devtype    = MR32(c->esp + 8u);
    uint32_t pPP        = MR32(c->esp + 20u);
    uint32_t ppDevice   = MR32(c->esp + 24u);
    c->esp += 28; /* Pop this + 6 args */

    if (ppDevice == 0 || pPP == 0 || adapter != 0) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    if (devtype != 1u && devtype != 2u) {
        c->eax = D3DERR_NOTAVAILABLE;
        return;
    }

    /* Initialize IDirect3DDevice9 instance in guest heap */
    s_device_ref_count = 1u;
    s_device_active = true;

    if (GUEST_MEM_READY) {
        MR32(D3D9_DEVICE_INSTANCE_VA) = D3D9_DEVICE_VTABLE_VA;
        MR32(D3D9_DEVICE_INSTANCE_VA + 4u) = s_device_ref_count;
        MR32(ppDevice) = D3D9_DEVICE_INSTANCE_VA;

        /* Initialize 4 MB shared command ring buffer */
        d3d9_ring_init(g_mem + D3D9_RING_BUFFER_VA, D3D9_RING_DEFAULT_CAPACITY + D3D9_RING_HEADER_SIZE);

        /* Set initial viewport from presentation parameters */
        s_viewport.x = 0;
        s_viewport.y = 0;
        s_viewport.width = MR32(pPP + 0u) ? MR32(pPP + 0u) : 1280u;
        s_viewport.height = MR32(pPP + 4u) ? MR32(pPP + 4u) : 720u;
        s_viewport.min_z = 0.0f;
        s_viewport.max_z = 1.0f;

        emit_cmd(D3DCMD_SET_VIEWPORT, &s_viewport, sizeof(s_viewport));
    }

    c->eax = D3D_OK;
}

/* --------------------------------------------------------------------------
 * IDirect3DDevice9 COM Vtable Methods (119 methods)
 * -------------------------------------------------------------------------- */

void d3d9_dev_shim_QueryInterface(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    uint32_t pRiid = MR32(c->esp + 4u);
    uint32_t ppvObj = MR32(c->esp + 8u);
    c->esp += 12;

    if (ppvObj == 0) {
        c->eax = E_POINTER;
        return;
    }

    if (pRiid != 0 && GUEST_MEM_READY) {
        const uint8_t *riid = g_mem + pRiid;
        if (memcmp(riid, s_guid_iunknown, 16) == 0 ||
            memcmp(riid, s_guid_idirect3ddevice9, 16) == 0) {
            MR32(ppvObj) = pThis;
            s_device_ref_count++;
            if (GUEST_MEM_READY) MR32(pThis + 4u) = s_device_ref_count;
            c->eax = D3D_OK;
            return;
        }
    }

    MR32(ppvObj) = 0u;
    c->eax = E_NOINTERFACE;
}

void d3d9_dev_shim_AddRef(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    c->esp += 4;
    s_device_ref_count++;
    if (GUEST_MEM_READY && pThis != 0) MR32(pThis + 4u) = s_device_ref_count;
    c->eax = s_device_ref_count;
}

void d3d9_dev_shim_Release(CPU *c) {
    uint32_t pThis = MR32(c->esp);
    c->esp += 4;
    if (s_device_ref_count > 0) s_device_ref_count--;
    if (s_device_ref_count == 0) s_device_active = false;
    if (GUEST_MEM_READY && pThis != 0) MR32(pThis + 4u) = s_device_ref_count;
    c->eax = s_device_ref_count;
}

void d3d9_dev_shim_TestCooperativeLevel(CPU *c) {
    c->esp += 4;
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetAvailableTextureMem(CPU *c) {
    c->esp += 4;
    c->eax = 512u * 1024u * 1024u; /* 512 MB */
}

void d3d9_dev_shim_EvictManagedResources(CPU *c) {
    c->esp += 4;
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetDirect3D(CPU *c) {
    uint32_t ppD3D = MR32(c->esp + 4u);
    c->esp += 8;
    if (ppD3D != 0 && GUEST_MEM_READY) {
        MR32(ppD3D) = D3D9_INSTANCE_VA;
        s_d3d9_ref_count++;
        MR32(D3D9_INSTANCE_VA + 4u) = s_d3d9_ref_count;
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetDeviceCaps(CPU *c) {
    d3d9_shim_GetDeviceCaps(c); /* Equivalent signature (Adapter 0) */
}

void d3d9_dev_shim_GetDisplayMode(CPU *c) {
    uint32_t pMode = MR32(c->esp + 8u);
    c->esp += 12;
    if (pMode != 0 && GUEST_MEM_READY) {
        MR32(pMode + 0u) = 1280u;
        MR32(pMode + 4u) = 720u;
        MR32(pMode + 8u) = 60u;
        MR32(pMode + 12u) = D3DFMT_X8R8G8B8;
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetCreationParameters(CPU *c) {
    uint32_t pParams = MR32(c->esp + 4u);
    c->esp += 8;
    if (pParams != 0 && GUEST_MEM_READY) {
        MR32(pParams + 0u) = 0u; /* AdapterOrdinal = 0 */
        MR32(pParams + 4u) = 1u; /* DeviceType = D3DDEVTYPE_HAL */
        MR32(pParams + 8u) = 0x00010001u; /* hFocusWindow */
        MR32(pParams + 12u) = 0x00000040u; /* D3DCREATE_HARDWARE_VERTEXPROCESSING */
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetCursorProperties(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetCursorPosition(CPU *c) { c->esp += 16; }
void d3d9_dev_shim_ShowCursor(CPU *c) { c->esp += 8; c->eax = 1u; }
void d3d9_dev_shim_CreateAdditionalSwapChain(CPU *c) { c->esp += 12; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_GetSwapChain(CPU *c) { c->esp += 12; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_GetNumberOfSwapChains(CPU *c) { c->esp += 4; c->eax = 1u; }

void d3d9_dev_shim_Reset(CPU *c) {
    uint32_t pPP = MR32(c->esp + 4u);
    c->esp += 8;
    if (pPP != 0 && GUEST_MEM_READY) {
        s_viewport.width = MR32(pPP + 0u) ? MR32(pPP + 0u) : 1280u;
        s_viewport.height = MR32(pPP + 4u) ? MR32(pPP + 4u) : 720u;
        emit_cmd(D3DCMD_SET_VIEWPORT, &s_viewport, sizeof(s_viewport));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_Present(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::Present called!\n"); fflush(stdout);
    uint32_t pSrc = MR32(c->esp + 4u);
    c->esp += 20;

    d3d9_cmd_present_t pres = { 0, 0, s_viewport.width, s_viewport.height };
    if (pSrc != 0 && GUEST_MEM_READY) {
        pres.src_rect_w = MR32(pSrc + 8u);
        pres.src_rect_h = MR32(pSrc + 12u);
    }
    emit_cmd(D3DCMD_PRESENT, &pres, sizeof(pres));

    if (GUEST_MEM_READY) {
        d3d9_ring_header_t *hdr = (d3d9_ring_header_t *)(g_mem + D3D9_RING_BUFFER_VA);
        if (hdr->magic == D3D9_RING_MAGIC) hdr->frame_index++;
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetBackBuffer(CPU *c) {
    uint32_t ppBack = MR32(c->esp + 16u);
    c->esp += 20;
    if (ppBack != 0 && GUEST_MEM_READY) {
        MR32(ppBack) = 0x02004000u; /* Synthetic surface handle */
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetRasterStatus(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_SetDialogBoxMode(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetGammaRamp(CPU *c) { c->esp += 16; }
void d3d9_dev_shim_GetGammaRamp(CPU *c) { c->esp += 12; }

void d3d9_dev_shim_CreateTexture(CPU *c) {
    uint32_t width  = MR32(c->esp + 4u);
    uint32_t height = MR32(c->esp + 8u);
    uint32_t levels = MR32(c->esp + 12u);
    uint32_t usage  = MR32(c->esp + 16u);
    uint32_t format = MR32(c->esp + 20u);
    uint32_t pool   = MR32(c->esp + 24u);
    uint32_t ppTex  = MR32(c->esp + 28u);
    c->esp += 36;

    if (ppTex == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    uint32_t tex_id = s_next_resource_id++;
    uint32_t tex_handle = 0x02005000u + (tex_id * 32u);
    MR32(ppTex) = tex_handle;

    d3d9_cmd_create_texture_t cmd;
    cmd.texture_id = tex_id;
    cmd.width = width;
    cmd.height = height;
    cmd.levels = levels;
    cmd.usage = usage;
    cmd.format = format;
    cmd.pool = pool;
    emit_cmd(D3DCMD_CREATE_TEXTURE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_CreateVolumeTexture(CPU *c) { c->esp += 40; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_CreateCubeTexture(CPU *c) { c->esp += 32; c->eax = D3DERR_NOTAVAILABLE; }

void d3d9_dev_shim_CreateVertexBuffer(CPU *c) {
    uint32_t length = MR32(c->esp + 4u);
    uint32_t usage  = MR32(c->esp + 8u);
    uint32_t fvf    = MR32(c->esp + 12u);
    uint32_t pool   = MR32(c->esp + 16u);
    uint32_t ppVB   = MR32(c->esp + 20u);
    c->esp += 28;

    if (ppVB == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    uint32_t buf_id = s_next_resource_id++;
    uint32_t vb_handle = 0x02002000u + (buf_id * 32u);
    MR32(ppVB) = vb_handle;

    d3d9_cmd_create_vertex_buffer_t cmd;
    cmd.buffer_id = buf_id;
    cmd.length = length;
    cmd.usage = usage;
    cmd.fvf = fvf;
    cmd.pool = pool;
    emit_cmd(D3DCMD_CREATE_VERTEX_BUFFER, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_CreateIndexBuffer(CPU *c) {
    uint32_t length = MR32(c->esp + 4u);
    uint32_t usage  = MR32(c->esp + 8u);
    uint32_t format = MR32(c->esp + 12u);
    uint32_t pool   = MR32(c->esp + 16u);
    uint32_t ppIB   = MR32(c->esp + 20u);
    c->esp += 28;

    if (ppIB == 0 || !GUEST_MEM_READY) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    uint32_t buf_id = s_next_resource_id++;
    uint32_t ib_handle = 0x02003000u + (buf_id * 32u);
    MR32(ppIB) = ib_handle;

    d3d9_cmd_create_index_buffer_t cmd;
    cmd.buffer_id = buf_id;
    cmd.length = length;
    cmd.usage = usage;
    cmd.format = format;
    cmd.pool = pool;
    emit_cmd(D3DCMD_CREATE_INDEX_BUFFER, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_CreateRenderTarget(CPU *c) { c->esp += 36; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_CreateDepthStencilSurface(CPU *c) { c->esp += 36; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_UpdateSurface(CPU *c) { c->esp += 20; c->eax = D3D_OK; }
void d3d9_dev_shim_UpdateTexture(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetRenderTargetData(CPU *c) { c->esp += 12; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_GetFrontBufferData(CPU *c) { c->esp += 12; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_StretchRect(CPU *c) { c->esp += 24; c->eax = D3D_OK; }
void d3d9_dev_shim_ColorFill(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_CreateOffscreenPlainSurface(CPU *c) { c->esp += 28; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_SetRenderTarget(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetRenderTarget(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_SetDepthStencilSurface(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetDepthStencilSurface(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_BeginScene(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::BeginScene called!\n"); fflush(stdout);
    c->esp += 4;
    emit_cmd(D3DCMD_BEGIN_SCENE, NULL, 0);
    c->eax = D3D_OK;
}

void d3d9_dev_shim_EndScene(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::EndScene called!\n"); fflush(stdout);
    c->esp += 4;
    emit_cmd(D3DCMD_END_SCENE, NULL, 0);
    c->eax = D3D_OK;
}

void d3d9_dev_shim_Clear(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::Clear called!\n"); fflush(stdout);
    uint32_t count   = MR32(c->esp + 4u);
    uint32_t flags   = MR32(c->esp + 12u);
    uint32_t color   = MR32(c->esp + 16u);
    float    z       = *(float *)(g_mem ? (g_mem + c->esp + 20u) : (const uint8_t *)&(c->esp));
    uint32_t stencil = MR32(c->esp + 24u);
    c->esp += 28;

    d3d9_cmd_clear_t cmd;
    cmd.flags = flags;
    cmd.color = color;
    cmd.z = z;
    cmd.stencil = stencil;
    cmd.count = count;
    emit_cmd(D3DCMD_CLEAR, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetTransform(CPU *c) {
    uint32_t state = MR32(c->esp + 4u);
    uint32_t pMat  = MR32(c->esp + 8u);
    c->esp += 12;

    if (pMat != 0 && GUEST_MEM_READY) {
        d3d9_cmd_set_transform_t cmd;
        cmd.state = state;
        memcpy(cmd.matrix, g_mem + pMat, 64);
        emit_cmd(D3DCMD_SET_TRANSFORM, &cmd, sizeof(cmd));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetTransform(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_MultiplyTransform(CPU *c) { c->esp += 12; c->eax = D3D_OK; }

void d3d9_dev_shim_SetViewport(CPU *c) {
    uint32_t pVP = MR32(c->esp + 4u);
    c->esp += 8;

    if (pVP != 0 && GUEST_MEM_READY) {
        memcpy(&s_viewport, g_mem + pVP, sizeof(s_viewport));
        emit_cmd(D3DCMD_SET_VIEWPORT, &s_viewport, sizeof(s_viewport));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetViewport(CPU *c) {
    uint32_t pVP = MR32(c->esp + 4u);
    c->esp += 8;

    if (pVP != 0 && GUEST_MEM_READY) {
        memcpy(g_mem + pVP, &s_viewport, sizeof(s_viewport));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetMaterial(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetMaterial(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetLight(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetLight(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_LightEnable(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetLightEnable(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_SetClipPlane(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetClipPlane(CPU *c) { c->esp += 12; c->eax = D3D_OK; }

void d3d9_dev_shim_SetRenderState(CPU *c) {
    uint32_t state = MR32(c->esp + 4u);
    uint32_t val   = MR32(c->esp + 8u);
    c->esp += 12;

    if (state < 256) s_render_states[state] = val;

    d3d9_cmd_set_render_state_t cmd;
    cmd.state = state;
    cmd.value = val;
    emit_cmd(D3DCMD_SET_RENDER_STATE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetRenderState(CPU *c) {
    uint32_t state = MR32(c->esp + 4u);
    uint32_t pVal  = MR32(c->esp + 8u);
    c->esp += 12;

    if (pVal != 0 && GUEST_MEM_READY) {
        MR32(pVal) = (state < 256) ? s_render_states[state] : 0u;
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_CreateStateBlock(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_BeginStateBlock(CPU *c) { c->esp += 4; c->eax = D3D_OK; }
void d3d9_dev_shim_EndStateBlock(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetClipStatus(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetClipStatus(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_GetTexture(CPU *c) {
    uint32_t stage = MR32(c->esp + 4u);
    uint32_t ppTex = MR32(c->esp + 8u);
    c->esp += 12;
    if (ppTex != 0 && GUEST_MEM_READY) {
        MR32(ppTex) = (stage < 16) ? s_textures[stage] : 0u;
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetTexture(CPU *c) {
    uint32_t stage = MR32(c->esp + 4u);
    uint32_t pTex  = MR32(c->esp + 8u);
    c->esp += 12;

    if (stage < 16) s_textures[stage] = pTex;

    d3d9_cmd_set_texture_t cmd;
    cmd.stage = stage;
    cmd.texture_id = pTex ? ((pTex - 0x02005000u) / 32u) : 0u;
    emit_cmd(D3DCMD_SET_TEXTURE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetTextureStageState(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetTextureStageState(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_GetSamplerState(CPU *c) { c->esp += 16; c->eax = D3D_OK; }

void d3d9_dev_shim_SetSamplerState(CPU *c) {
    uint32_t sampler = MR32(c->esp + 4u);
    uint32_t type    = MR32(c->esp + 8u);
    uint32_t value   = MR32(c->esp + 12u);
    c->esp += 16;

    d3d9_cmd_set_sampler_state_t cmd;
    cmd.sampler = sampler;
    cmd.type = type;
    cmd.value = value;
    emit_cmd(D3DCMD_SET_SAMPLER_STATE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_ValidateDevice(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetPaletteEntries(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetPaletteEntries(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_SetCurrentTexturePalette(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetCurrentTexturePalette(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_SetScissorRect(CPU *c) {
    uint32_t pRect = MR32(c->esp + 4u);
    c->esp += 8;
    if (pRect != 0 && GUEST_MEM_READY) {
        emit_cmd(D3DCMD_SET_SCISSOR_RECT, g_mem + pRect, 16);
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetScissorRect(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetSoftwareVertexProcessing(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetSoftwareVertexProcessing(CPU *c) { c->esp += 4; c->eax = 0u; }
void d3d9_dev_shim_SetNPatchMode(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetNPatchMode(CPU *c) { c->esp += 4; c->eax = 0u; }

/* DrawPrimitive requires vertex stream 0 bound and primitive_count > 0 */
void d3d9_dev_shim_DrawPrimitive(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::DrawPrimitive called!\n"); fflush(stdout);
    uint32_t prim_type   = MR32(c->esp + 4u);
    uint32_t start_vert  = MR32(c->esp + 8u);
    uint32_t prim_count  = MR32(c->esp + 12u);
    c->esp += 16;

    if (prim_count == 0 || s_streams[0].stride == 0) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    d3d9_cmd_draw_primitive_t cmd;
    cmd.primitive_type = prim_type;
    cmd.start_vertex = start_vert;
    cmd.primitive_count = prim_count;
    emit_cmd(D3DCMD_DRAW_PRIMITIVE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

/* DrawIndexedPrimitive requires index buffer + stream 0 bound and primitive_count > 0 */
void d3d9_dev_shim_DrawIndexedPrimitive(CPU *c) {
    printf("[D3D9] IDirect3DDevice9::DrawIndexedPrimitive called!\n"); fflush(stdout);
    uint32_t prim_type   = MR32(c->esp + 4u);
    int32_t  base_vert   = (int32_t)MR32(c->esp + 8u);
    uint32_t min_idx     = MR32(c->esp + 12u);
    uint32_t num_verts   = MR32(c->esp + 16u);
    uint32_t start_idx   = MR32(c->esp + 20u);
    uint32_t prim_count  = MR32(c->esp + 24u);
    c->esp += 28;

    if (prim_count == 0 || s_bound_indices_id == 0 || s_streams[0].stride == 0) {
        c->eax = D3DERR_INVALIDCALL;
        return;
    }

    d3d9_cmd_draw_indexed_primitive_t cmd;
    cmd.primitive_type = prim_type;
    cmd.base_vertex_index = base_vert;
    cmd.min_vertex_index = min_idx;
    cmd.num_vertices = num_verts;
    cmd.start_index = start_idx;
    cmd.primitive_count = prim_count;
    emit_cmd(D3DCMD_DRAW_INDEXED_PRIMITIVE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_DrawPrimitiveUP(CPU *c) { c->esp += 20; c->eax = D3D_OK; }
void d3d9_dev_shim_DrawIndexedPrimitiveUP(CPU *c) { c->esp += 36; c->eax = D3D_OK; }
void d3d9_dev_shim_ProcessVertices(CPU *c) { c->esp += 28; c->eax = D3D_OK; }

void d3d9_dev_shim_CreateVertexDeclaration(CPU *c) {
    uint32_t ppDecl = MR32(c->esp + 8u);
    c->esp += 12;
    if (ppDecl != 0 && GUEST_MEM_READY) {
        MR32(ppDecl) = 0x02006000u + (s_next_resource_id++ * 16u);
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetVertexDeclaration(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetVertexDeclaration(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_SetFVF(CPU *c) { c->esp += 8; c->eax = D3D_OK; }
void d3d9_dev_shim_GetFVF(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_CreateVertexShader(CPU *c) {
    uint32_t ppShader = MR32(c->esp + 8u);
    c->esp += 12;
    if (ppShader != 0 && GUEST_MEM_READY) {
        MR32(ppShader) = 0x02007000u + (s_next_resource_id++ * 16u);
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetVertexShader(CPU *c) {
    uint32_t pShader = MR32(c->esp + 4u);
    c->esp += 8;
    emit_cmd(D3DCMD_SET_VERTEX_SHADER, &pShader, sizeof(pShader));
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetVertexShader(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_SetVertexShaderConstantF(CPU *c) {
    uint32_t start_reg = MR32(c->esp + 4u);
    uint32_t pData     = MR32(c->esp + 8u);
    uint32_t count     = MR32(c->esp + 12u);
    c->esp += 16;

    if (pData != 0 && count > 0 && GUEST_MEM_READY) {
        d3d9_cmd_set_constants_t cmd = { start_reg, count };
        emit_cmd(D3DCMD_SET_VS_CONSTANTS, &cmd, sizeof(cmd));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetVertexShaderConstantF(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetVertexShaderConstantI(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_GetVertexShaderConstantI(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetVertexShaderConstantB(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_GetVertexShaderConstantB(CPU *c) { c->esp += 16; c->eax = D3D_OK; }

void d3d9_dev_shim_SetStreamSource(CPU *c) {
    uint32_t stream = MR32(c->esp + 4u);
    uint32_t pVB    = MR32(c->esp + 8u);
    uint32_t offset = MR32(c->esp + 12u);
    uint32_t stride = MR32(c->esp + 16u);
    c->esp += 20;

    if (stream < 16) {
        s_streams[stream].buffer_id = pVB ? ((pVB - 0x02002000u) / 32u) : 0u;
        s_streams[stream].offset = offset;
        s_streams[stream].stride = stride;
    }

    d3d9_cmd_set_stream_source_t cmd;
    cmd.stream_number = stream;
    cmd.buffer_id = pVB ? ((pVB - 0x02002000u) / 32u) : 0u;
    cmd.offset = offset;
    cmd.stride = stride;
    emit_cmd(D3DCMD_SET_STREAM_SOURCE, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetStreamSource(CPU *c) { c->esp += 20; c->eax = D3D_OK; }
void d3d9_dev_shim_SetStreamSourceFreq(CPU *c) { c->esp += 12; c->eax = D3D_OK; }
void d3d9_dev_shim_GetStreamSourceFreq(CPU *c) { c->esp += 12; c->eax = D3D_OK; }

void d3d9_dev_shim_SetIndices(CPU *c) {
    uint32_t pIB = MR32(c->esp + 4u);
    c->esp += 8;

    s_bound_indices_id = pIB ? ((pIB - 0x02003000u) / 32u) : 0u;

    d3d9_cmd_set_indices_t cmd;
    cmd.buffer_id = s_bound_indices_id;
    emit_cmd(D3DCMD_SET_INDICES, &cmd, sizeof(cmd));

    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetIndices(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_CreatePixelShader(CPU *c) {
    uint32_t ppShader = MR32(c->esp + 8u);
    c->esp += 12;
    if (ppShader != 0 && GUEST_MEM_READY) {
        MR32(ppShader) = 0x02008000u + (s_next_resource_id++ * 16u);
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_SetPixelShader(CPU *c) {
    uint32_t pShader = MR32(c->esp + 4u);
    c->esp += 8;
    emit_cmd(D3DCMD_SET_PIXEL_SHADER, &pShader, sizeof(pShader));
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetPixelShader(CPU *c) { c->esp += 8; c->eax = D3D_OK; }

void d3d9_dev_shim_SetPixelShaderConstantF(CPU *c) {
    uint32_t start_reg = MR32(c->esp + 4u);
    uint32_t pData     = MR32(c->esp + 8u);
    uint32_t count     = MR32(c->esp + 12u);
    c->esp += 16;

    if (pData != 0 && count > 0 && GUEST_MEM_READY) {
        d3d9_cmd_set_constants_t cmd = { start_reg, count };
        emit_cmd(D3DCMD_SET_PS_CONSTANTS, &cmd, sizeof(cmd));
    }
    c->eax = D3D_OK;
}

void d3d9_dev_shim_GetPixelShaderConstantF(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetPixelShaderConstantI(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_GetPixelShaderConstantI(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_SetPixelShaderConstantB(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_GetPixelShaderConstantB(CPU *c) { c->esp += 16; c->eax = D3D_OK; }
void d3d9_dev_shim_DrawRectPatch(CPU *c) { c->esp += 16; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_DrawTriPatch(CPU *c) { c->esp += 16; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_DeletePatch(CPU *c) { c->esp += 8; c->eax = D3DERR_NOTAVAILABLE; }
void d3d9_dev_shim_CreateQuery(CPU *c) { c->esp += 12; c->eax = D3DERR_NOTAVAILABLE; }

/* Handlers Arrays */
static const guest_fn_t s_d3d9_method_handlers[D3D9_METHOD_TOTAL_COUNT] = {
    d3d9_shim_QueryInterface,
    d3d9_shim_AddRef,
    d3d9_shim_Release,
    d3d9_shim_RegisterSoftwareDevice,
    d3d9_shim_GetAdapterCount,
    d3d9_shim_GetAdapterIdentifier,
    d3d9_shim_GetAdapterModeCount,
    d3d9_shim_EnumAdapterModes,
    d3d9_shim_GetAdapterDisplayMode,
    d3d9_shim_CheckDeviceType,
    d3d9_shim_CheckDeviceFormat,
    d3d9_shim_CheckDeviceMultiSampleType,
    d3d9_shim_CheckDepthStencilMatch,
    d3d9_shim_CheckDeviceFormatConversion,
    d3d9_shim_GetDeviceCaps,
    d3d9_shim_GetAdapterMonitor,
    d3d9_shim_CreateDevice
};

static const guest_fn_t s_device_method_handlers[D3D9_DEV_METHOD_TOTAL_COUNT] = {
    d3d9_dev_shim_QueryInterface,
    d3d9_dev_shim_AddRef,
    d3d9_dev_shim_Release,
    d3d9_dev_shim_TestCooperativeLevel,
    d3d9_dev_shim_GetAvailableTextureMem,
    d3d9_dev_shim_EvictManagedResources,
    d3d9_dev_shim_GetDirect3D,
    d3d9_dev_shim_GetDeviceCaps,
    d3d9_dev_shim_GetDisplayMode,
    d3d9_dev_shim_GetCreationParameters,
    d3d9_dev_shim_SetCursorProperties,
    d3d9_dev_shim_SetCursorPosition,
    d3d9_dev_shim_ShowCursor,
    d3d9_dev_shim_CreateAdditionalSwapChain,
    d3d9_dev_shim_GetSwapChain,
    d3d9_dev_shim_GetNumberOfSwapChains,
    d3d9_dev_shim_Reset,
    d3d9_dev_shim_Present,
    d3d9_dev_shim_GetBackBuffer,
    d3d9_dev_shim_GetRasterStatus,
    d3d9_dev_shim_SetDialogBoxMode,
    d3d9_dev_shim_SetGammaRamp,
    d3d9_dev_shim_GetGammaRamp,
    d3d9_dev_shim_CreateTexture,
    d3d9_dev_shim_CreateVolumeTexture,
    d3d9_dev_shim_CreateCubeTexture,
    d3d9_dev_shim_CreateVertexBuffer,
    d3d9_dev_shim_CreateIndexBuffer,
    d3d9_dev_shim_CreateRenderTarget,
    d3d9_dev_shim_CreateDepthStencilSurface,
    d3d9_dev_shim_UpdateSurface,
    d3d9_dev_shim_UpdateTexture,
    d3d9_dev_shim_GetRenderTargetData,
    d3d9_dev_shim_GetFrontBufferData,
    d3d9_dev_shim_StretchRect,
    d3d9_dev_shim_ColorFill,
    d3d9_dev_shim_CreateOffscreenPlainSurface,
    d3d9_dev_shim_SetRenderTarget,
    d3d9_dev_shim_GetRenderTarget,
    d3d9_dev_shim_SetDepthStencilSurface,
    d3d9_dev_shim_GetDepthStencilSurface,
    d3d9_dev_shim_BeginScene,
    d3d9_dev_shim_EndScene,
    d3d9_dev_shim_Clear,
    d3d9_dev_shim_SetTransform,
    d3d9_dev_shim_GetTransform,
    d3d9_dev_shim_MultiplyTransform,
    d3d9_dev_shim_SetViewport,
    d3d9_dev_shim_GetViewport,
    d3d9_dev_shim_SetMaterial,
    d3d9_dev_shim_GetMaterial,
    d3d9_dev_shim_SetLight,
    d3d9_dev_shim_GetLight,
    d3d9_dev_shim_LightEnable,
    d3d9_dev_shim_GetLightEnable,
    d3d9_dev_shim_SetClipPlane,
    d3d9_dev_shim_GetClipPlane,
    d3d9_dev_shim_SetRenderState,
    d3d9_dev_shim_GetRenderState,
    d3d9_dev_shim_CreateStateBlock,
    d3d9_dev_shim_BeginStateBlock,
    d3d9_dev_shim_EndStateBlock,
    d3d9_dev_shim_SetClipStatus,
    d3d9_dev_shim_GetClipStatus,
    d3d9_dev_shim_GetTexture,
    d3d9_dev_shim_SetTexture,
    d3d9_dev_shim_GetTextureStageState,
    d3d9_dev_shim_SetTextureStageState,
    d3d9_dev_shim_GetSamplerState,
    d3d9_dev_shim_SetSamplerState,
    d3d9_dev_shim_ValidateDevice,
    d3d9_dev_shim_SetPaletteEntries,
    d3d9_dev_shim_GetPaletteEntries,
    d3d9_dev_shim_SetCurrentTexturePalette,
    d3d9_dev_shim_GetCurrentTexturePalette,
    d3d9_dev_shim_SetScissorRect,
    d3d9_dev_shim_GetScissorRect,
    d3d9_dev_shim_SetSoftwareVertexProcessing,
    d3d9_dev_shim_GetSoftwareVertexProcessing,
    d3d9_dev_shim_SetNPatchMode,
    d3d9_dev_shim_GetNPatchMode,
    d3d9_dev_shim_DrawPrimitive,
    d3d9_dev_shim_DrawIndexedPrimitive,
    d3d9_dev_shim_DrawPrimitiveUP,
    d3d9_dev_shim_DrawIndexedPrimitiveUP,
    d3d9_dev_shim_ProcessVertices,
    d3d9_dev_shim_CreateVertexDeclaration,
    d3d9_dev_shim_SetVertexDeclaration,
    d3d9_dev_shim_GetVertexDeclaration,
    d3d9_dev_shim_SetFVF,
    d3d9_dev_shim_GetFVF,
    d3d9_dev_shim_CreateVertexShader,
    d3d9_dev_shim_SetVertexShader,
    d3d9_dev_shim_GetVertexShader,
    d3d9_dev_shim_SetVertexShaderConstantF,
    d3d9_dev_shim_GetVertexShaderConstantF,
    d3d9_dev_shim_SetVertexShaderConstantI,
    d3d9_dev_shim_GetVertexShaderConstantI,
    d3d9_dev_shim_SetVertexShaderConstantB,
    d3d9_dev_shim_GetVertexShaderConstantB,
    d3d9_dev_shim_SetStreamSource,
    d3d9_dev_shim_GetStreamSource,
    d3d9_dev_shim_SetStreamSourceFreq,
    d3d9_dev_shim_GetStreamSourceFreq,
    d3d9_dev_shim_SetIndices,
    d3d9_dev_shim_GetIndices,
    d3d9_dev_shim_CreatePixelShader,
    d3d9_dev_shim_SetPixelShader,
    d3d9_dev_shim_GetPixelShader,
    d3d9_dev_shim_SetPixelShaderConstantF,
    d3d9_dev_shim_GetPixelShaderConstantF,
    d3d9_dev_shim_SetPixelShaderConstantI,
    d3d9_dev_shim_GetPixelShaderConstantI,
    d3d9_dev_shim_SetPixelShaderConstantB,
    d3d9_dev_shim_GetPixelShaderConstantB,
    d3d9_dev_shim_DrawRectPatch,
    d3d9_dev_shim_DrawTriPatch,
    d3d9_dev_shim_DeletePatch,
    d3d9_dev_shim_CreateQuery
};

/* --------------------------------------------------------------------------
 * Subsystem Lifecycle
 * -------------------------------------------------------------------------- */
void d3d9_init_iat(void) {
    /* 1. Bind Direct3DCreate9, D3DXVec3Transform, and D3DXMatrixTranspose IAT slots in .rdata */
    if (GUEST_MEM_READY) {
        MR32(D3D9_DIRECT3DCREATE9_IAT_VA) = D3D9_DIRECT3DCREATE9_IAT_VA;
        MR32(D3DX9_D3DXVEC3TRANSFORM_IAT_VA) = D3DX9_D3DXVEC3TRANSFORM_IAT_VA;
        MR32(D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA) = D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA;

        /* 2. Setup IDirect3D9 COM Vtable at D3D9_VTABLE_VA (0x02001000 in heap) */
        for (uint32_t i = 0; i < D3D9_METHOD_TOTAL_COUNT; ++i) {
            MR32(D3D9_VTABLE_VA + i * 4u) = D3D9_METHOD_BASE_VA + i * 4u;
        }

        /* 3. Setup IDirect3D9 instance at D3D9_INSTANCE_VA (0x02001080 in heap) */
        MR32(D3D9_INSTANCE_VA) = D3D9_VTABLE_VA;
        MR32(D3D9_INSTANCE_VA + 4u) = 1u;

        /* 4. Setup IDirect3DDevice9 COM Vtable at D3D9_DEVICE_VTABLE_VA (0x02001100 in heap) */
        for (uint32_t i = 0; i < D3D9_DEV_METHOD_TOTAL_COUNT; ++i) {
            MR32(D3D9_DEVICE_VTABLE_VA + i * 4u) = D3D9_DEVICE_METHOD_BASE_VA + i * 4u;
        }

        /* 5. Setup IDirect3DDevice9 instance at D3D9_DEVICE_INSTANCE_VA (0x02001300 in heap) */
        MR32(D3D9_DEVICE_INSTANCE_VA) = D3D9_DEVICE_VTABLE_VA;
        MR32(D3D9_DEVICE_INSTANCE_VA + 4u) = 0u; /* initial device inactive */
    }

    /* 6. Bind Direct3DCreate9, D3DXVec3Transform, and D3DXMatrixTranspose into g_dtab */
    uint32_t create_idx = D3D9_DIRECT3DCREATE9_IAT_VA - DISPATCH_TEXT_BASE;
    if (create_idx < DISPATCH_TEXT_SIZE) {
        g_dtab[create_idx] = d3d9_shim_Direct3DCreate9;
    }
    uint32_t vec3trans_idx = D3DX9_D3DXVEC3TRANSFORM_IAT_VA - DISPATCH_TEXT_BASE;
    if (vec3trans_idx < DISPATCH_TEXT_SIZE) {
        g_dtab[vec3trans_idx] = d3d9_shim_D3DXVec3Transform;
    }
    uint32_t transpose_idx = D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA - DISPATCH_TEXT_BASE;
    if (transpose_idx < DISPATCH_TEXT_SIZE) {
        g_dtab[transpose_idx] = d3d9_shim_D3DXMatrixTranspose;
    }

    /* 7. Bind all 17 IDirect3D9 COM vtable methods into g_dtab */
    for (uint32_t i = 0; i < D3D9_METHOD_TOTAL_COUNT; ++i) {
        uint32_t m_va = D3D9_METHOD_BASE_VA + i * 4u;
        uint32_t idx = m_va - DISPATCH_TEXT_BASE;
        if (idx < DISPATCH_TEXT_SIZE) {
            g_dtab[idx] = s_d3d9_method_handlers[i];
        }
    }

    /* 8. Bind all 119 IDirect3DDevice9 COM vtable methods into g_dtab */
    for (uint32_t i = 0; i < D3D9_DEV_METHOD_TOTAL_COUNT; ++i) {
        uint32_t m_va = D3D9_DEVICE_METHOD_BASE_VA + i * 4u;
        uint32_t idx = m_va - DISPATCH_TEXT_BASE;
        if (idx < DISPATCH_TEXT_SIZE) {
            g_dtab[idx] = s_device_method_handlers[i];
        }
    }

    s_d3d9_ref_count = 1u;
    s_d3d9_active = true;
    s_device_ref_count = 0u;
    s_device_active = false;
    s_bound_indices_id = 0u;
    memset(s_streams, 0, sizeof(s_streams));
    memset(s_textures, 0, sizeof(s_textures));
    memset(s_render_states, 0, sizeof(s_render_states));
}

void d3d9_reset(void) {
    s_d3d9_ref_count = 0;
    s_d3d9_active = false;
    s_device_ref_count = 0;
    s_device_active = false;
    s_bound_indices_id = 0;
    memset(s_streams, 0, sizeof(s_streams));
    memset(s_textures, 0, sizeof(s_textures));
    memset(s_render_states, 0, sizeof(s_render_states));
}

uint32_t d3d9_get_ref_count(void) {
    return s_d3d9_ref_count;
}

uint32_t d3d9_device_get_ref_count(void) {
    return s_device_ref_count;
}

bool d3d9_is_instance_active(void) {
    return s_d3d9_active;
}

bool d3d9_is_device_active(void) {
    return s_device_active;
}
