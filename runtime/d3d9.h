/* Need for Speed ProStreet - Direct3D 9 COM Interface Shim Header.
 *
 * Implements Direct3DCreate9 entrypoint, IDirect3D9 COM vtable (17 methods),
 * and IDirect3DDevice9 COM vtable (119 methods) with authentic Win32 __stdcall
 * stack discipline, lock-free ring buffer command serialization, and 1:1 guest memory.
 */
#ifndef PROSTREET_D3D9_H
#define PROSTREET_D3D9_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cpu.h"
#include "d3d9_cmd.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Memory Layout Constants for Direct3D 9
 * All vtables and instances reside in the guest heap (0x02000000..0x28000000),
 * leaving the authentic PE sections (0x00400000..0x01f687e2) 100% unmodified.
 * Synthetic method addresses map to unused g_dtab slots in the .text dispatch range.
 * -------------------------------------------------------------------------- */
#define D3D9_DIRECT3DCREATE9_IAT_VA     0x009675bcu   /* Authentic PE IAT VA in nfs.exe */
#define D3DX9_D3DXVEC3TRANSFORM_IAT_VA  0x009675dcu   /* Authentic PE IAT VA in nfs.exe (d3dx9_34.dll) */
#define D3DX9_D3DXMATRIXTRANSPOSE_IAT_VA 0x009675f4u  /* Authentic PE IAT VA in nfs.exe (d3dx9_34.dll) */

/* Synthetic method entry points in g_dtab */
#define D3D9_METHOD_BASE_VA             0x00966500u   /* 17 IDirect3D9 methods (0x00966500..0x00966540) */
#define D3D9_DEVICE_METHOD_BASE_VA      0x00966600u   /* 119 IDirect3DDevice9 methods (0x00966600..0x009667dc) */

/* Dedicated D3D9 reservation structures (0x27800000..0x28000000, 8 MB) */
#define D3D9_VTABLE_VA                  0x27801000u   /* 17 IDirect3D9 pointers (68 bytes) */
#define D3D9_INSTANCE_VA                0x27801080u   /* IDirect3D9 instance (vptr + ref_count) */
#define D3D9_DEVICE_VTABLE_VA           0x27801100u   /* 119 IDirect3DDevice9 pointers (476 bytes) */
#define D3D9_DEVICE_INSTANCE_VA         0x27801300u   /* IDirect3DDevice9 instance (32 bytes) */
#define D3D9_RING_BUFFER_VA             0x27810000u   /* Shared memory command ring buffer (4 MB) */

#define D3D_SDK_VERSION                 32u

/* Direct3D 9 Error & Status Codes */
#define D3D_OK                          0x00000000u
#define D3DERR_NOTAVAILABLE             0x8876086Au
#define D3DERR_INVALIDCALL              0x8876086Cu
#define E_NOINTERFACE                   0x80004002u
#define E_POINTER                       0x80004003u
#define E_NOTIMPL                       0x80004001u

/* Standard Formats */
#define D3DFMT_R8G8B8                   20u
#define D3DFMT_A8R8G8B8                 21u
#define D3DFMT_X8R8G8B8                 22u
#define D3DFMT_R5G6B5                   23u
#define D3DFMT_D24S8                    75u
#define D3DFMT_INDEX16                  101u
#define D3DFMT_INDEX32                  102u
#define D3DFMT_DXT1                     0x31545844u
#define D3DFMT_DXT2                     0x32545844u
#define D3DFMT_DXT3                     0x33545844u
#define D3DFMT_DXT4                     0x34545844u
#define D3DFMT_DXT5                     0x35545844u

/* --------------------------------------------------------------------------
 * D3DADAPTER_IDENTIFIER9 (Authentic 1,100-byte Win32 ABI layout)
 * -------------------------------------------------------------------------- */
typedef struct {
    char     driver[512];           /* Offset 0    (512 bytes) */
    char     description[512];      /* Offset 512  (512 bytes) */
    char     device_name[32];       /* Offset 1024 (32 bytes)  */
    uint64_t driver_version;        /* Offset 1056 (8 bytes)   */
    uint32_t vendor_id;             /* Offset 1064 (4 bytes)   */
    uint32_t device_id;             /* Offset 1068 (4 bytes)   */
    uint32_t subsys_id;             /* Offset 1072 (4 bytes)   */
    uint32_t revision;              /* Offset 1076 (4 bytes)   */
    uint8_t  device_identifier[16]; /* Offset 1080 (16 bytes)  */
    uint32_t whql_level;            /* Offset 1096 (4 bytes)   */
} d3d9_adapter_identifier9_t;       /* Total size: 1100 bytes */

/* --------------------------------------------------------------------------
 * IDirect3D9 Method Indices (17 methods)
 * -------------------------------------------------------------------------- */
typedef enum {
    D3D9_METHOD_QUERY_INTERFACE             = 0,
    D3D9_METHOD_ADD_REF                     = 1,
    D3D9_METHOD_RELEASE                     = 2,
    D3D9_METHOD_REGISTER_SOFTWARE_DEVICE    = 3,
    D3D9_METHOD_GET_ADAPTER_COUNT           = 4,
    D3D9_METHOD_GET_ADAPTER_IDENTIFIER      = 5,
    D3D9_METHOD_GET_ADAPTER_MODE_COUNT      = 6,
    D3D9_METHOD_ENUM_ADAPTER_MODES          = 7,
    D3D9_METHOD_GET_ADAPTER_DISPLAY_MODE    = 8,
    D3D9_METHOD_CHECK_DEVICE_TYPE           = 9,
    D3D9_METHOD_CHECK_DEVICE_FORMAT         = 10,
    D3D9_METHOD_CHECK_DEVICE_MULTI_SAMPLE   = 11,
    D3D9_METHOD_CHECK_DEPTH_STENCIL_MATCH   = 12,
    D3D9_METHOD_CHECK_DEVICE_FORMAT_CONV    = 13,
    D3D9_METHOD_GET_DEVICE_CAPS             = 14,
    D3D9_METHOD_GET_ADAPTER_MONITOR         = 15,
    D3D9_METHOD_CREATE_DEVICE               = 16,
    D3D9_METHOD_TOTAL_COUNT                 = 17
} d3d9_method_index_t;

/* --------------------------------------------------------------------------
 * IDirect3DDevice9 Method Indices (119 methods)
 * -------------------------------------------------------------------------- */
typedef enum {
    D3D9_DEV_METHOD_QUERY_INTERFACE             = 0,
    D3D9_DEV_METHOD_ADD_REF                     = 1,
    D3D9_DEV_METHOD_RELEASE                     = 2,
    D3D9_DEV_METHOD_TEST_COOPERATIVE_LEVEL      = 3,
    D3D9_DEV_METHOD_GET_AVAILABLE_TEXTURE_MEM   = 4,
    D3D9_DEV_METHOD_EVICT_MANAGED_RESOURCES     = 5,
    D3D9_DEV_METHOD_GET_DIRECT3D                = 6,
    D3D9_DEV_METHOD_GET_DEVICE_CAPS             = 7,
    D3D9_DEV_METHOD_GET_DISPLAY_MODE            = 8,
    D3D9_DEV_METHOD_GET_CREATION_PARAMETERS     = 9,
    D3D9_DEV_METHOD_SET_CURSOR_PROPERTIES       = 10,
    D3D9_DEV_METHOD_SET_CURSOR_POSITION         = 11,
    D3D9_DEV_METHOD_SHOW_CURSOR                 = 12,
    D3D9_DEV_METHOD_CREATE_ADDITIONAL_SWAP_CHAIN= 13,
    D3D9_DEV_METHOD_GET_SWAP_CHAIN              = 14,
    D3D9_DEV_METHOD_GET_NUMBER_OF_SWAP_CHAINS   = 15,
    D3D9_DEV_METHOD_RESET                       = 16,
    D3D9_DEV_METHOD_PRESENT                     = 17,
    D3D9_DEV_METHOD_GET_BACK_BUFFER             = 18,
    D3D9_DEV_METHOD_GET_RASTER_STATUS           = 19,
    D3D9_DEV_METHOD_SET_DIALOG_BOX_MODE         = 20,
    D3D9_DEV_METHOD_SET_GAMMA_RAMP              = 21,
    D3D9_DEV_METHOD_GET_GAMMA_RAMP              = 22,
    D3D9_DEV_METHOD_CREATE_TEXTURE              = 23,
    D3D9_DEV_METHOD_CREATE_VOLUME_TEXTURE       = 24,
    D3D9_DEV_METHOD_CREATE_CUBE_TEXTURE         = 25,
    D3D9_DEV_METHOD_CREATE_VERTEX_BUFFER        = 26,
    D3D9_DEV_METHOD_CREATE_INDEX_BUFFER         = 27,
    D3D9_DEV_METHOD_CREATE_RENDER_TARGET        = 28,
    D3D9_DEV_METHOD_CREATE_DEPTH_STENCIL_SURFACE= 29,
    D3D9_DEV_METHOD_UPDATE_SURFACE              = 30,
    D3D9_DEV_METHOD_UPDATE_TEXTURE              = 31,
    D3D9_DEV_METHOD_GET_RENDER_TARGET_DATA      = 32,
    D3D9_DEV_METHOD_GET_FRONT_BUFFER_DATA       = 33,
    D3D9_DEV_METHOD_STRETCH_RECT                = 34,
    D3D9_DEV_METHOD_COLOR_FILL                  = 35,
    D3D9_DEV_METHOD_CREATE_OFFSCREEN_PLAIN_SURF = 36,
    D3D9_DEV_METHOD_SET_RENDER_TARGET           = 37,
    D3D9_DEV_METHOD_GET_RENDER_TARGET           = 38,
    D3D9_DEV_METHOD_SET_DEPTH_STENCIL_SURFACE   = 39,
    D3D9_DEV_METHOD_GET_DEPTH_STENCIL_SURFACE   = 40,
    D3D9_DEV_METHOD_BEGIN_SCENE                 = 41,
    D3D9_DEV_METHOD_END_SCENE                   = 42,
    D3D9_DEV_METHOD_CLEAR                       = 43,
    D3D9_DEV_METHOD_SET_TRANSFORM               = 44,
    D3D9_DEV_METHOD_GET_TRANSFORM               = 45,
    D3D9_DEV_METHOD_MULTIPLY_TRANSFORM          = 46,
    D3D9_DEV_METHOD_SET_VIEWPORT                = 47,
    D3D9_DEV_METHOD_GET_VIEWPORT                = 48,
    D3D9_DEV_METHOD_SET_MATERIAL                = 49,
    D3D9_DEV_METHOD_GET_MATERIAL                = 50,
    D3D9_DEV_METHOD_SET_LIGHT                   = 51,
    D3D9_DEV_METHOD_GET_LIGHT                   = 52,
    D3D9_DEV_METHOD_LIGHT_ENABLE                = 53,
    D3D9_DEV_METHOD_GET_LIGHT_ENABLE            = 54,
    D3D9_DEV_METHOD_SET_CLIP_PLANE              = 55,
    D3D9_DEV_METHOD_GET_CLIP_PLANE              = 56,
    D3D9_DEV_METHOD_SET_RENDER_STATE            = 57,
    D3D9_DEV_METHOD_GET_RENDER_STATE            = 58,
    D3D9_DEV_METHOD_CREATE_STATE_BLOCK          = 59,
    D3D9_DEV_METHOD_BEGIN_STATE_BLOCK           = 60,
    D3D9_DEV_METHOD_END_STATE_BLOCK             = 61,
    D3D9_DEV_METHOD_SET_CLIP_STATUS             = 62,
    D3D9_DEV_METHOD_GET_CLIP_STATUS             = 63,
    D3D9_DEV_METHOD_GET_TEXTURE                 = 64,
    D3D9_DEV_METHOD_SET_TEXTURE                 = 65,
    D3D9_DEV_METHOD_GET_TEXTURE_STAGE_STATE     = 66,
    D3D9_DEV_METHOD_SET_TEXTURE_STAGE_STATE     = 67,
    D3D9_DEV_METHOD_GET_SAMPLER_STATE           = 68,
    D3D9_DEV_METHOD_SET_SAMPLER_STATE           = 69,
    D3D9_DEV_METHOD_VALIDATE_DEVICE             = 70,
    D3D9_DEV_METHOD_SET_PALETTE_ENTRIES         = 71,
    D3D9_DEV_METHOD_GET_PALETTE_ENTRIES         = 72,
    D3D9_DEV_METHOD_SET_CURRENT_TEXTURE_PALETTE = 73,
    D3D9_DEV_METHOD_GET_CURRENT_TEXTURE_PALETTE = 74,
    D3D9_DEV_METHOD_SET_SCISSOR_RECT            = 75,
    D3D9_DEV_METHOD_GET_SCISSOR_RECT            = 76,
    D3D9_DEV_METHOD_SET_SOFTWARE_VERTEX_PROCESS = 77,
    D3D9_DEV_METHOD_GET_SOFTWARE_VERTEX_PROCESS = 78,
    D3D9_DEV_METHOD_SET_NPATCH_MODE             = 79,
    D3D9_DEV_METHOD_GET_NPATCH_MODE             = 80,
    D3D9_DEV_METHOD_DRAW_PRIMITIVE              = 81,
    D3D9_DEV_METHOD_DRAW_INDEXED_PRIMITIVE      = 82,
    D3D9_DEV_METHOD_DRAW_PRIMITIVE_UP           = 83,
    D3D9_DEV_METHOD_DRAW_INDEXED_PRIMITIVE_UP   = 84,
    D3D9_DEV_METHOD_PROCESS_VERTICES            = 85,
    D3D9_DEV_METHOD_CREATE_VERTEX_DECLARATION   = 86,
    D3D9_DEV_METHOD_SET_VERTEX_DECLARATION      = 87,
    D3D9_DEV_METHOD_GET_VERTEX_DECLARATION      = 88,
    D3D9_DEV_METHOD_SET_FVF                     = 89,
    D3D9_DEV_METHOD_GET_FVF                     = 90,
    D3D9_DEV_METHOD_CREATE_VERTEX_SHADER        = 91,
    D3D9_DEV_METHOD_SET_VERTEX_SHADER           = 92,
    D3D9_DEV_METHOD_GET_VERTEX_SHADER           = 93,
    D3D9_DEV_METHOD_SET_VS_CONSTANT_F           = 94,
    D3D9_DEV_METHOD_GET_VS_CONSTANT_F           = 95,
    D3D9_DEV_METHOD_SET_VS_CONSTANT_I           = 96,
    D3D9_DEV_METHOD_GET_VS_CONSTANT_I           = 97,
    D3D9_DEV_METHOD_SET_VS_CONSTANT_B           = 98,
    D3D9_DEV_METHOD_GET_VS_CONSTANT_B           = 99,
    D3D9_DEV_METHOD_SET_STREAM_SOURCE           = 100,
    D3D9_DEV_METHOD_GET_STREAM_SOURCE           = 101,
    D3D9_DEV_METHOD_SET_STREAM_SOURCE_FREQ      = 102,
    D3D9_DEV_METHOD_GET_STREAM_SOURCE_FREQ      = 103,
    D3D9_DEV_METHOD_SET_INDICES                 = 104,
    D3D9_DEV_METHOD_GET_INDICES                 = 105,
    D3D9_DEV_METHOD_CREATE_PIXEL_SHADER         = 106,
    D3D9_DEV_METHOD_SET_PIXEL_SHADER            = 107,
    D3D9_DEV_METHOD_GET_PIXEL_SHADER            = 108,
    D3D9_DEV_METHOD_SET_PS_CONSTANT_F           = 109,
    D3D9_DEV_METHOD_GET_PS_CONSTANT_F           = 110,
    D3D9_DEV_METHOD_SET_PS_CONSTANT_I           = 111,
    D3D9_DEV_METHOD_GET_PS_CONSTANT_I           = 112,
    D3D9_DEV_METHOD_SET_PS_CONSTANT_B           = 113,
    D3D9_DEV_METHOD_GET_PS_CONSTANT_B           = 114,
    D3D9_DEV_METHOD_DRAW_RECT_PATCH             = 115,
    D3D9_DEV_METHOD_DRAW_TRI_PATCH              = 116,
    D3D9_DEV_METHOD_DELETE_PATCH                = 117,
    D3D9_DEV_METHOD_CREATE_QUERY                = 118,
    D3D9_DEV_METHOD_TOTAL_COUNT                 = 119
} d3d9_dev_method_index_t;

/* --------------------------------------------------------------------------
 * Direct3D 9 Entrypoint and Shim Functions
 * -------------------------------------------------------------------------- */
void d3d9_shim_Direct3DCreate9(struct CPU *c);
void d3d9_shim_D3DXVec3Transform(struct CPU *c);
void d3d9_shim_D3DXMatrixTranspose(struct CPU *c);

/* IDirect3D9 COM vtable method shims (17 methods) */
void d3d9_shim_QueryInterface(struct CPU *c);
void d3d9_shim_AddRef(struct CPU *c);
void d3d9_shim_Release(struct CPU *c);
void d3d9_shim_RegisterSoftwareDevice(struct CPU *c);
void d3d9_shim_GetAdapterCount(struct CPU *c);
void d3d9_shim_GetAdapterIdentifier(struct CPU *c);
void d3d9_shim_GetAdapterModeCount(struct CPU *c);
void d3d9_shim_EnumAdapterModes(struct CPU *c);
void d3d9_shim_GetAdapterDisplayMode(struct CPU *c);
void d3d9_shim_CheckDeviceType(struct CPU *c);
void d3d9_shim_CheckDeviceFormat(struct CPU *c);
void d3d9_shim_CheckDeviceMultiSampleType(struct CPU *c);
void d3d9_shim_CheckDepthStencilMatch(struct CPU *c);
void d3d9_shim_CheckDeviceFormatConversion(struct CPU *c);
void d3d9_shim_GetDeviceCaps(struct CPU *c);
void d3d9_shim_GetAdapterMonitor(struct CPU *c);
void d3d9_shim_CreateDevice(struct CPU *c);

/* IDirect3DDevice9 COM vtable method shims (119 methods) */
void d3d9_dev_shim_QueryInterface(struct CPU *c);
void d3d9_dev_shim_AddRef(struct CPU *c);
void d3d9_dev_shim_Release(struct CPU *c);
void d3d9_dev_shim_TestCooperativeLevel(struct CPU *c);
void d3d9_dev_shim_GetAvailableTextureMem(struct CPU *c);
void d3d9_dev_shim_EvictManagedResources(struct CPU *c);
void d3d9_dev_shim_GetDirect3D(struct CPU *c);
void d3d9_dev_shim_GetDeviceCaps(struct CPU *c);
void d3d9_dev_shim_GetDisplayMode(struct CPU *c);
void d3d9_dev_shim_GetCreationParameters(struct CPU *c);
void d3d9_dev_shim_SetCursorProperties(struct CPU *c);
void d3d9_dev_shim_SetCursorPosition(struct CPU *c);
void d3d9_dev_shim_ShowCursor(struct CPU *c);
void d3d9_dev_shim_CreateAdditionalSwapChain(struct CPU *c);
void d3d9_dev_shim_GetSwapChain(struct CPU *c);
void d3d9_dev_shim_GetNumberOfSwapChains(struct CPU *c);
void d3d9_dev_shim_Reset(struct CPU *c);
void d3d9_dev_shim_Present(struct CPU *c);
void d3d9_dev_shim_GetBackBuffer(struct CPU *c);
void d3d9_dev_shim_GetRasterStatus(struct CPU *c);
void d3d9_dev_shim_SetDialogBoxMode(struct CPU *c);
void d3d9_dev_shim_SetGammaRamp(struct CPU *c);
void d3d9_dev_shim_GetGammaRamp(struct CPU *c);
void d3d9_dev_shim_CreateTexture(struct CPU *c);
void d3d9_dev_shim_CreateVolumeTexture(struct CPU *c);
void d3d9_dev_shim_CreateCubeTexture(struct CPU *c);
void d3d9_dev_shim_CreateVertexBuffer(struct CPU *c);
void d3d9_dev_shim_CreateIndexBuffer(struct CPU *c);
void d3d9_dev_shim_CreateRenderTarget(struct CPU *c);
void d3d9_dev_shim_CreateDepthStencilSurface(struct CPU *c);
void d3d9_dev_shim_UpdateSurface(struct CPU *c);
void d3d9_dev_shim_UpdateTexture(struct CPU *c);
void d3d9_dev_shim_GetRenderTargetData(struct CPU *c);
void d3d9_dev_shim_GetFrontBufferData(struct CPU *c);
void d3d9_dev_shim_StretchRect(struct CPU *c);
void d3d9_dev_shim_ColorFill(struct CPU *c);
void d3d9_dev_shim_CreateOffscreenPlainSurface(struct CPU *c);
void d3d9_dev_shim_SetRenderTarget(struct CPU *c);
void d3d9_dev_shim_GetRenderTarget(struct CPU *c);
void d3d9_dev_shim_SetDepthStencilSurface(struct CPU *c);
void d3d9_dev_shim_GetDepthStencilSurface(struct CPU *c);
void d3d9_dev_shim_BeginScene(struct CPU *c);
void d3d9_dev_shim_EndScene(struct CPU *c);
void d3d9_dev_shim_Clear(struct CPU *c);
void d3d9_dev_shim_SetTransform(struct CPU *c);
void d3d9_dev_shim_GetTransform(struct CPU *c);
void d3d9_dev_shim_MultiplyTransform(struct CPU *c);
void d3d9_dev_shim_SetViewport(struct CPU *c);
void d3d9_dev_shim_GetViewport(struct CPU *c);
void d3d9_dev_shim_SetMaterial(struct CPU *c);
void d3d9_dev_shim_GetMaterial(struct CPU *c);
void d3d9_dev_shim_SetLight(struct CPU *c);
void d3d9_dev_shim_GetLight(struct CPU *c);
void d3d9_dev_shim_LightEnable(struct CPU *c);
void d3d9_dev_shim_GetLightEnable(struct CPU *c);
void d3d9_dev_shim_SetClipPlane(struct CPU *c);
void d3d9_dev_shim_GetClipPlane(struct CPU *c);
void d3d9_dev_shim_SetRenderState(struct CPU *c);
void d3d9_dev_shim_GetRenderState(struct CPU *c);
void d3d9_dev_shim_CreateStateBlock(struct CPU *c);
void d3d9_dev_shim_BeginStateBlock(struct CPU *c);
void d3d9_dev_shim_EndStateBlock(struct CPU *c);
void d3d9_dev_shim_SetClipStatus(struct CPU *c);
void d3d9_dev_shim_GetClipStatus(struct CPU *c);
void d3d9_dev_shim_GetTexture(struct CPU *c);
void d3d9_dev_shim_SetTexture(struct CPU *c);
void d3d9_dev_shim_GetTextureStageState(struct CPU *c);
void d3d9_dev_shim_SetTextureStageState(struct CPU *c);
void d3d9_dev_shim_GetSamplerState(struct CPU *c);
void d3d9_dev_shim_SetSamplerState(struct CPU *c);
void d3d9_dev_shim_ValidateDevice(struct CPU *c);
void d3d9_dev_shim_SetPaletteEntries(struct CPU *c);
void d3d9_dev_shim_GetPaletteEntries(struct CPU *c);
void d3d9_dev_shim_SetCurrentTexturePalette(struct CPU *c);
void d3d9_dev_shim_GetCurrentTexturePalette(struct CPU *c);
void d3d9_dev_shim_SetScissorRect(struct CPU *c);
void d3d9_dev_shim_GetScissorRect(struct CPU *c);
void d3d9_dev_shim_SetSoftwareVertexProcessing(struct CPU *c);
void d3d9_dev_shim_GetSoftwareVertexProcessing(struct CPU *c);
void d3d9_dev_shim_SetNPatchMode(struct CPU *c);
void d3d9_dev_shim_GetNPatchMode(struct CPU *c);
void d3d9_dev_shim_DrawPrimitive(struct CPU *c);
void d3d9_dev_shim_DrawIndexedPrimitive(struct CPU *c);
void d3d9_dev_shim_DrawPrimitiveUP(struct CPU *c);
void d3d9_dev_shim_DrawIndexedPrimitiveUP(struct CPU *c);
void d3d9_dev_shim_ProcessVertices(struct CPU *c);
void d3d9_dev_shim_CreateVertexDeclaration(struct CPU *c);
void d3d9_dev_shim_SetVertexDeclaration(struct CPU *c);
void d3d9_dev_shim_GetVertexDeclaration(struct CPU *c);
void d3d9_dev_shim_SetFVF(struct CPU *c);
void d3d9_dev_shim_GetFVF(struct CPU *c);
void d3d9_dev_shim_CreateVertexShader(struct CPU *c);
void d3d9_dev_shim_SetVertexShader(struct CPU *c);
void d3d9_dev_shim_GetVertexShader(struct CPU *c);
void d3d9_dev_shim_SetVertexShaderConstantF(struct CPU *c);
void d3d9_dev_shim_GetVertexShaderConstantF(struct CPU *c);
void d3d9_dev_shim_SetVertexShaderConstantI(struct CPU *c);
void d3d9_dev_shim_GetVertexShaderConstantI(struct CPU *c);
void d3d9_dev_shim_SetVertexShaderConstantB(struct CPU *c);
void d3d9_dev_shim_GetVertexShaderConstantB(struct CPU *c);
void d3d9_dev_shim_SetStreamSource(struct CPU *c);
void d3d9_dev_shim_GetStreamSource(struct CPU *c);
void d3d9_dev_shim_SetStreamSourceFreq(struct CPU *c);
void d3d9_dev_shim_GetStreamSourceFreq(struct CPU *c);
void d3d9_dev_shim_SetIndices(struct CPU *c);
void d3d9_dev_shim_GetIndices(struct CPU *c);
void d3d9_dev_shim_CreatePixelShader(struct CPU *c);
void d3d9_dev_shim_SetPixelShader(struct CPU *c);
void d3d9_dev_shim_GetPixelShader(struct CPU *c);
void d3d9_dev_shim_SetPixelShaderConstantF(struct CPU *c);
void d3d9_dev_shim_GetPixelShaderConstantF(struct CPU *c);
void d3d9_dev_shim_SetPixelShaderConstantI(struct CPU *c);
void d3d9_dev_shim_GetPixelShaderConstantI(struct CPU *c);
void d3d9_dev_shim_SetPixelShaderConstantB(struct CPU *c);
void d3d9_dev_shim_GetPixelShaderConstantB(struct CPU *c);
void d3d9_dev_shim_DrawRectPatch(struct CPU *c);
void d3d9_dev_shim_DrawTriPatch(struct CPU *c);
void d3d9_dev_shim_DeletePatch(struct CPU *c);
void d3d9_dev_shim_CreateQuery(struct CPU *c);

/* Subsystem Lifecycle */
void d3d9_init_iat(void);
void d3d9_reset(void);
uint32_t d3d9_get_ref_count(void);
uint32_t d3d9_device_get_ref_count(void);
bool d3d9_is_instance_active(void);
bool d3d9_is_device_active(void);

#ifdef __cplusplus
}
#endif

#endif /* PROSTREET_D3D9_H */
