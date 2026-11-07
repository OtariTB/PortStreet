/* Need for Speed ProStreet - 1:1 Linear Guest Memory Layout.
 *
 * Implements the 32-bit WebAssembly linear address space mapping for ProStreet:
 * - 0x00000000..0x00100000: Null-page guard.
 * - 0x00100000..0x00200000: TEB & TLS storage.
 * - 0x00200000..0x00400000: 2 MB Guest stack (ESP initialized to 0x003FF000).
 * - 0x00401000..0x00967000: .text (code & function table references).
 * - 0x00967000..0x00a4a000: Authentic .rdata (vtables, strings, IAT, initializer tables).
 * - 0x00a4a000..0x01010000: Authentic .data (global state and zero-initialized BSS).
 * - 0x01010000..0x01011000: .tls (TLS template).
 * - 0x01011000..0x010ea000: .rsrc (34 D3DX .fx shaders, icon, version info).
 * - 0x010ea000..0x01f687e2: SecuROM / DRM wrapper sections (ars, est, artem, celare, .securom).
 * - 0x02000000..0x28000000: Dynamic guest heap (VirtualAlloc / malloc arena, up to 640 MB).
 */
#ifndef PROSTREET_MEMORY_H
#define PROSTREET_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Memory Layout Constants
 * -------------------------------------------------------------------------- */
#define GUEST_PAGE_SIZE          0x1000u       /* 4 KiB */
#define GUEST_NULL_GUARD_LIMIT   0x00100000u   /* 0..1 MB guarded against nullptr */
#define GUEST_TEB_ADDR           0x00100000u   /* Main Thread Environment Block */
#define GUEST_MAIN_TLS_COPY_ADDR 0x00102000u   /* Main Thread 4 KiB .tls copy */
#define GUEST_CPU_STRUCT_ADDR    0x00104000u   /* Main host guest CPU register structure */

#define GUEST_MAX_WORKERS              8u
#define GUEST_WORKER_CPU_STRIDE        0x00000400u /* 1 KiB per CPU struct */
#define GUEST_WORKER_TEB_STRIDE        0x00001000u /* 4 KiB per Worker TEB */
#define GUEST_WORKER_TLS_BASE          0x00110000u /* 8 * 4 KiB Worker .tls copies */
#define GUEST_WORKER_STACK_REGION_BASE 0x00140000u /* 8 * 96 KiB Worker x86 stacks (..0x00200000) */
#define GUEST_WORKER_STACK_STRIDE      0x00018000u /* 96 KiB per Worker x86 stack */

#define GUEST_WORKER_CPU_ADDR_N(i)          (0x00105000u + (uint32_t)(i) * GUEST_WORKER_CPU_STRIDE)
#define GUEST_WORKER_MAILBOX_VA             0x00107000u /* Shared atomic mailbox for 8 guest workers (4 KiB) */
#define GUEST_WORKER_TEB_ADDR_N(i)          (0x00108000u + (uint32_t)(i) * GUEST_WORKER_TEB_STRIDE)
#define GUEST_WORKER_TLS_ADDR_N(i)          (GUEST_WORKER_TLS_BASE + (uint32_t)(i) * 0x1000u)
#define GUEST_WORKER_STACK_BOTTOM_N(i)      (GUEST_WORKER_STACK_REGION_BASE + (uint32_t)(i) * GUEST_WORKER_STACK_STRIDE)
#define GUEST_WORKER_STACK_TOP_N(i)         (GUEST_WORKER_STACK_BOTTOM_N(i) + GUEST_WORKER_STACK_STRIDE - 0x10u)

#define GUEST_WORKER_CPU_ADDR    GUEST_WORKER_CPU_ADDR_N(0)
#define GUEST_WORKER_TEB_ADDR    GUEST_WORKER_TEB_ADDR_N(0)
#define GUEST_WORKER_STACK_BOTTOM GUEST_WORKER_STACK_BOTTOM_N(0)
#define GUEST_WORKER_STACK_TOP   GUEST_WORKER_STACK_TOP_N(0)

#define GUEST_STACK_BOTTOM       0x00200000u   /* Main Stack base (2 MB) */
#define GUEST_STACK_TOP          0x003FF000u   /* Main Initial ESP (stack grows down) */
#define GUEST_IMAGE_BASE         0x00400000u   /* PE Image Base */

#define GUEST_TEXT_START         0x00401000u
#define GUEST_TEXT_END           0x00967000u
#define GUEST_RDATA_START        0x00967000u
#define GUEST_RDATA_END          0x00a4a000u
#define GUEST_DATA_START         0x00a4a000u
#define GUEST_DATA_END           0x01010000u
#define GUEST_TLS_START          0x01010000u
#define GUEST_TLS_END            0x01011000u
#define GUEST_RSRC_START         0x01011000u
#define GUEST_RSRC_END           0x010ea000u
#define GUEST_IMAGE_END          0x01f687e2u

#define GUEST_HEAP_START         0x02000000u   /* Dynamic heap arena starts at 32 MB */
#define GUEST_HEAP_LIMIT         0x27800000u   /* Allocator upper bound (632 MB mark) */

/* --------------------------------------------------------------------------
 * Dedicated D3D9 Runtime Command Ring & COM Infrastructure Reservation
 * Genuinely non-overlapping with dynamic heap [0x27800000..0x28000000] (8 MB)
 * -------------------------------------------------------------------------- */
#define GUEST_D3D9_RESERVE_START 0x27800000u   /* Dedicated D3D9 runtime reservation */
#define GUEST_D3D9_RESERVE_END   GUEST_END     /* 0x28000000 (640 MB boundary) */
#define GUEST_D3D9_RESERVE_SIZE  (GUEST_D3D9_RESERVE_END - GUEST_D3D9_RESERVE_START) /* 8 MB */

/* --------------------------------------------------------------------------
 * Win32 VirtualAlloc Allocation Type & Protection Flags
 * -------------------------------------------------------------------------- */
#define GUEST_MEM_COMMIT         0x00001000u
#define GUEST_MEM_RESERVE        0x00002000u
#define GUEST_MEM_DECOMMIT       0x00004000u
#define GUEST_MEM_RELEASE        0x00008000u
#define GUEST_MEM_RESET          0x00080000u

#define GUEST_PAGE_NOACCESS      0x01u
#define GUEST_PAGE_READONLY      0x02u
#define GUEST_PAGE_READWRITE     0x04u
#define GUEST_PAGE_EXECUTE       0x10u
#define GUEST_PAGE_EXECUTE_READ  0x20u
#define GUEST_PAGE_EXECUTE_RW    0x40u

/* --------------------------------------------------------------------------
 * Section Metadata Record
 * -------------------------------------------------------------------------- */
typedef struct {
    char     name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t flags;
} guest_section_t;

/* --------------------------------------------------------------------------
 * Memory Management API
 * -------------------------------------------------------------------------- */

/**
 * Initializes the guest linear memory space (640 MB).
 * In native builds, allocates g_mem; in WebAssembly, g_mem is offset 0.
 */
bool guest_memory_init(void);

/**
 * Frees host memory allocated by guest_memory_init (native builds only).
 */
void guest_memory_free(void);

/**
 * Checks whether [va, va + size) falls within valid guest memory bounds.
 */
static inline bool guest_is_valid_va(uint32_t va, uint32_t size) {
    if (size == 0) return true;
    uint64_t end = (uint64_t)va + (uint64_t)size;
    return (va >= GUEST_NULL_GUARD_LIMIT) && (end <= (uint64_t)GUEST_HEAP_LIMIT);
}

/**
 * Converts a guest virtual address to a host pointer.
 */
static inline void *guest_to_host(uint32_t va) {
    return (void *)(g_mem + va);
}

/**
 * Converts a host pointer inside guest memory to a 32-bit guest virtual address.
 */
static inline uint32_t host_to_guest(const void *ptr) {
    return (uint32_t)((const uint8_t *)ptr - g_mem);
}

/**
 * Computes Jenkins 96-bit mix hash used by EA bString::Hash.
 */
static inline uint32_t bstring_hash(const uint8_t *k, uint32_t length, uint32_t initval) {
    uint32_t a = 0x9e3779b9u, b = 0x9e3779b9u, c = initval;
    uint32_t len = length;
    while (len >= 12) {
        a += (uint32_t)k[0] | ((uint32_t)k[1] << 8) | ((uint32_t)k[2] << 16) | ((uint32_t)k[3] << 24);
        b += (uint32_t)k[4] | ((uint32_t)k[5] << 8) | ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 24);
        c += (uint32_t)k[8] | ((uint32_t)k[9] << 8) | ((uint32_t)k[10] << 16) | ((uint32_t)k[11] << 24);
        a = (a - b - c) ^ (c >> 13);
        b = (b - c - a) ^ (a << 8);
        c = (c - a - b) ^ (b >> 13);
        a = (a - b - c) ^ (c >> 12);
        b = (b - c - a) ^ (a << 16);
        c = (c - a - b) ^ (b >> 5);
        a = (a - b - c) ^ (c >> 3);
        b = (b - c - a) ^ (a << 10);
        c = (c - a - b) ^ (b >> 15);
        k += 12;
        len -= 12;
    }
    c += length;
    switch (len) {
    case 11: c += ((uint32_t)k[10]) << 24;
    case 10: c += ((uint32_t)k[9]) << 16;
    case 9:  c += ((uint32_t)k[8]) << 8;
    case 8:  b += ((uint32_t)k[7]) << 24;
    case 7:  b += ((uint32_t)k[6]) << 16;
    case 6:  b += ((uint32_t)k[5]) << 8;
    case 5:  b += (uint32_t)k[4];
    case 4:  a += ((uint32_t)k[3]) << 24;
    case 3:  a += ((uint32_t)k[2]) << 16;
    case 2:  a += ((uint32_t)k[1]) << 8;
    case 1:  a += (uint32_t)k[0];
    }
    a = (a - b - c) ^ (c >> 13);
    b = (b - c - a) ^ (a << 8);
    c = (c - a - b) ^ (b >> 13);
    a = (a - b - c) ^ (c >> 12);
    b = (b - c - a) ^ (a << 16);
    c = (c - a - b) ^ (b >> 5);
    a = (a - b - c) ^ (c >> 3);
    b = (b - c - a) ^ (a << 10);
    c = (c - a - b) ^ (b >> 15);
    return c;
}

/**
 * Parses PE sections from raw_exe bytes and copies initialized sections
 * (.text, .rdata, .data, .tls, .rsrc, etc.) into linear memory at their authentic VAs,
 * zeroing uninitialized BSS space.
 */
bool guest_memory_load_pe(const uint8_t *raw_exe, size_t exe_size);

/**
 * Win32 VirtualAlloc emulation on top of the 1:1 linear memory layout.
 */
uint32_t guest_virtual_alloc(uint32_t target_va, uint32_t size, uint32_t alloc_type, uint32_t protect);

/**
 * Win32 VirtualFree emulation.
 */
bool guest_virtual_free(uint32_t va, uint32_t size, uint32_t free_type);

/**
 * Fast bump / aligned allocator for guest heap.
 */
uint32_t guest_heap_alloc(uint32_t size, uint32_t alignment);

/**
 * Initializes the CPU execution state (stack, frame pointer, flags, control words).
 */
void guest_cpu_init(struct CPU *c, uint32_t entry_point);

/**
 * Initializes the worker thread environment block (TEB) and per-slot TLS state.
 */
void guest_init_worker_teb_slot(struct CPU *c, uint32_t slot_idx);
void guest_init_worker_teb(struct CPU *c);

#ifdef __cplusplus
}
#endif

#endif /* PROSTREET_MEMORY_H */

