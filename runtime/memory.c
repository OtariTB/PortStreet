/* Need for Speed ProStreet - 1:1 Linear Guest Memory Layout Implementation.
 * Auto-generated and verified for PortSpeed.
 */
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) && !defined(__wasm__)
#include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

#ifndef __wasm__
uint8_t *g_mem = NULL;
#endif

static uint32_t s_heap_cur = GUEST_HEAP_START;

bool guest_memory_init(void) {
#ifdef __wasm__
    /* In WebAssembly, linear memory is already mapped at offset 0 */
    return true;
#else
    if (g_mem != NULL) {
        return true;
    }
#if defined(_WIN32)
    g_mem = (uint8_t *)VirtualAlloc(NULL, GUEST_HEAP_LIMIT, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#elif defined(MAP_ANONYMOUS)
    g_mem = (uint8_t *)mmap(NULL, GUEST_HEAP_LIMIT, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_mem == MAP_FAILED) g_mem = NULL;
#else
    g_mem = (uint8_t *)calloc(1, GUEST_HEAP_LIMIT);
#endif

    if (g_mem == NULL) {
        fprintf(stderr, "[FATAL] Failed to allocate 640 MB guest linear memory.\n");
        return false;
    }

    s_heap_cur = GUEST_HEAP_START;
    return true;
#endif
}

void guest_memory_free(void) {
#ifndef __wasm__
    if (g_mem != NULL) {
#if defined(_WIN32)
        VirtualFree(g_mem, 0, MEM_RELEASE);
#elif defined(MAP_ANONYMOUS)
        munmap(g_mem, GUEST_HEAP_LIMIT);
#else
        free(g_mem);
#endif
        g_mem = NULL;
    }
#endif
    s_heap_cur = GUEST_HEAP_START;
}

bool guest_memory_load_pe(const uint8_t *raw_exe, size_t exe_size) {
    if (raw_exe == NULL || exe_size < 0x40) {
        return false;
    }
    if (raw_exe[0] != 'M' || raw_exe[1] != 'Z') {
        return false;
    }

    /* Locate PE Header via e_lfanew */
    uint32_t pe_offset = *(const uint32_t *)(raw_exe + 0x3C);
    if (pe_offset + 0x18 > exe_size) {
        return false;
    }
    if (memcmp(raw_exe + pe_offset, "PE\0\0", 4) != 0) {
        return false;
    }

    uint16_t machine = *(const uint16_t *)(raw_exe + pe_offset + 4);
    uint16_t num_sections = *(const uint16_t *)(raw_exe + pe_offset + 6);
    if (machine != 0x014C || num_sections < 1 || num_sections > 96) {
        return false;
    }

    uint16_t opt_hdr_size = *(const uint16_t *)(raw_exe + pe_offset + 20);
    uint16_t opt_magic = *(const uint16_t *)(raw_exe + pe_offset + 24);
    if (opt_magic != 0x010B) { /* PE32 required */
        return false;
    }

    uint32_t image_base = *(const uint32_t *)(raw_exe + pe_offset + 24 + 28);
    if (image_base != GUEST_IMAGE_BASE) {
        return false;
    }

    uint32_t sec_table = pe_offset + 24 + opt_hdr_size;
    if (sec_table + (uint32_t)num_sections * 40u > exe_size) {
        return false;
    }

    /* Initialize guest memory if not already done */
    if (!guest_memory_init()) {
        return false;
    }

    /* Map each PE section directly into g_mem at authentic VirtualAddress */
    for (uint16_t i = 0; i < num_sections; i++) {
        const uint8_t *sec = raw_exe + sec_table + (uint32_t)i * 40u;
        uint32_t vsize = *(const uint32_t *)(sec + 8);
        uint32_t rva   = *(const uint32_t *)(sec + 12);
        uint32_t rsize = *(const uint32_t *)(sec + 16);
        uint32_t roff  = *(const uint32_t *)(sec + 20);

        uint32_t va = image_base + rva;
        if (!guest_is_valid_va(va, vsize)) {
            continue;
        }

        uint32_t init_len = (rsize < vsize) ? rsize : vsize;
        if (init_len > 0 && roff + init_len <= exe_size) {
            memcpy(g_mem + va, raw_exe + roff, init_len);
        }
        /* Explicitly zero uninitialized BSS portion */
        if (vsize > init_len) {
            memset(g_mem + va + init_len, 0, vsize - init_len);
        }
    }

    return true;
}

uint32_t guest_virtual_alloc(uint32_t target_va, uint32_t size, uint32_t alloc_type, uint32_t protect) {
    (void)protect;
    if (size == 0) return 0;

    /* Align size up to 4 KiB page boundary */
    uint32_t aligned_size = (size + GUEST_PAGE_SIZE - 1u) & ~(GUEST_PAGE_SIZE - 1u);

    if (target_va == 0) {
        /* Align heap bump pointer to 64 KiB boundary */
        s_heap_cur = (s_heap_cur + 0xFFFFu) & ~0xFFFFu;
        target_va = s_heap_cur;
        if ((uint64_t)target_va + (uint64_t)aligned_size > (uint64_t)GUEST_HEAP_LIMIT) {
            return 0;
        }
        s_heap_cur += aligned_size;
    } else {
        if ((uint64_t)target_va + (uint64_t)aligned_size > (uint64_t)GUEST_HEAP_LIMIT) {
            return 0;
        }
    }

    if (!guest_is_valid_va(target_va, aligned_size)) {
        return 0;
    }

    if (alloc_type & GUEST_MEM_COMMIT) {
        memset(g_mem + target_va, 0, aligned_size);
    }

    return target_va;
}

bool guest_virtual_free(uint32_t va, uint32_t size, uint32_t free_type) {
    if (!guest_is_valid_va(va, size)) {
        return false;
    }

    if (free_type & GUEST_MEM_DECOMMIT) {
        memset(g_mem + va, 0, size);
    }
    return true;
}

uint32_t guest_heap_alloc(uint32_t size, uint32_t alignment) {
    if (size == 0) return 0;
    if (alignment < 4) alignment = 4;

    uint32_t mask = alignment - 1u;
    uint32_t cur = __atomic_load_n(&s_heap_cur, __ATOMIC_RELAXED);
    while (1) {
        uint32_t allocated = (cur + mask) & ~mask;
        if ((uint64_t)allocated + (uint64_t)size > (uint64_t)GUEST_HEAP_LIMIT) {
            return 0;
        }
        uint32_t next = allocated + size;
        if (__atomic_compare_exchange_n(&s_heap_cur, &cur, next, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            if (!guest_is_valid_va(allocated, size)) {
                return 0;
            }
            return allocated;
        }
    }
}

void guest_init_worker_teb(struct CPU *c) {
    if (c == NULL) return;
    MR32(GUEST_WORKER_TEB_ADDR + 0x00u) = 0xFFFFFFFFu;               /* SEH frame head */
    MR32(GUEST_WORKER_TEB_ADDR + 0x04u) = GUEST_WORKER_STACK_TOP;   /* Stack Base */
    MR32(GUEST_WORKER_TEB_ADDR + 0x08u) = GUEST_WORKER_STACK_BOTTOM;/* Stack Limit */
    MR32(GUEST_WORKER_TEB_ADDR + 0x18u) = GUEST_WORKER_TEB_ADDR;    /* Self-pointer to TEB */
    MR32(GUEST_WORKER_TEB_ADDR + 0x20u) = 0x00001000u;               /* Simulated PID */
    MR32(GUEST_WORKER_TEB_ADDR + 0x24u) = 0x00001002u;               /* Simulated Worker TID */
    MR32(GUEST_WORKER_TEB_ADDR + 0x2cu) = GUEST_TEB_ADDR + 0x100u;   /* ThreadLocalStoragePointer */
    MR32(GUEST_WORKER_TEB_ADDR + 0x30u) = GUEST_TEB_ADDR + 0x1000u;  /* Simulated PEB */
    c->fs_base = GUEST_WORKER_TEB_ADDR;
}

void guest_cpu_init(struct CPU *c, uint32_t entry_point) {
    if (c == NULL) return;
    memset(c, 0, sizeof(*c));

    c->esp = GUEST_STACK_TOP;
    c->ebp = c->esp;
    c->eip = entry_point;

    /* Default x87 Control Word: 64-bit precision, all exceptions masked */
    c->fcw = 0x037Fu;
    c->fsw = 0;
    c->top = 0;

    /* Point fs_base to simulated TEB */
    c->fs_base = GUEST_TEB_ADDR;

    /* Write termination sentinel on stack at [ESP] */
    if (GUEST_MEM_READY) {
        MR32(c->esp) = 0xDEADF00Du;

        /* Initialize Win32 TEB and TLS layout at GUEST_TEB_ADDR (0x00100000) */
        MR32(GUEST_TEB_ADDR + 0x00u) = 0xFFFFFFFFu;               /* SEH frame head */
        MR32(GUEST_TEB_ADDR + 0x04u) = GUEST_STACK_TOP;           /* Stack Base */
        MR32(GUEST_TEB_ADDR + 0x08u) = GUEST_STACK_BOTTOM;        /* Stack Limit */
        MR32(GUEST_TEB_ADDR + 0x18u) = GUEST_TEB_ADDR;            /* Self-pointer to TEB */
        MR32(GUEST_TEB_ADDR + 0x20u) = 0x00001000u;               /* Simulated PID */
        MR32(GUEST_TEB_ADDR + 0x24u) = 0x00001001u;               /* Simulated TID */
        MR32(GUEST_TEB_ADDR + 0x2cu) = GUEST_TEB_ADDR + 0x100u;   /* ThreadLocalStoragePointer */
        MR32(GUEST_TEB_ADDR + 0x30u) = GUEST_TEB_ADDR + 0x1000u;  /* Simulated PEB */
        MR32(GUEST_TEB_ADDR + 0x100u) = GUEST_TEB_ADDR + 0x200u;  /* TLS module 0 array pointer */
    }
}

