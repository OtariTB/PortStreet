/* Need for Speed ProStreet - Engine Boot & Lifecycle Orchestrator Implementation.
 *
 * Coordinates memory initialization, IAT binding, static initializers,
 * command-line setup, and invocation of the authentic main() (sub_004afee0).
 */
#include "boot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration of authentic game frame tick */
void sub_006dae50(CPU *c);

#if defined(__wasm__) || !defined(_WIN32)
#define _stricmp strcasecmp
#endif

static boot_status_t g_boot_status = {
    .stage = BOOT_STAGE_UNINITIALIZED,
    .argc = 0,
    .is_safemode = false,
    .c_init_result = 0,
    .cpp_ctors_count = 0,
    .event_handles = {0, 0, 0, 0},
    .engine_object_ptr = 0,
    .exit_code = 0
};

const boot_status_t *boot_get_status(void) {
    return &g_boot_status;
}

void boot_reset_status(void) {
    memset(&g_boot_status, 0, sizeof(g_boot_status));
    g_boot_status.stage = BOOT_STAGE_UNINITIALIZED;
}

static void hook_safemode_check(CPU *c) {
    c->eax = g_boot_status.is_safemode ? 1u : 0u;
    c->esp += 4u;
}

static void hook_dos_header_check(CPU *c) {
    c->eax = 0u;
    c->esp += 4u;
}

static void hook_security_cookie(CPU *c) {
    if (GUEST_MEM_READY) {
        MR32(0x0100f4ccu) = 0xbb40e64eu;
    }
    c->eax = 0u;
    c->esp += 4u;
}

static void hook_multi_instance_check(CPU *c) {
    c->eax = 0u;
    c->esp += 4u;
}

static void hook_disc_check(CPU *c) {
    c->eax = 1u;
    c->esp += 4u;
}

static void hook_default_wndproc(CPU *c) {
    /* __stdcall WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) */
    c->eax = 0u;
    c->esp += 20u;
}

bool boot_init_memory(const uint8_t *pe_bytes, size_t pe_size) {
    if (!guest_memory_init()) {
        return false;
    }

    if (pe_bytes != NULL && pe_size > 0) {
        if (!guest_memory_load_pe(pe_bytes, pe_size)) {
            return false;
        }
    }

    g_boot_status.stage = BOOT_STAGE_MEMORY_READY;
    return true;
}

void boot_bind_iats(void) {
    crt_init_iat();
    win32_init_iat();
    d3d9_init_iat();
    dinput_init();
    dsound_init();
    g_boot_status.stage = BOOT_STAGE_IAT_BOUND;
}

void boot_install_hooks(void) {
    /* Install sub_0082851b hook for atexit registrations */
    initterm_install_hooks();

    /* Write authentic DOS signature 'MZ' at 0x00400000 */
    if (GUEST_MEM_READY) {
        *(uint16_t *)(g_mem + 0x00400000u) = 0x5a4du;
    }

    /* Install hooks into g_dtab */
    uint32_t off_safe = GUEST_SAFEMODE_CHECK_VA - DISPATCH_TEXT_BASE;
    if (off_safe < DISPATCH_TEXT_SIZE) {
        g_dtab[off_safe] = hook_safemode_check;
    }

    uint32_t off_dos = 0x00828b43u - DISPATCH_TEXT_BASE;
    if (off_dos < DISPATCH_TEXT_SIZE) {
        g_dtab[off_dos] = hook_dos_header_check;
    }

    uint32_t off_cookie = 0x00828feeu - DISPATCH_TEXT_BASE;
    if (off_cookie < DISPATCH_TEXT_SIZE) {
        g_dtab[off_cookie] = hook_security_cookie;
    }

    uint32_t off_inst = 0x0070f640u - DISPATCH_TEXT_BASE;
    if (off_inst < DISPATCH_TEXT_SIZE) {
        g_dtab[off_inst] = hook_multi_instance_check;
    }

    uint32_t off_disc = 0x0070f600u - DISPATCH_TEXT_BASE;
    if (off_disc < DISPATCH_TEXT_SIZE) {
        g_dtab[off_disc] = hook_disc_check;
    }

    uint32_t off_wndproc = 0x0070b4c0u - DISPATCH_TEXT_BASE;
    if (off_wndproc < DISPATCH_TEXT_SIZE) {
        g_dtab[off_wndproc] = hook_default_wndproc;
    }

    g_boot_status.stage = BOOT_STAGE_HOOKS_INSTALLED;
}

bool boot_run_initializers(CPU *c) {
    if (c == NULL) return false;

    int c_rc = initterm_run_c_initializers(c);
    g_boot_status.c_init_result = (uint32_t)c_rc;
    if (c_rc != 0) {
        return false;
    }

    uint32_t cpp_count = initterm_run_cpp_constructors(c);
    g_boot_status.cpp_ctors_count = cpp_count;
    g_boot_status.stage = BOOT_STAGE_INITTERM_DONE;
    return true;
}

void boot_setup_arguments(CPU *c, int argc, const char **argv) {
    if (c == NULL) return;

    if (argc < 1 || argv == NULL) {
        static const char *default_argv[] = { "nfs.exe" };
        argc = 1;
        argv = default_argv;
    }

    g_boot_status.argc = argc;
    g_boot_status.is_safemode = false;
    for (int i = 0; i < argc; i++) {
        if (argv[i] && _stricmp(argv[i], "-safemode") == 0) {
            g_boot_status.is_safemode = true;
            break;
        }
    }

    if (!GUEST_MEM_READY) return;

    /* Write argument strings into guest heap memory */
    uint32_t str_cur = 0x00102000u;
    uint32_t arg_ptrs[64];
    int count = argc < 64 ? argc : 64;

    for (int i = 0; i < count; i++) {
        const char *s = argv[i] ? argv[i] : "";
        size_t len = strlen(s) + 1;
        memcpy(g_mem + str_cur, s, len);
        arg_ptrs[i] = str_cur;
        str_cur += (uint32_t)((len + 3u) & ~3u);
    }

    /* Write argv table [arg0_ptr, arg1_ptr, ..., 0] at GUEST_ARGV_TAB_ADDR (0x00102100) */
    uint32_t tab_va = GUEST_ARGV_TAB_ADDR;
    for (int i = 0; i < count; i++) {
        MR32(tab_va) = arg_ptrs[i];
        tab_va += 4;
    }
    MR32(tab_va) = 0u;

    /* Write envp table [0] at GUEST_ENVP_TAB_ADDR (0x00102200) */
    MR32(GUEST_ENVP_TAB_ADDR) = 0u;

    /* Populate MSVC CRT global variables for __getmainargs */
    MR32(0x00b33a64u) = (uint32_t)argc;
    MR32(0x00b33a6cu) = GUEST_ARGV_TAB_ADDR;
    MR32(0x00b33a68u) = GUEST_ENVP_TAB_ADDR;

    /* Set up stack frame for sub_004afee0(argc, argv, envp) */
    c->esp = GUEST_STACK_TOP;
    c->esp -= 4; MR32(c->esp) = GUEST_ENVP_TAB_ADDR;
    c->esp -= 4; MR32(c->esp) = GUEST_ARGV_TAB_ADDR;
    c->esp -= 4; MR32(c->esp) = (uint32_t)argc;
    c->esp -= 4; MR32(c->esp) = GUEST_DUMMY_RETURN_VA;
}

int boot_invoke_main(CPU *c, bool dry_run) {
    if (c == NULL) return -1;

    g_boot_status.stage = BOOT_STAGE_MAIN_ENTERED;

    if (dry_run) {
        /* 1. Safe mode evaluation */
        if (g_boot_status.is_safemode && GUEST_MEM_READY) {
            MR32(GUEST_GLOBAL_SAFEMODE) = 1u;
        }

        /* 2. Emulate CreateEventA creation of 4 synchronization events */
        if (GUEST_MEM_READY) {
            for (int i = 0; i < 4; i++) {
                c->esp -= 16;
                MR32(c->esp) = 0u;
                MR32(c->esp + 4) = 1u;
                MR32(c->esp + 8) = 0u;
                MR32(c->esp + 12) = 0u;
                win32_shim_CreateEventA(c);
                c->esp += 16;
                uint32_t h = c->eax;
                g_boot_status.event_handles[i] = h;
                MR32(GUEST_GLOBAL_EVENTS + (uint32_t)i * 4u) = h;
            }

            /* 3. Allocate 4-byte root engine object */
            uint32_t obj_ptr = guest_heap_alloc(4, 4);
            if (obj_ptr) {
                MR32(obj_ptr) = 0u;
                MR32(0x00bfc024u) = obj_ptr;
                g_boot_status.engine_object_ptr = obj_ptr;

                /* 4. Update TLS array via fs:[0x2c] */
                uint32_t tls_arr = MR32(c->fs_base + 0x2cu);
                uint32_t tls_slot0 = MR32(tls_arr);
                MR32(0x00bfc02cu) = obj_ptr;
                MR32(tls_slot0 + 4u) = obj_ptr;
            }

            /* 5. Set quit flag for clean main loop termination */
            MR32(GUEST_GLOBAL_QUIT) = 1u;

            /* 6. Close event handles */
            for (int i = 0; i < 4; i++) {
                if (g_boot_status.event_handles[i]) {
                    c->esp -= 4;
                    MR32(c->esp) = g_boot_status.event_handles[i];
                    win32_shim_CloseHandle(c);
                    c->esp += 4;
                }
            }

            /* 7. Run exit destructors */
            initterm_run_exit_destructors(c);
        }

        g_boot_status.stage = BOOT_STAGE_MAIN_EXITED;
        g_boot_status.exit_code = 0;
        return 0;
    }

    /* Normal full dispatch of sub_004afee0 */
    c->eip = GUEST_MAIN_ENTRY_VA;
    DISPATCH_CALL(c, GUEST_MAIN_ENTRY_VA);
    g_boot_status.stage = BOOT_STAGE_MAIN_EXITED;
    g_boot_status.exit_code = (int)c->eax;
    return g_boot_status.exit_code;
}

int boot_engine(const uint8_t *pe_bytes, size_t pe_size, int argc, const char **argv, bool dry_run) {
    boot_reset_status();

    if (!boot_init_memory(pe_bytes, pe_size)) {
        return -1;
    }

    boot_bind_iats();
    boot_install_hooks();

    CPU cpu;
    guest_cpu_init(&cpu, GUEST_MAIN_ENTRY_VA);

    if (!boot_run_initializers(&cpu)) {
        return -2;
    }

    boot_setup_arguments(&cpu, argc, argv);
    return boot_invoke_main(&cpu, dry_run);
}

PROSTREET_WASM_EXPORT
uint32_t fntab_count(void) {
    uint32_t count = 0u;
    for (uint32_t i = 0u; i < DISPATCH_TEXT_SIZE; i++) {
        if (g_dtab[i] != (guest_fn_t)0) {
            count++;
        }
    }
    return count;
}

#if defined(__wasm__) || defined(__EMSCRIPTEN__)
PROSTREET_WASM_EXPORT
int prostreet_load_pe(uint32_t pe_va, uint32_t pe_size) {
    if (pe_va == 0 || pe_size == 0) return -1;
    const uint8_t *raw = (const uint8_t *)(g_mem + pe_va);
    return guest_memory_load_pe(raw, (size_t)pe_size) ? 0 : -2;
}

PROSTREET_WASM_EXPORT
int prostreet_main(int argc, const char **argv) {
    return boot_engine(NULL, 0, argc, argv, false);
}

PROSTREET_WASM_EXPORT
uint8_t *prostreet_get_guest_memory(void) {
    return g_mem;
}

static CPU s_tick_cpu;
static bool s_tick_inited = false;

PROSTREET_WASM_EXPORT
uint32_t prostreet_get_tick_esp(void) {
    return s_tick_cpu.esp;
}

PROSTREET_WASM_EXPORT
int prostreet_tick(uint32_t dt_us) {
    /* Guard 1: master dispatch table must be populated by fntab_init() */
    if (g_dtab[0] == (guest_fn_t)0) {
        return -1;
    }
    /* Guard 2: C++ static initializers must have initialized the intrusive list
     * sentinel at 0x00a79bc8 (walked by sub_0074ac50 inside sub_006dae50). If
     * still 0, sub_0074ac50 would spin forever chasing 0 -> 0 -> 0. */
    if (!GUEST_MEM_READY || MR32(0x00a79bc8u) == 0u) {
        return -2;
    }
    if (!s_tick_inited) {
        guest_cpu_init(&s_tick_cpu, 0x006dae50u);
        s_tick_inited = true;
    }
    if (dt_us == 0u) {
        dt_us = 16666u; /* 60 fps dt in microseconds */
    }
    s_tick_cpu.esp = 0x003e0000u - 8u;
    MR32(s_tick_cpu.esp + 4u) = dt_us;
    MR32(s_tick_cpu.esp) = 0x006dbb6cu; /* dummy return address */
    sub_006dae50(&s_tick_cpu);
    return 0;
}
#endif

