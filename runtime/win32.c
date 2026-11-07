/* Need for Speed ProStreet - Win32 Core Emulation Layer Implementation.
 *
 * Comprehensive __stdcall C99 shims for KERNEL32, USER32, ADVAPI32, WINMM,
 * SHFOLDER, ole32, RPCRT4, NETAPI32, MSVCP80, and WS2_32.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "win32.h"
#include "memory.h"

/* --------------------------------------------------------------------------
 * Win32 Handle Manager & Synchronization Primitives
 * -------------------------------------------------------------------------- */
#define MAX_WIN32_HANDLES 256
enum {
    HANDLE_FREE = 0,
    HANDLE_FILE,
    HANDLE_MUTEX,
    HANDLE_EVENT,
    HANDLE_SEMAPHORE,
    HANDLE_THREAD,
    HANDLE_PROCESS,
    HANDLE_FIND,
    HANDLE_HWND
};

typedef struct {
    uint32_t type;
    uint32_t state;
    uint32_t extra;
    char     name[64];
} win32_handle_t;

static win32_handle_t g_handles[MAX_WIN32_HANDLES];
static FILE          *g_win32_files[MAX_WIN32_HANDLES];
static uint32_t       g_file_lock = 0;
static uint32_t       g_io_log_count = 0;
static uint32_t       g_sleep_dummy = 0;
static uint32_t       g_tls_slots[64];
static uint64_t       g_tls_bitmap = 0;
static uint32_t       g_wnd_proc = 0;
static uint32_t       g_win_width = 1280;
static uint32_t       g_win_height = 720;
#define WIN32_MSG_QUEUE_CAPACITY 64u
static uint32_t g_msg_queue[WIN32_MSG_QUEUE_CAPACITY][4]; /* (hwnd, msg, wParam, lParam) */
static uint32_t g_msg_head = 0;
static uint32_t g_msg_tail = 0;
static uint8_t  g_key_state[256];

static inline void file_lock_acquire(void) {
    while (1) {
        uint32_t exp = 0u;
        if (PS_HOST_ATOMIC_CAS32(&g_file_lock, &exp, 1u)) return;
        PS_WASM_HOST_WAIT32(&g_file_lock, 1u, 1000000ll);
    }
}

static inline void file_lock_release(void) {
    PS_HOST_ATOMIC_STORE32(&g_file_lock, 0u);
    PS_WASM_HOST_NOTIFY(&g_file_lock, 1u);
}

static inline uint32_t w32_current_tid(const CPU *c) {
    if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x40u <= GUEST_HEAP_LIMIT) {
        uint32_t tid = MR32(c->fs_base + 0x24u);
        if (tid != 0u) return tid;
    }
    return 1000u;
}

static inline void w32_set_last_error(CPU *c, uint32_t err) {
    if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x40u <= GUEST_HEAP_LIMIT) {
        MR32(c->fs_base + 0x34u) = err;
    }
}

static inline uint32_t w32_get_last_error(const CPU *c) {
    if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x40u <= GUEST_HEAP_LIMIT) {
        return MR32(c->fs_base + 0x34u);
    }
    return 0u;
}

FILE *win32_open_game_file(const char *guest_path, bool read_only) {
    if (!guest_path || !guest_path[0]) return NULL;

    const char *game_dir = getenv("PROSTREET_GAME_DIR");
    /* Never permit mutating files inside the read-only game directory */
    if (!read_only && game_dir && game_dir[0]) {
        return NULL;
    }

    const char *p = guest_path;
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] == '.' && (p[1] == '\\' || p[1] == '/')) p += 2;

    /* Strip Windows drive or prefix if path points into game folder */
    const char *marker = strstr(p, "Need For Spped - Pro Street");
    if (marker) {
        p = marker + strlen("Need For Spped - Pro Street");
        while (*p == '\\' || *p == '/') p++;
    } else if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':') {
        if (game_dir && game_dir[0]) {
            p += 2;
            while (*p == '\\' || *p == '/') p++;
        }
    }

    if (strstr(p, "..") != NULL) {
        return NULL;
    }

    if (game_dir && game_dir[0]) {
        char rel[260];
        size_t rlen = 0;
        char sep = (game_dir[0] == '/') ? '/' : '\\';
        for (size_t i = 0; p[i] && rlen + 1 < sizeof(rel); ++i) {
            char ch = p[i];
            if (ch == '\\' || ch == '/') ch = sep;
            rel[rlen++] = ch;
        }
        rel[rlen] = '\0';

        char full[520];
        snprintf(full, sizeof(full), "%s%c%s", game_dir, sep, rel);
        FILE *fp = fopen(full, "rb");
        if (fp) return fp;

        /* Case-normalized fallback (UPPERCASE / lowercase) for case-sensitive VFS */
        for (size_t i = 0; i < rlen; ++i) {
            if (rel[i] >= 'a' && rel[i] <= 'z') rel[i] = (char)(rel[i] - 'a' + 'A');
        }
        snprintf(full, sizeof(full), "%s%c%s", game_dir, sep, rel);
        fp = fopen(full, "rb");
        if (fp) return fp;

        for (size_t i = 0; i < rlen; ++i) {
            if (rel[i] >= 'A' && rel[i] <= 'Z') rel[i] = (char)(rel[i] - 'A' + 'a');
        }
        snprintf(full, sizeof(full), "%s%c%s", game_dir, sep, rel);
        return fopen(full, "rb");
    }

    return fopen(guest_path, read_only ? "rb" : "wb");
}

static uint32_t alloc_handle(uint32_t type, const char *name) {
    for (uint32_t i = 0x10; i < MAX_WIN32_HANDLES; ++i) {
        uint32_t expected = HANDLE_FREE;
        if (PS_HOST_ATOMIC_CAS32(&g_handles[i].type, &expected, type)) {
            PS_HOST_ATOMIC_STORE32(&g_handles[i].state, 0);
            g_handles[i].extra = 0;
            g_handles[i].name[0] = '\0';
            if (name) {
                strncpy(g_handles[i].name, name, 63);
                g_handles[i].name[63] = '\0';
            }
            return (i << 2) | 0x01; /* Pseudo-Win32 handle */
        }
    }
    return 0x1000; /* Fallback handle */
}

static inline const char *w32_str(uint32_t va) {
    return (va >= GUEST_NULL_GUARD_LIMIT && va < GUEST_HEAP_LIMIT) ? (const char *)(g_mem + va) : "";
}

void win32_shim_MultiByteToWideChar(CPU *c) {
    const char *src = w32_str(MR32(c->esp + 8));
    int cbMulti = (int)MR32(c->esp + 12);
    uint32_t dst = MR32(c->esp + 16);
    int cchWide = (int)MR32(c->esp + 20);
    int slen = cbMulti > 0 ? cbMulti : (int)strlen(src);
    if (cchWide == 0) {
        c->eax = (uint32_t)(slen + 1);
    } else {
        for (int i = 0; i < slen && i < cchWide; ++i) {
            MR16(dst + i * 2) = (uint16_t)(unsigned char)src[i];
        }
        if (slen < cchWide) MR16(dst + slen * 2) = 0;
        c->eax = (uint32_t)slen;
    }
    c->esp += 24;
}
void win32_shim_SuspendThread(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ResumeThread(CPU *c) {
    uint32_t h = MR32(c->esp);
    c->eax = win32_resume_guest_thread(h);
    c->esp += 4;
}
void win32_shim_GetVersionExA(CPU *c) {
    uint32_t pVer = MR32(c->esp);
    if (pVer) {
        MR32(pVer + 4)  = 5;    /* dwMajorVersion (Windows XP) */
        MR32(pVer + 8)  = 1;    /* dwMinorVersion */
        MR32(pVer + 12) = 2600; /* dwBuildNumber */
        MR32(pVer + 16) = 2;    /* VER_PLATFORM_WIN32_NT */
        strcpy((char *)(g_mem + pVer + 20), "Service Pack 3");
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_GetLongPathNameA(CPU *c) {
    const char *src = w32_str(MR32(c->esp));
    uint32_t dst = MR32(c->esp + 4);
    uint32_t max = MR32(c->esp + 8);
    if (dst && max > 0) strncpy((char *)(g_mem + dst), src, max);
    c->eax = (uint32_t)strlen(src);
    c->esp += 12;
}
void win32_shim_GetDriveTypeA(CPU *c) {
    c->eax = 3; /* DRIVE_FIXED */
    c->esp += 4;
}
void win32_shim_GetLogicalDrives(CPU *c) {
    c->eax = 0x0C; /* C: and D: */
    c->esp += 0;
}
void win32_shim_FindClose(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_FindNextFileA(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_FindFirstFileA(CPU *c) {
    c->eax = (uint32_t)-1; /* INVALID_HANDLE_VALUE */
    c->esp += 8;
}
void win32_shim_FreeLibrary(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateDirectoryA(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_GetModuleHandleA(CPU *c) {
    c->eax = 0x00400000u; /* ImageBase */
    c->esp += 4;
}
void win32_shim_GetSystemInfo(CPU *c) {
    uint32_t pInfo = MR32(c->esp);
    if (pInfo) {
        MR16(pInfo + 0)  = 0; /* PROCESSOR_ARCHITECTURE_INTEL */
        MR32(pInfo + 4)  = 4096; /* dwPageSize */
        MR32(pInfo + 8)  = 0x00010000; /* lpMinimumApplicationAddress */
        MR32(pInfo + 12) = 0x7FFEFFFF; /* lpMaximumApplicationAddress */
        MR32(pInfo + 20) = 4; /* dwNumberOfProcessors */
        MR32(pInfo + 28) = 586; /* dwProcessorType */
    }
    c->esp += 4;
}
void win32_shim_Sleep(CPU *c) {
    uint32_t ms = MR32(c->esp);
    if (ms > 0u) {
        long long ns = (long long)(ms > 5u ? 5u : ms) * 1000000ll;
        PS_WASM_HOST_WAIT32(&g_sleep_dummy, 0, ns);
    }
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_Process32Next(CPU *c) {
    c->eax = 0; /* No more processes */
    c->esp += 8;
}
void win32_shim_Process32First(CPU *c) {
    uint32_t pe = MR32(c->esp + 4);
    if (pe) {
        MR32(pe + 8)  = 1000; /* th32ProcessID */
        MR32(pe + 20) = 4;    /* cntThreads */
        strcpy((char *)(g_mem + pe + 36), "nfs.exe");
    }
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_CreateToolhelp32Snapshot(CPU *c) {
    c->eax = 0x2000;
    c->esp += 8;
}
void win32_shim_SetErrorMode(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_GetTickCount(CPU *c) {
    static uint32_t s_tick = 50000u;
    c->eax = PS_HOST_ATOMIC_FETCH_ADD32(&s_tick, 16u) + 16u;
    c->esp += 0;
}
void win32_shim_SetThreadPriority(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_GetSystemTimeAsFileTime(CPU *c) {
    uint32_t pFT = MR32(c->esp);
    if (pFT) {
        MR32(pFT + 0) = 0x80000000u;
        MR32(pFT + 4) = 0x01D38000u;
    }
    c->esp += 4;
}
void win32_shim_GetCurrentProcessId(CPU *c) {
    c->eax = 1000;
    c->esp += 0;
}
void win32_shim_GetCurrentThreadId(CPU *c) {
    c->eax = w32_current_tid(c);
    c->esp += 0;
}
void win32_shim_SetUnhandledExceptionFilter(CPU *c) {
    c->eax = 1; /* EXCEPTION_EXECUTE_HANDLER */
    c->esp += 4;
}
void win32_shim_UnhandledExceptionFilter(CPU *c) {
    c->eax = 1; /* EXCEPTION_EXECUTE_HANDLER */
    c->esp += 4;
}
void win32_shim_GetCurrentProcess(CPU *c) {
    c->eax = (uint32_t)-1;
    c->esp += 0;
}
void win32_shim_TerminateProcess(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_CloseHandle(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx >= 0x10u && idx < MAX_WIN32_HANDLES) {
        uint32_t t = PS_HOST_ATOMIC_LOAD32(&g_handles[idx].type);
        if (t == HANDLE_FILE) {
            file_lock_acquire();
            if (g_win32_files[idx]) {
                fclose(g_win32_files[idx]);
                g_win32_files[idx] = NULL;
            }
            file_lock_release();
            PS_HOST_ATOMIC_STORE32(&g_handles[idx].type, HANDLE_FREE);
        }
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_InterlockedExchange(CPU *c) {
    uint32_t pTarget = MR32(c->esp);
    uint32_t val     = MR32(c->esp + 4);
    c->eax = pTarget ? PS_ATOMIC_XCHG32(pTarget, val) : 0u;
    c->esp += 8;
}
void win32_shim_ReleaseMutex(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_MUTEX) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 0u);
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, 1u);
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateMutexW(CPU *c) {
    uint32_t init_owner = MR32(c->esp + 4) ? 1u : 0u;
    uint32_t h = alloc_handle(HANDLE_MUTEX, "NFS_Mutex");
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, init_owner);
    }
    c->eax = h;
    c->esp += 12;
}
void win32_shim_GetSystemDirectoryA(CPU *c) {
    uint32_t buf = MR32(c->esp);
    uint32_t uSz = MR32(c->esp + 4);
    if (buf && uSz > 16) strcpy((char *)(g_mem + buf), "C:\\WINDOWS\\system32");
    c->eax = 19;
    c->esp += 8;
}
void win32_shim_LoadLibraryA(CPU *c) {
    c->eax = 0x10000000u; /* Pseudo DLL base */
    c->esp += 4;
}
void win32_shim_LeaveCriticalSection(CPU *c) {
    uint32_t cs = MR32(c->esp);
    if (cs) {
        uint32_t rec = MR32(cs + 8);
        if (rec > 1u) {
            MR32(cs + 8) = rec - 1u;
        } else {
            MR32(cs + 8) = 0u;
            PS_ATOMIC_STORE32(cs + 12, 0u);
            PS_ATOMIC_STORE32(cs + 4, 0u);
            PS_WASM_NOTIFY(cs + 4, 1u);
        }
    }
    c->esp += 4;
}
void win32_shim_TryEnterCriticalSection(CPU *c) {
    uint32_t cs = MR32(c->esp);
    uint32_t ok = 0u;
    if (cs) {
        uint32_t tid = w32_current_tid(c);
        if (PS_ATOMIC_LOAD32(cs + 4) == 1u && PS_ATOMIC_LOAD32(cs + 12) == tid) {
            MR32(cs + 8) = MR32(cs + 8) + 1u;
            ok = 1u;
        } else {
            uint32_t exp = 0u;
            if (PS_ATOMIC_CAS32(cs + 4, &exp, 1u)) {
                PS_ATOMIC_STORE32(cs + 12, tid);
                MR32(cs + 8) = 1u;
                ok = 1u;
            }
        }
    }
    c->eax = ok;
    c->esp += 4;
}
void win32_shim_EnterCriticalSection(CPU *c) {
    uint32_t cs = MR32(c->esp);
    if (cs) {
        uint32_t tid = w32_current_tid(c);
        if (PS_ATOMIC_LOAD32(cs + 4) == 1u && PS_ATOMIC_LOAD32(cs + 12) == tid) {
            MR32(cs + 8) = MR32(cs + 8) + 1u;
        } else {
            while (1) {
                uint32_t exp = 0u;
                if (PS_ATOMIC_CAS32(cs + 4, &exp, 1u)) {
                    PS_ATOMIC_STORE32(cs + 12, tid);
                    MR32(cs + 8) = 1u;
                    break;
                }
                PS_WASM_WAIT32(cs + 4, 1, 5000000ll);
            }
        }
    }
    c->esp += 4;
}
void win32_shim_DeleteCriticalSection(CPU *c) {
    uint32_t cs = MR32(c->esp);
    if (cs) memset(g_mem + cs, 0, 24);
    c->esp += 4;
}
void win32_shim_InitializeCriticalSection(CPU *c) {
    uint32_t cs = MR32(c->esp);
    if (cs) memset(g_mem + cs, 0, 24);
    c->esp += 4;
}
void win32_shim_WaitForSingleObject(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t timeout = MR32(c->esp + 4);
    uint32_t idx = h >> 2;
    uint32_t rc = 0u; /* WAIT_OBJECT_0 */

    if (idx < MAX_WIN32_HANDLES) {
        uint32_t t = PS_HOST_ATOMIC_LOAD32(&g_handles[idx].type);
        long long wait_ns = (timeout == 0xFFFFFFFFu) ? -1ll : (long long)timeout * 1000000ll;

        if (t == HANDLE_EVENT) {
            uint32_t manual = g_handles[idx].extra;
            while (1) {
                if (manual) {
                    if (PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state) != 0u) break;
                } else {
                    uint32_t exp = 1u;
                    if (PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &exp, 0u)) break;
                }
                if (timeout == 0u) { rc = 0x102u; break; }
                int w = PS_WASM_HOST_WAIT32(&g_handles[idx].state, 0, wait_ns);
                if (w == 2) {
                    if (manual) {
                        if (PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state) == 0u) rc = 0x102u;
                    } else {
                        uint32_t exp2 = 1u;
                        if (!PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &exp2, 0u)) rc = 0x102u;
                    }
                    break;
                }
            }
        } else if (t == HANDLE_SEMAPHORE) {
            while (1) {
                uint32_t cur = PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state);
                if (cur > 0u && PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &cur, cur - 1u)) {
                    break;
                }
                if (timeout == 0u) { rc = 0x102u; break; }
                int w = PS_WASM_HOST_WAIT32(&g_handles[idx].state, 0, wait_ns);
                if (w == 2) {
                    uint32_t cur2 = PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state);
                    if (!(cur2 > 0u && PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &cur2, cur2 - 1u))) {
                        rc = 0x102u;
                    }
                    break;
                }
            }
        } else if (t == HANDLE_MUTEX) {
            while (1) {
                uint32_t exp = 0u;
                if (PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &exp, 1u)) break;
                if (timeout == 0u) { rc = 0x102u; break; }
                int w = PS_WASM_HOST_WAIT32(&g_handles[idx].state, 1, wait_ns);
                if (w == 2) {
                    uint32_t exp2 = 0u;
                    if (!PS_HOST_ATOMIC_CAS32(&g_handles[idx].state, &exp2, 1u)) rc = 0x102u;
                    break;
                }
            }
        } else if (t == HANDLE_THREAD) {
            while (PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state) == 0u) {
                if (timeout == 0u) { rc = 0x102u; break; }
                int w = PS_WASM_HOST_WAIT32(&g_handles[idx].state, 0, wait_ns);
                if (w == 2) {
                    if (PS_HOST_ATOMIC_LOAD32(&g_handles[idx].state) == 0u) rc = 0x102u;
                    break;
                }
            }
        }
    }

    c->eax = rc;
    c->esp += 8;
}
void win32_shim_CreateEventA(CPU *c) {
    uint32_t manual_reset = MR32(c->esp + 4) ? 1u : 0u;
    uint32_t init_state   = MR32(c->esp + 8) ? 1u : 0u;
    const char *name      = MR32(c->esp + 12) ? w32_str(MR32(c->esp + 12)) : "NFS_Event";
    uint32_t h = alloc_handle(HANDLE_EVENT, name);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        g_handles[idx].extra = manual_reset;
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, init_state);
    }
    c->eax = h;
    c->esp += 16;
}
void win32_shim_GetDiskFreeSpaceExA(CPU *c) {
    uint64_t free_bytes = 100ull * 1024ull * 1024ull * 1024ull; /* 100 GB */
    uint32_t pFree = MR32(c->esp + 4);
    uint32_t pTotal = MR32(c->esp + 8);
    uint32_t pTotalFree = MR32(c->esp + 12);
    if (pFree) MR64(pFree) = free_bytes;
    if (pTotal) MR64(pTotal) = free_bytes * 2;
    if (pTotalFree) MR64(pTotalFree) = free_bytes;
    c->eax = 1;
    c->esp += 16;
}
void win32_shim_SetWaitableTimer(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 1u);
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, 1u);
    }
    c->eax = 1;
    c->esp += 24;
}
void win32_shim_SystemTimeToFileTime(CPU *c) {
    uint32_t pFT = MR32(c->esp + 4);
    if (pFT) {
        MR32(pFT + 0) = 0x80000000u;
        MR32(pFT + 4) = 0x01D38000u;
    }
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_GetSystemTime(CPU *c) {
    uint32_t pST = MR32(c->esp);
    if (pST) {
        MR16(pST + 0) = 2026; /* wYear */
        MR16(pST + 2) = 10;   /* wMonth */
        MR16(pST + 4) = 6;    /* wDayOfWeek */
        MR16(pST + 6) = 31;   /* wDay */
        MR16(pST + 8) = 12;   /* wHour */
        MR16(pST + 10) = 0;   /* wMinute */
        MR16(pST + 12) = 0;   /* wSecond */
        MR16(pST + 14) = 0;   /* wMilliseconds */
    }
    c->esp += 4;
}
void win32_shim_CreateWaitableTimerA(CPU *c) {
    uint32_t manual_reset = MR32(c->esp + 4) ? 1u : 0u;
    uint32_t h = alloc_handle(HANDLE_EVENT, "Timer");
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        g_handles[idx].extra = manual_reset;
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 1u);
    }
    c->eax = h;
    c->esp += 12;
}
void win32_shim_DuplicateHandle(CPU *c) {
    uint32_t pTarget = MR32(c->esp + 12);
    if (pTarget) MR32(pTarget) = MR32(c->esp + 4);
    c->eax = 1;
    c->esp += 28;
}
void win32_shim_GetCurrentThread(CPU *c) {
    c->eax = (uint32_t)-2;
    c->esp += 0;
}
void win32_shim_TerminateThread(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_SleepEx(CPU *c) {
    uint32_t ms = MR32(c->esp);
    if (ms > 0u) {
        long long ns = (long long)(ms > 5u ? 5u : ms) * 1000000ll;
        PS_WASM_HOST_WAIT32(&g_sleep_dummy, 0, ns);
    }
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_GetThreadPriority(CPU *c) {
    c->eax = 0; /* THREAD_PRIORITY_NORMAL */
    c->esp += 4;
}
void win32_shim_GetExitCodeThread(CPU *c) {
    uint32_t hThread = MR32(c->esp);
    uint32_t pCode   = MR32(c->esp + 4);
    uint32_t code    = 0u;
    uint32_t slot    = hThread >> 2;
    if (slot < MAX_WIN32_HANDLES && g_handles[slot].type == HANDLE_THREAD) {
        if (PS_HOST_ATOMIC_LOAD32(&g_handles[slot].state) == 0u) {
            code = 259u; /* STILL_ACTIVE */
        } else {
            const guest_thread_desc_t *th = win32_get_guest_thread(hThread);
            if (th) code = th->exit_code;
        }
    }
    if (pCode) MR32(pCode) = code;
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_WriteFile(CPU *c) {
    uint32_t nBytes = MR32(c->esp + 8);
    uint32_t pDone  = MR32(c->esp + 12);
    if (pDone) MR32(pDone) = nBytes;
    c->eax = 1;
    c->esp += 20;
}
void win32_shim_SetFilePointer(CPU *c) {
    uint32_t hFile  = MR32(c->esp);
    int32_t  distLo = (int32_t)MR32(c->esp + 4);
    uint32_t pDistHi = MR32(c->esp + 8);
    uint32_t method = MR32(c->esp + 12);
    uint32_t idx    = hFile >> 2;
    int whence = (method == 1u) ? SEEK_CUR : ((method == 2u) ? SEEK_END : SEEK_SET);
    int64_t dist = pDistHi ? (((int64_t)(int32_t)MR32(pDistHi) << 32) | (uint32_t)distLo) : (int64_t)distLo;

    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_FILE) {
        file_lock_acquire();
        FILE *fp = g_win32_files[idx];
        long pos = 0;
        if (fp && fseek(fp, (long)dist, whence) == 0) {
            pos = ftell(fp);
            if (pos < 0) pos = 0;
            if (pDistHi) MR32(pDistHi) = (uint32_t)((uint64_t)pos >> 32);
            w32_set_last_error(c, 0u);
            c->eax = (uint32_t)pos;
        } else {
            w32_set_last_error(c, 6u); /* ERROR_INVALID_HANDLE */
            c->eax = 0xFFFFFFFFu;
        }
        file_lock_release();
    } else {
        c->eax = 0xFFFFFFFFu;
    }
    c->esp += 16;
}
void win32_shim_DeleteFileA(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_MoveFileA(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_ReadFile(CPU *c) {
    uint32_t hFile  = MR32(c->esp);
    uint32_t pBuf   = MR32(c->esp + 4);
    uint32_t nBytes = MR32(c->esp + 8);
    uint32_t pDone  = MR32(c->esp + 12);
    uint32_t pOv    = MR32(c->esp + 16);
    uint32_t idx    = hFile >> 2;
    uint32_t got    = 0u;
    uint32_t ok     = 0u;

    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_FILE) {
        file_lock_acquire();
        FILE *fp = g_win32_files[idx];
        if (fp) {
            if (pOv) {
                uint64_t off = ((uint64_t)MR32(pOv + 12) << 32) | (uint64_t)MR32(pOv + 8);
                fseek(fp, (long)off, SEEK_SET);
            }
            if (nBytes == 0u) {
                ok = 1u;
            } else if (pBuf >= GUEST_NULL_GUARD_LIMIT && (uint64_t)pBuf + (uint64_t)nBytes <= (uint64_t)GUEST_END) {
                got = (uint32_t)fread(g_mem + pBuf, 1, nBytes, fp);
                ok = 1u;
            }
        }
        file_lock_release();
    }

    if (pDone) MR32(pDone) = got;
    if (pOv) {
        MR32(pOv + 0) = ok ? 0u : 0xC0000008u; /* Internal = STATUS_SUCCESS */
        MR32(pOv + 4) = got;                   /* InternalHigh = bytes transferred */
        uint32_t hEv = MR32(pOv + 16);
        if (hEv && ok) {
            win32_signal_event(hEv);
        }
    }
    w32_set_last_error(c, ok ? 0u : 6u);
    c->eax = ok;
    c->esp += 20;
}
void win32_shim_GetFileSize(CPU *c) {
    uint32_t hFile = MR32(c->esp);
    uint32_t pHigh = MR32(c->esp + 4);
    uint32_t idx   = hFile >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_FILE) {
        file_lock_acquire();
        FILE *fp = g_win32_files[idx];
        if (fp) {
            long cur = ftell(fp);
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, cur >= 0 ? cur : 0, SEEK_SET);
            uint64_t usz = (sz >= 0) ? (uint64_t)sz : 0ull;
            if (pHigh) MR32(pHigh) = (uint32_t)(usz >> 32);
            w32_set_last_error(c, 0u);
            c->eax = (uint32_t)(usz & 0xFFFFFFFFu);
            file_lock_release();
            c->esp += 8;
            return;
        }
        file_lock_release();
    }
    if (pHigh) MR32(pHigh) = 0;
    w32_set_last_error(c, 6u);
    c->eax = 0xFFFFFFFFu;
    c->esp += 8;
}
void win32_shim_GetProcAddress(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_OutputDebugStringA(CPU *c) {
    const char *s = w32_str(MR32(c->esp));
    fputs(s, stderr);
    c->esp += 4;
}
void win32_shim_QueryPerformanceFrequency(CPU *c) {
    uint32_t pFreq = MR32(c->esp);
    if (pFreq) MR64(pFreq) = 1000000ull; /* 1 MHz */
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_SetEvent(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 1u);
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, g_handles[idx].extra ? 0x7fffffffu : 1u);
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_InterlockedCompareExchange(CPU *c) {
    uint32_t pDest = MR32(c->esp);
    uint32_t exch  = MR32(c->esp + 4);
    uint32_t comp  = MR32(c->esp + 8);
    if (pDest) {
        uint32_t expected = comp;
        PS_ATOMIC_CAS32(pDest, &expected, exch);
        c->eax = expected;
    } else {
        c->eax = 0u;
    }
    c->esp += 12;
}
void win32_shim_PulseEvent(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 1u);
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, g_handles[idx].extra ? 0x7fffffffu : 1u);
        if (!g_handles[idx].extra) {
            PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 0u);
        }
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_GetPriorityClass(CPU *c) {
    c->eax = 0x20; /* NORMAL_PRIORITY_CLASS */
    c->esp += 4;
}
void win32_shim_SetPriorityClass(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_RemoveDirectoryW(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateDirectoryW(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_FindNextFileW(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_FindFirstFileW(CPU *c) {
    c->eax = (uint32_t)-1; /* INVALID_HANDLE_VALUE */
    c->esp += 8;
}
void win32_shim_WideCharToMultiByte(CPU *c) {
    uint32_t src = MR32(c->esp + 8);
    int cchWide = (int)MR32(c->esp + 12);
    uint32_t dst = MR32(c->esp + 16);
    int cbMulti = (int)MR32(c->esp + 20);
    int len = 0;
    if (cchWide < 0) {
        if (src >= GUEST_NULL_GUARD_LIMIT && src < GUEST_HEAP_LIMIT) {
            while (len < 4096 && MR16(src + len * 2) != 0) len++;
            len++;
        } else {
            len = 1;
        }
    } else {
        len = cchWide;
    }
    if (cbMulti == 0) {
        c->eax = (uint32_t)len;
    } else {
        for (int i = 0; i < len && i < cbMulti; ++i) {
            MR8(dst + i) = (uint8_t)MR16(src + i * 2);
        }
        c->eax = (uint32_t)(len < cbMulti ? len : cbMulti);
    }
    c->esp += 32;
}
void win32_shim_MoveFileW(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_DeleteFileW(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_SetEndOfFile(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateFileW(CPU *c) {
    uint32_t wpath_va = MR32(c->esp);
    uint32_t access   = MR32(c->esp + 4);
    char ascii_path[260];
    size_t n = 0;
    if (wpath_va >= GUEST_NULL_GUARD_LIMIT && wpath_va < GUEST_HEAP_LIMIT) {
        while (n + 1 < sizeof(ascii_path)) {
            uint16_t ch = MR16(wpath_va + (uint32_t)(n * 2));
            if (ch == 0) break;
            ascii_path[n++] = (char)(ch & 0xFFu);
        }
    }
    ascii_path[n] = '\0';
    bool read_only = (access & 0x40000000u) == 0u;
    file_lock_acquire();
    FILE *fp = win32_open_game_file(ascii_path, read_only);
    uint32_t log_idx = PS_HOST_ATOMIC_FETCH_ADD32(&g_io_log_count, 1u);
    if (fp) {
        uint32_t h = alloc_handle(HANDLE_FILE, ascii_path);
        uint32_t idx = h >> 2;
        if (idx < MAX_WIN32_HANDLES) g_win32_files[idx] = fp;
        file_lock_release();
        if (log_idx < 32u) {
            printf("[IO] CreateFileW('%s') -> handle=0x%x\n", ascii_path, h);
            fflush(stdout);
        }
        w32_set_last_error(c, 0u);
        c->eax = h;
    } else {
        file_lock_release();
        if (log_idx < 32u) {
            printf("[IO] CreateFileW('%s') -> NOT FOUND\n", ascii_path);
            fflush(stdout);
        }
        w32_set_last_error(c, 2u); /* ERROR_FILE_NOT_FOUND */
        c->eax = 0xFFFFFFFFu;
    }
    c->esp += 28;
}
void win32_shim_IsDebuggerPresent(CPU *c) {
    c->eax = 0;
    c->esp += 0;
}
void win32_shim_GetLastError(CPU *c) {
    c->eax = w32_get_last_error(c);
    c->esp += 0;
}
void win32_shim_IsBadReadPtr(CPU *c) {
    uint32_t lp = MR32(c->esp);
    uint32_t cb = MR32(c->esp + 4);
    c->eax = guest_is_valid_va(lp, cb) ? 0u : 1u;
    c->esp += 8;
}
void win32_shim_QueryPerformanceCounter(CPU *c) {
    uint32_t pCounter = MR32(c->esp);
    if (pCounter) {
        static uint32_t s_qpc_lo = 1000000u;
        uint32_t next = PS_HOST_ATOMIC_FETCH_ADD32(&s_qpc_lo, 16666u) + 16666u;
        MR64(pCounter) = (uint64_t)next;
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateThread(CPU *c) {
    uint32_t stack_sz   = MR32(c->esp + 4);
    uint32_t start_addr = MR32(c->esp + 8);
    uint32_t param      = MR32(c->esp + 12);
    uint32_t flags      = MR32(c->esp + 16);
    uint32_t pThrdId    = MR32(c->esp + 20);
    uint32_t tid        = 0u;
    uint32_t h = win32_create_guest_thread(start_addr, param, stack_sz, flags, &tid);
    if (pThrdId) MR32(pThrdId) = tid;
    c->eax = h;
    c->esp += 24;
}
void win32_shim_GetFileSizeEx(CPU *c) {
    uint32_t hFile = MR32(c->esp);
    uint32_t pSize = MR32(c->esp + 4);
    uint32_t idx   = hFile >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_FILE) {
        file_lock_acquire();
        FILE *fp = g_win32_files[idx];
        if (fp) {
            long cur = ftell(fp);
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, cur >= 0 ? cur : 0, SEEK_SET);
            if (pSize) MR64(pSize) = (sz >= 0) ? (uint64_t)sz : 0ull;
            file_lock_release();
            w32_set_last_error(c, 0u);
            c->eax = 1;
            c->esp += 8;
            return;
        }
        file_lock_release();
    }
    w32_set_last_error(c, 6u);
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_SetFilePointerEx(CPU *c) {
    uint32_t hFile   = MR32(c->esp);
    int64_t  dist    = (int64_t)MR64(c->esp + 4);
    uint32_t pNewPos = MR32(c->esp + 12);
    uint32_t method  = MR32(c->esp + 16);
    uint32_t idx     = hFile >> 2;
    int whence = (method == 1u) ? SEEK_CUR : ((method == 2u) ? SEEK_END : SEEK_SET);

    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_FILE) {
        file_lock_acquire();
        FILE *fp = g_win32_files[idx];
        if (fp && fseek(fp, (long)dist, whence) == 0) {
            long pos = ftell(fp);
            if (pNewPos) MR64(pNewPos) = (pos >= 0) ? (uint64_t)pos : 0ull;
            file_lock_release();
            w32_set_last_error(c, 0u);
            c->eax = 1;
            c->esp += 20;
            return;
        }
        file_lock_release();
    }
    w32_set_last_error(c, 6u);
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_RaiseException(CPU *c) {
    c->esp += 16;
}
void win32_shim_ReleaseSemaphore(CPU *c) {
    uint32_t h     = MR32(c->esp);
    uint32_t count = MR32(c->esp + 4);
    uint32_t pPrev = MR32(c->esp + 8);
    uint32_t idx   = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_SEMAPHORE && count > 0u) {
        uint32_t prev = PS_HOST_ATOMIC_FETCH_ADD32(&g_handles[idx].state, count);
        if (pPrev) MR32(pPrev) = prev;
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, count);
        c->eax = 1;
    } else {
        c->eax = 0;
    }
    c->esp += 12;
}
void win32_shim_InterlockedDecrement(CPU *c) {
    uint32_t pAdd = MR32(c->esp);
    c->eax = pAdd ? (PS_ATOMIC_FETCH_ADD32(pAdd, (uint32_t)-1) - 1u) : 0u;
    c->esp += 4;
}
void win32_shim_CreateSemaphoreA(CPU *c) {
    uint32_t init_cnt = MR32(c->esp + 4);
    uint32_t max_cnt  = MR32(c->esp + 8);
    const char *name  = MR32(c->esp + 12) ? w32_str(MR32(c->esp + 12)) : "NFS_Sem";
    uint32_t h = alloc_handle(HANDLE_SEMAPHORE, name);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        g_handles[idx].extra = max_cnt ? max_cnt : 0x7fffffffu;
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, init_cnt);
    }
    c->eax = h;
    c->esp += 16;
}
void win32_shim_InterlockedExchangeAdd(CPU *c) {
    uint32_t pAdd = MR32(c->esp);
    uint32_t val  = MR32(c->esp + 4);
    c->eax = pAdd ? PS_ATOMIC_FETCH_ADD32(pAdd, val) : 0u;
    c->esp += 8;
}
void win32_shim_SetThreadIdealProcessor(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_TlsGetValue(CPU *c) {
    uint32_t idx = MR32(c->esp);
    if (idx < 64u) {
        if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x0f10u <= GUEST_HEAP_LIMIT) {
            c->eax = MR32(c->fs_base + 0x0e10u + idx * 4u);
        } else {
            c->eax = g_tls_slots[idx];
        }
        w32_set_last_error(c, 0u);
    } else {
        c->eax = 0u;
        w32_set_last_error(c, 87u);
    }
    c->esp += 4;
}
void win32_shim_TlsSetValue(CPU *c) {
    uint32_t idx = MR32(c->esp);
    uint32_t val = MR32(c->esp + 4);
    if (idx < 64u) {
        if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x0f10u <= GUEST_HEAP_LIMIT) {
            MR32(c->fs_base + 0x0e10u + idx * 4u) = val;
        } else {
            g_tls_slots[idx] = val;
        }
        c->eax = 1u;
    } else {
        c->eax = 0u;
    }
    c->esp += 8;
}
void win32_shim_TlsAlloc(CPU *c) {
    while (1) {
        uint64_t cur = PS_HOST_ATOMIC_LOAD64(&g_tls_bitmap);
        uint32_t chosen = 64u;
        for (uint32_t i = 0; i < 64u; ++i) {
            if (!(cur & (1ull << i))) {
                chosen = i;
                break;
            }
        }
        if (chosen >= 64u) {
            c->eax = (uint32_t)-1; /* TLS_OUT_OF_INDEXES */
            c->esp += 0;
            return;
        }
        uint64_t next = cur | (1ull << chosen);
        if (PS_HOST_ATOMIC_CAS64(&g_tls_bitmap, &cur, next)) {
            g_tls_slots[chosen] = 0u;
            if (c && c->fs_base >= GUEST_NULL_GUARD_LIMIT && c->fs_base + 0x0f10u <= GUEST_HEAP_LIMIT) {
                MR32(c->fs_base + 0x0e10u + chosen * 4u) = 0u;
            }
            c->eax = chosen;
            c->esp += 0;
            return;
        }
    }
}
void win32_shim_CreateMutexA(CPU *c) {
    uint32_t init_owner = MR32(c->esp + 4) ? 1u : 0u;
    const char *name = MR32(c->esp + 8) ? w32_str(MR32(c->esp + 8)) : "NFS_Mutex";
    uint32_t h = alloc_handle(HANDLE_MUTEX, name);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, init_owner);
    }
    c->eax = h;
    c->esp += 12;
}
void win32_shim_VirtualProtect(CPU *c) {
    uint32_t pOld = MR32(c->esp + 12);
    if (pOld) MR32(pOld) = 0x40; /* PAGE_EXECUTE_READWRITE */
    c->eax = 1;
    c->esp += 16;
}
void win32_shim_GetCurrentDirectoryA(CPU *c) {
    uint32_t len = MR32(c->esp);
    uint32_t buf = MR32(c->esp + 4);
    if (buf && len > 2) strcpy((char *)(g_mem + buf), ".");
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_ResetEvent(CPU *c) {
    uint32_t h = MR32(c->esp);
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 0u);
    }
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_CreateFileA(CPU *c) {
    const char *path = w32_str(MR32(c->esp));
    uint32_t access  = MR32(c->esp + 4);
    bool read_only   = (access & 0x40000000u) == 0u;
    file_lock_acquire();
    FILE *fp = win32_open_game_file(path, read_only);
    uint32_t log_idx = PS_HOST_ATOMIC_FETCH_ADD32(&g_io_log_count, 1u);
    if (fp) {
        uint32_t h = alloc_handle(HANDLE_FILE, path);
        uint32_t idx = h >> 2;
        if (idx < MAX_WIN32_HANDLES) g_win32_files[idx] = fp;
        file_lock_release();
        if (log_idx < 32u) {
            printf("[IO] CreateFileA('%s') -> handle=0x%x\n", path, h);
            fflush(stdout);
        }
        w32_set_last_error(c, 0u);
        c->eax = h;
    } else {
        file_lock_release();
        if (log_idx < 32u) {
            printf("[IO] CreateFileA('%s') -> NOT FOUND\n", path);
            fflush(stdout);
        }
        w32_set_last_error(c, 2u); /* ERROR_FILE_NOT_FOUND */
        c->eax = 0xFFFFFFFFu;
    }
    c->esp += 28;
}
void win32_shim_DispatchMessageA(CPU *c) {
    uint32_t pMsg = MR32(c->esp);
    if (g_wnd_proc && pMsg) {
        uint32_t hwnd = MR32(pMsg + 0);
        uint32_t msg  = MR32(pMsg + 4);
        uint32_t wp   = MR32(pMsg + 8);
        uint32_t lp   = MR32(pMsg + 12);
        uint32_t old_esp = c->esp;
        c->esp -= 4; MR32(c->esp) = lp;
        c->esp -= 4; MR32(c->esp) = wp;
        c->esp -= 4; MR32(c->esp) = msg;
        c->esp -= 4; MR32(c->esp) = hwnd;
        c->esp -= 4; MR32(c->esp) = 0x00828ae0u; /* Return address for __stdcall WndProc */
        DISPATCH_CALL(c, g_wnd_proc);
        c->esp = old_esp;
    } else {
        c->eax = 0;
    }
    c->esp += 4;
}
void win32_shim_TranslateMessage(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_GetMessageA(CPU *c) {
    c->eax = 1;
    c->esp += 16;
}
void win32_shim_ShowCursor(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_PeekMessageA(CPU *c) {
    uint32_t pMsg = MR32(c->esp);
    if (g_msg_head != g_msg_tail && pMsg) {
        MR32(pMsg + 0)  = g_msg_queue[g_msg_tail][0]; /* hwnd */
        MR32(pMsg + 4)  = g_msg_queue[g_msg_tail][1]; /* message */
        MR32(pMsg + 8)  = g_msg_queue[g_msg_tail][2]; /* wParam */
        MR32(pMsg + 12) = g_msg_queue[g_msg_tail][3]; /* lParam */
        MR32(pMsg + 16) = (uint32_t)time(NULL);        /* time */
        MR32(pMsg + 20) = 0;                           /* pt.x */
        MR32(pMsg + 24) = 0;                           /* pt.y */
        g_msg_tail = (g_msg_tail + 1u) % WIN32_MSG_QUEUE_CAPACITY;
        c->eax = 1;
    } else {
        c->eax = 0;
    }
    c->esp += 20;
}
void win32_shim_GetClientRect(CPU *c) {
    uint32_t pRect = MR32(c->esp + 4);
    if (pRect) {
        MR32(pRect + 0)  = 0;            /* left */
        MR32(pRect + 4)  = 0;            /* top */
        MR32(pRect + 8)  = g_win_width;  /* right */
        MR32(pRect + 12) = g_win_height; /* bottom */
    }
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_SetWindowLongA(CPU *c) {
    c->eax = MR32(c->esp + 8);
    c->esp += 12;
}
void win32_shim_DestroyWindow(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_SendInput(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 12;
}
void win32_shim_SetCapture(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 4;
}
void win32_shim_SystemParametersInfoA(CPU *c) {
    c->eax = 1;
    c->esp += 16;
}
void win32_shim_EnumDisplaySettingsA(CPU *c) {
    uint32_t pDev = MR32(c->esp + 8);
    if (pDev) {
        MR32(pDev + 104) = 32;           /* dmBitsPerPel */
        MR32(pDev + 108) = g_win_width;  /* dmPelsWidth */
        MR32(pDev + 112) = g_win_height; /* dmPelsHeight */
        MR32(pDev + 120) = 60;           /* dmDisplayFrequency */
    }
    c->eax = 1;
    c->esp += 12;
}
void win32_shim_EndPaint(CPU *c) {
    c->eax = 0x00030001u;
    c->esp += 8;
}
void win32_shim_BeginPaint(CPU *c) {
    c->eax = 0x00030001u;
    c->esp += 8;
}
void win32_shim_PostQuitMessage(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_MapVirtualKeyA(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 8;
}
void win32_shim_ToUnicode(CPU *c) {
    c->eax = 0;
    c->esp += 24;
}
void win32_shim_GetForegroundWindow(CPU *c) {
    c->eax = 0x00010001u;
    c->esp += 0;
}
void win32_shim_GetDesktopWindow(CPU *c) {
    c->eax = 0x00010000u;
    c->esp += 0;
}
void win32_shim_GetKeyboardLayout(CPU *c) {
    c->eax = 0x04090409u; /* US English */
    c->esp += 4;
}
void win32_shim_MapVirtualKeyExA(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 12;
}
void win32_shim_GetKeyState(CPU *c) {
    uint32_t vk = MR32(c->esp);
    int16_t state = (vk < 256u && (g_key_state[vk] & 0x80u)) ? (int16_t)0x8000 : 0;
    c->eax = (uint32_t)(uint16_t)state;
    c->esp += 4;
}
void win32_shim_IsIconic(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_MessageBoxA(CPU *c) {
    const char *txt = w32_str(MR32(c->esp + 4));
    const char *cap = w32_str(MR32(c->esp + 8));
    fprintf(stderr, "[MessageBox] %s: %s\n", cap, txt);
    c->eax = 1; /* IDOK */
    c->esp += 16;
}
void win32_shim_ReleaseCapture(CPU *c) {
    c->eax = 1;
    c->esp += 0;
}
void win32_shim_wvsprintfA(CPU *c) {
    uint32_t dst = MR32(c->esp);
    const char *fmt = w32_str(MR32(c->esp + 4));
    if (dst) strcpy((char *)(g_mem + dst), fmt);
    c->eax = (uint32_t)strlen(fmt);
    c->esp += 12;
}
void win32_shim_LoadIconA(CPU *c) {
    c->eax = 0x00020001u;
    c->esp += 8;
}
void win32_shim_LoadCursorA(CPU *c) {
    c->eax = 0x00020002u;
    c->esp += 8;
}
void win32_shim_RegisterClassExA(CPU *c) {
    uint32_t lpwcx = MR32(c->esp);
    if (lpwcx) g_wnd_proc = MR32(lpwcx + 8); /* lpfnWndProc */
    c->eax = 0xC001; /* Atom */
    c->esp += 4;
}
void win32_shim_AdjustWindowRect(CPU *c) {
    c->eax = 1;
    c->esp += 12;
}
void win32_shim_CreateWindowExA(CPU *c) {
    c->eax = 0x00010001u; /* HWND */
    c->esp += 48;
}
void win32_shim_UpdateWindow(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_SetCursor(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 4;
}
void win32_shim_SetFocus(CPU *c) {
    c->eax = MR32(c->esp);
    c->esp += 4;
}
void win32_shim_SetForegroundWindow(CPU *c) {
    c->eax = 1;
    c->esp += 4;
}
void win32_shim_GetWindowRect(CPU *c) {
    uint32_t pRect = MR32(c->esp + 4);
    if (pRect) {
        MR32(pRect + 0)  = 0;            /* left */
        MR32(pRect + 4)  = 0;            /* top */
        MR32(pRect + 8)  = g_win_width;  /* right */
        MR32(pRect + 12) = g_win_height; /* bottom */
    }
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_ShowWindow(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_GetWindowLongA(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_DefWindowProcA(CPU *c) {
    c->eax = 0;
    c->esp += 16;
}
void win32_shim_PostMessageA(CPU *c) {
    c->eax = 1;
    c->esp += 16;
}
void win32_shim_CheckTokenMembership(CPU *c) {
    uint32_t pIsMember = MR32(c->esp + 8);
    if (pIsMember) MR32(pIsMember) = 1; /* TRUE */
    c->eax = 1;
    c->esp += 12;
}
void win32_shim_FreeSid(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_RegCreateKeyA(CPU *c) {
    uint32_t phk = MR32(c->esp + 8);
    if (phk) MR32(phk) = 0x80000001u;
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_RegOpenKeyExA(CPU *c) {
    uint32_t phk = MR32(c->esp + 16);
    if (phk) MR32(phk) = 0x80000001u; /* HKEY_CURRENT_USER pseudo */
    c->eax = 0; /* ERROR_SUCCESS */
    c->esp += 20;
}
void win32_shim_RegCloseKey(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_RegSetValueExA(CPU *c) {
    c->eax = 0;
    c->esp += 24;
}
void win32_shim_RegQueryValueExA(CPU *c) {
    const char *valName = w32_str(MR32(c->esp + 4));
    uint32_t pType = MR32(c->esp + 12);
    uint32_t pData = MR32(c->esp + 16);
    uint32_t pCb   = MR32(c->esp + 20);
    if (pType) MR32(pType) = 1; /* REG_SZ */
    if (pData && pCb && MR32(pCb) > 0) {
        if (strstr(valName, "Language") || strstr(valName, "Locale")) {
            strcpy((char *)(g_mem + pData), "English");
        } else {
            strcpy((char *)(g_mem + pData), ".");
        }
    }
    c->eax = 0; /* ERROR_SUCCESS */
    c->esp += 24;
}
void win32_shim_CryptReleaseContext(CPU *c) {
    c->eax = 1;
    c->esp += 8;
}
void win32_shim_CryptGenRandom(CPU *c) {
    uint32_t len = MR32(c->esp + 4);
    uint32_t buf = MR32(c->esp + 8);
    for (uint32_t i = 0; i < len; ++i) MR8(buf + i) = (uint8_t)rand();
    c->eax = 1;
    c->esp += 12;
}
void win32_shim_CryptAcquireContextA(CPU *c) {
    uint32_t phProv = MR32(c->esp);
    if (phProv) MR32(phProv) = 0x4000;
    c->eax = 1;
    c->esp += 20;
}
void win32_shim_AllocateAndInitializeSid(CPU *c) {
    uint32_t pSid = MR32(c->esp + 40);
    if (pSid) MR32(pSid) = 0x5000;
    c->eax = 1;
    c->esp += 44;
}
void win32_shim_SHGetFolderPathA(CPU *c) {
    uint32_t pPath = MR32(c->esp + 16);
    if (pPath) strcpy((char *)(g_mem + pPath), ".");
    c->eax = 0; /* S_OK */
    c->esp += 20;
}
void win32_shim_ord_8(CPU *c) {
    uint32_t val = MR32(c->esp);
    c->eax = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
    c->esp += 4;
}
void win32_shim_ord_115(CPU *c) {
    uint32_t pData = MR32(c->esp + 4);
    if (pData) memset(g_mem + pData, 0, 400);
    c->eax = 0; /* Success */
    c->esp += 8;
}
void win32_shim_ord_14(CPU *c) {
    uint32_t val = MR32(c->esp);
    c->eax = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
    c->esp += 4;
}
void win32_shim_ord_111(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ord_116(CPU *c) {
    c->eax = 0;
    c->esp += 0;
}
void win32_shim_ord_9(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ord_15(CPU *c) {
    c->eax = 0;
    c->esp += 16;
}
void win32_shim_ord_11(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_52(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ord_12(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_WSACreateEvent(CPU *c) {
    c->eax = 0;
    c->esp += 0;
}
void win32_shim_WSACloseEvent(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_WSASetEvent(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_WSARecv(CPU *c) {
    c->eax = 0;
    c->esp += 28;
}
void win32_shim_WSARecvFrom(CPU *c) {
    c->eax = 0;
    c->esp += 36;
}
void win32_shim_WSAResetEvent(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_WSAWaitForMultipleEvents(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_WSAGetOverlappedResult(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_ord_2(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_1(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_5(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_6(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_57(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_WSAIoctl(CPU *c) {
    c->eax = 0;
    c->esp += 36;
}
void win32_shim_ord_55(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_51(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_56(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_3(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ord_18(CPU *c) {
    c->eax = 0;
    c->esp += 16;
}
void win32_shim_ord_19(CPU *c) {
    c->eax = 0;
    c->esp += 24;
}
void win32_shim_ord_16(CPU *c) {
    c->eax = 0;
    c->esp += 24;
}
void win32_shim_ord_4(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_7(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_ord_21(CPU *c) {
    c->eax = 0;
    c->esp += 8;
}
void win32_shim_ord_10(CPU *c) {
    c->eax = 0;
    c->esp += 4;
}
void win32_shim_ord_23(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_20(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_ord_22(CPU *c) {
    c->eax = 0;
    c->esp += 12;
}
void win32_shim_ord_112(CPU *c) {
    c->eax = 0;
    c->esp += 0;
}
void win32_shim_ord_17(CPU *c) {
    c->eax = 0;
    c->esp += 20;
}
void win32_shim_UuidToStringA(CPU *c) {
    uint32_t pStr = MR32(c->esp + 4);
    uint32_t gstr = guest_heap_alloc(40, 4);
    if (gstr) strcpy((char *)(g_mem + gstr), "00000000-0000-0000-0000-000000000000");
    if (pStr) MR32(pStr) = gstr;
    c->eax = 0; /* RPC_S_OK */
    c->esp += 8;
}
void win32_shim_RpcStringFreeA(CPU *c) {
    c->eax = 0; /* RPC_S_OK */
    c->esp += 4;
}
void win32_shim_CoCreateGuid(CPU *c) {
    uint32_t pGuid = MR32(c->esp);
    if (pGuid) {
        for (int i = 0; i < 16; ++i) MR8(pGuid + i) = (uint8_t)rand();
    }
    c->eax = 0; /* S_OK */
    c->esp += 4;
}
void win32_shim_std_string_copy_ctor(CPU *c) {
    c->eax = c->ecx;
    c->esp += 4;
}
void win32_shim_std_string_dtor(CPU *c) {
    c->eax = c->ecx;
    c->esp += 0;
}
void win32_shim_std_string_ctor_cstr(CPU *c) {
    c->eax = c->ecx;
    c->esp += 4;
}
void win32_shim_timeEndPeriod(CPU *c) {
    c->eax = 0; /* TIMERR_NOERROR */
    c->esp += 4;
}
void win32_shim_timeGetTime(CPU *c) {
    static uint32_t s_tick = 50000;
    s_tick += 16;
    c->eax = s_tick;
    c->esp += 0;
}
void win32_shim_timeBeginPeriod(CPU *c) {
    c->eax = 0; /* TIMERR_NOERROR */
    c->esp += 4;
}
void win32_shim_Netbios(CPU *c) {
    c->eax = 0; /* NRC_GOODRET */
    c->esp += 4;
}

/* --------------------------------------------------------------------------
 * Master Win32 IAT Table (198 entries)
 * -------------------------------------------------------------------------- */
static const win32_import_entry_t g_win32_imports[198] = {
    { 0x00967040u, "KERNEL32.dll", "MultiByteToWideChar", win32_shim_MultiByteToWideChar, 24u },
    { 0x00967044u, "KERNEL32.dll", "SuspendThread", win32_shim_SuspendThread, 4u },
    { 0x00967048u, "KERNEL32.dll", "ResumeThread", win32_shim_ResumeThread, 4u },
    { 0x0096704cu, "KERNEL32.dll", "GetVersionExA", win32_shim_GetVersionExA, 4u },
    { 0x00967050u, "KERNEL32.dll", "GetLongPathNameA", win32_shim_GetLongPathNameA, 12u },
    { 0x00967054u, "KERNEL32.dll", "GetDriveTypeA", win32_shim_GetDriveTypeA, 4u },
    { 0x00967058u, "KERNEL32.dll", "GetLogicalDrives", win32_shim_GetLogicalDrives, 0u },
    { 0x0096705cu, "KERNEL32.dll", "FindClose", win32_shim_FindClose, 4u },
    { 0x00967060u, "KERNEL32.dll", "FindNextFileA", win32_shim_FindNextFileA, 8u },
    { 0x00967064u, "KERNEL32.dll", "FindFirstFileA", win32_shim_FindFirstFileA, 8u },
    { 0x00967068u, "KERNEL32.dll", "FreeLibrary", win32_shim_FreeLibrary, 4u },
    { 0x0096706cu, "KERNEL32.dll", "CreateDirectoryA", win32_shim_CreateDirectoryA, 8u },
    { 0x00967070u, "KERNEL32.dll", "GetModuleHandleA", win32_shim_GetModuleHandleA, 4u },
    { 0x00967074u, "KERNEL32.dll", "GetSystemInfo", win32_shim_GetSystemInfo, 4u },
    { 0x00967078u, "KERNEL32.dll", "Sleep", win32_shim_Sleep, 4u },
    { 0x0096707cu, "KERNEL32.dll", "Process32Next", win32_shim_Process32Next, 8u },
    { 0x00967080u, "KERNEL32.dll", "Process32First", win32_shim_Process32First, 8u },
    { 0x00967084u, "KERNEL32.dll", "CreateToolhelp32Snapshot", win32_shim_CreateToolhelp32Snapshot, 8u },
    { 0x00967088u, "KERNEL32.dll", "SetErrorMode", win32_shim_SetErrorMode, 4u },
    { 0x0096708cu, "KERNEL32.dll", "GetTickCount", win32_shim_GetTickCount, 0u },
    { 0x00967090u, "KERNEL32.dll", "SetThreadPriority", win32_shim_SetThreadPriority, 8u },
    { 0x00967094u, "KERNEL32.dll", "GetSystemTimeAsFileTime", win32_shim_GetSystemTimeAsFileTime, 4u },
    { 0x00967098u, "KERNEL32.dll", "GetCurrentProcessId", win32_shim_GetCurrentProcessId, 0u },
    { 0x0096709cu, "KERNEL32.dll", "GetCurrentThreadId", win32_shim_GetCurrentThreadId, 0u },
    { 0x009670a0u, "KERNEL32.dll", "SetUnhandledExceptionFilter", win32_shim_SetUnhandledExceptionFilter, 4u },
    { 0x009670a4u, "KERNEL32.dll", "UnhandledExceptionFilter", win32_shim_UnhandledExceptionFilter, 4u },
    { 0x009670a8u, "KERNEL32.dll", "GetCurrentProcess", win32_shim_GetCurrentProcess, 0u },
    { 0x009670acu, "KERNEL32.dll", "TerminateProcess", win32_shim_TerminateProcess, 8u },
    { 0x009670b0u, "KERNEL32.dll", "CloseHandle", win32_shim_CloseHandle, 4u },
    { 0x009670b4u, "KERNEL32.dll", "InterlockedExchange", win32_shim_InterlockedExchange, 8u },
    { 0x009670b8u, "KERNEL32.dll", "ReleaseMutex", win32_shim_ReleaseMutex, 4u },
    { 0x009670bcu, "KERNEL32.dll", "CreateMutexW", win32_shim_CreateMutexW, 12u },
    { 0x009670c0u, "KERNEL32.dll", "GetSystemDirectoryA", win32_shim_GetSystemDirectoryA, 8u },
    { 0x009670c4u, "KERNEL32.dll", "LoadLibraryA", win32_shim_LoadLibraryA, 4u },
    { 0x009670c8u, "KERNEL32.dll", "LeaveCriticalSection", win32_shim_LeaveCriticalSection, 4u },
    { 0x009670ccu, "KERNEL32.dll", "TryEnterCriticalSection", win32_shim_TryEnterCriticalSection, 4u },
    { 0x009670d0u, "KERNEL32.dll", "EnterCriticalSection", win32_shim_EnterCriticalSection, 4u },
    { 0x009670d4u, "KERNEL32.dll", "DeleteCriticalSection", win32_shim_DeleteCriticalSection, 4u },
    { 0x009670d8u, "KERNEL32.dll", "InitializeCriticalSection", win32_shim_InitializeCriticalSection, 4u },
    { 0x009670dcu, "KERNEL32.dll", "WaitForSingleObject", win32_shim_WaitForSingleObject, 8u },
    { 0x009670e0u, "KERNEL32.dll", "CreateEventA", win32_shim_CreateEventA, 16u },
    { 0x009670e4u, "KERNEL32.dll", "GetDiskFreeSpaceExA", win32_shim_GetDiskFreeSpaceExA, 16u },
    { 0x009670e8u, "KERNEL32.dll", "SetWaitableTimer", win32_shim_SetWaitableTimer, 24u },
    { 0x009670ecu, "KERNEL32.dll", "SystemTimeToFileTime", win32_shim_SystemTimeToFileTime, 8u },
    { 0x009670f0u, "KERNEL32.dll", "GetSystemTime", win32_shim_GetSystemTime, 4u },
    { 0x009670f4u, "KERNEL32.dll", "CreateWaitableTimerA", win32_shim_CreateWaitableTimerA, 12u },
    { 0x009670f8u, "KERNEL32.dll", "DuplicateHandle", win32_shim_DuplicateHandle, 28u },
    { 0x009670fcu, "KERNEL32.dll", "GetCurrentThread", win32_shim_GetCurrentThread, 0u },
    { 0x00967100u, "KERNEL32.dll", "TerminateThread", win32_shim_TerminateThread, 8u },
    { 0x00967104u, "KERNEL32.dll", "SleepEx", win32_shim_SleepEx, 8u },
    { 0x00967108u, "KERNEL32.dll", "GetThreadPriority", win32_shim_GetThreadPriority, 4u },
    { 0x0096710cu, "KERNEL32.dll", "GetExitCodeThread", win32_shim_GetExitCodeThread, 8u },
    { 0x00967110u, "KERNEL32.dll", "WriteFile", win32_shim_WriteFile, 20u },
    { 0x00967114u, "KERNEL32.dll", "SetFilePointer", win32_shim_SetFilePointer, 16u },
    { 0x00967118u, "KERNEL32.dll", "DeleteFileA", win32_shim_DeleteFileA, 4u },
    { 0x0096711cu, "KERNEL32.dll", "MoveFileA", win32_shim_MoveFileA, 8u },
    { 0x00967120u, "KERNEL32.dll", "ReadFile", win32_shim_ReadFile, 20u },
    { 0x00967124u, "KERNEL32.dll", "GetFileSize", win32_shim_GetFileSize, 8u },
    { 0x00967128u, "KERNEL32.dll", "GetProcAddress", win32_shim_GetProcAddress, 8u },
    { 0x0096712cu, "KERNEL32.dll", "OutputDebugStringA", win32_shim_OutputDebugStringA, 4u },
    { 0x00967130u, "KERNEL32.dll", "QueryPerformanceFrequency", win32_shim_QueryPerformanceFrequency, 4u },
    { 0x00967134u, "KERNEL32.dll", "SetEvent", win32_shim_SetEvent, 4u },
    { 0x00967138u, "KERNEL32.dll", "InterlockedCompareExchange", win32_shim_InterlockedCompareExchange, 12u },
    { 0x0096713cu, "KERNEL32.dll", "PulseEvent", win32_shim_PulseEvent, 4u },
    { 0x00967140u, "KERNEL32.dll", "GetPriorityClass", win32_shim_GetPriorityClass, 4u },
    { 0x00967144u, "KERNEL32.dll", "SetPriorityClass", win32_shim_SetPriorityClass, 8u },
    { 0x00967148u, "KERNEL32.dll", "RemoveDirectoryW", win32_shim_RemoveDirectoryW, 4u },
    { 0x0096714cu, "KERNEL32.dll", "CreateDirectoryW", win32_shim_CreateDirectoryW, 8u },
    { 0x00967150u, "KERNEL32.dll", "FindNextFileW", win32_shim_FindNextFileW, 8u },
    { 0x00967154u, "KERNEL32.dll", "FindFirstFileW", win32_shim_FindFirstFileW, 8u },
    { 0x00967158u, "KERNEL32.dll", "WideCharToMultiByte", win32_shim_WideCharToMultiByte, 32u },
    { 0x0096715cu, "KERNEL32.dll", "MoveFileW", win32_shim_MoveFileW, 8u },
    { 0x00967160u, "KERNEL32.dll", "DeleteFileW", win32_shim_DeleteFileW, 4u },
    { 0x00967164u, "KERNEL32.dll", "SetEndOfFile", win32_shim_SetEndOfFile, 4u },
    { 0x00967168u, "KERNEL32.dll", "CreateFileW", win32_shim_CreateFileW, 28u },
    { 0x0096716cu, "KERNEL32.dll", "IsDebuggerPresent", win32_shim_IsDebuggerPresent, 0u },
    { 0x00967170u, "KERNEL32.dll", "GetLastError", win32_shim_GetLastError, 0u },
    { 0x00967174u, "KERNEL32.dll", "IsBadReadPtr", win32_shim_IsBadReadPtr, 8u },
    { 0x00967178u, "KERNEL32.dll", "QueryPerformanceCounter", win32_shim_QueryPerformanceCounter, 4u },
    { 0x0096717cu, "KERNEL32.dll", "CreateThread", win32_shim_CreateThread, 24u },
    { 0x00967180u, "KERNEL32.dll", "GetFileSizeEx", win32_shim_GetFileSizeEx, 8u },
    { 0x00967184u, "KERNEL32.dll", "SetFilePointerEx", win32_shim_SetFilePointerEx, 16u },
    { 0x00967188u, "KERNEL32.dll", "RaiseException", win32_shim_RaiseException, 16u },
    { 0x0096718cu, "KERNEL32.dll", "ReleaseSemaphore", win32_shim_ReleaseSemaphore, 12u },
    { 0x00967190u, "KERNEL32.dll", "InterlockedDecrement", win32_shim_InterlockedDecrement, 4u },
    { 0x00967194u, "KERNEL32.dll", "CreateSemaphoreA", win32_shim_CreateSemaphoreA, 16u },
    { 0x00967198u, "KERNEL32.dll", "InterlockedExchangeAdd", win32_shim_InterlockedExchangeAdd, 8u },
    { 0x0096719cu, "KERNEL32.dll", "SetThreadIdealProcessor", win32_shim_SetThreadIdealProcessor, 8u },
    { 0x009671a0u, "KERNEL32.dll", "TlsGetValue", win32_shim_TlsGetValue, 4u },
    { 0x009671a4u, "KERNEL32.dll", "TlsSetValue", win32_shim_TlsSetValue, 8u },
    { 0x009671a8u, "KERNEL32.dll", "TlsAlloc", win32_shim_TlsAlloc, 0u },
    { 0x009671acu, "KERNEL32.dll", "CreateMutexA", win32_shim_CreateMutexA, 12u },
    { 0x009671b0u, "KERNEL32.dll", "VirtualProtect", win32_shim_VirtualProtect, 16u },
    { 0x009671b4u, "KERNEL32.dll", "GetCurrentDirectoryA", win32_shim_GetCurrentDirectoryA, 8u },
    { 0x009671b8u, "KERNEL32.dll", "ResetEvent", win32_shim_ResetEvent, 4u },
    { 0x009671bcu, "KERNEL32.dll", "CreateFileA", win32_shim_CreateFileA, 28u },
    { 0x00967464u, "USER32.dll", "DispatchMessageA", win32_shim_DispatchMessageA, 4u },
    { 0x00967468u, "USER32.dll", "TranslateMessage", win32_shim_TranslateMessage, 4u },
    { 0x0096746cu, "USER32.dll", "GetMessageA", win32_shim_GetMessageA, 16u },
    { 0x00967470u, "USER32.dll", "ShowCursor", win32_shim_ShowCursor, 4u },
    { 0x00967474u, "USER32.dll", "PeekMessageA", win32_shim_PeekMessageA, 20u },
    { 0x00967478u, "USER32.dll", "GetClientRect", win32_shim_GetClientRect, 8u },
    { 0x0096747cu, "USER32.dll", "SetWindowLongA", win32_shim_SetWindowLongA, 12u },
    { 0x00967480u, "USER32.dll", "DestroyWindow", win32_shim_DestroyWindow, 4u },
    { 0x00967484u, "USER32.dll", "SendInput", win32_shim_SendInput, 12u },
    { 0x00967488u, "USER32.dll", "SetCapture", win32_shim_SetCapture, 4u },
    { 0x0096748cu, "USER32.dll", "SystemParametersInfoA", win32_shim_SystemParametersInfoA, 16u },
    { 0x00967490u, "USER32.dll", "EnumDisplaySettingsA", win32_shim_EnumDisplaySettingsA, 12u },
    { 0x00967494u, "USER32.dll", "EndPaint", win32_shim_EndPaint, 8u },
    { 0x00967498u, "USER32.dll", "BeginPaint", win32_shim_BeginPaint, 8u },
    { 0x0096749cu, "USER32.dll", "PostQuitMessage", win32_shim_PostQuitMessage, 4u },
    { 0x009674a0u, "USER32.dll", "MapVirtualKeyA", win32_shim_MapVirtualKeyA, 8u },
    { 0x009674a4u, "USER32.dll", "ToUnicode", win32_shim_ToUnicode, 24u },
    { 0x009674a8u, "USER32.dll", "GetForegroundWindow", win32_shim_GetForegroundWindow, 0u },
    { 0x009674acu, "USER32.dll", "GetDesktopWindow", win32_shim_GetDesktopWindow, 0u },
    { 0x009674b0u, "USER32.dll", "GetKeyboardLayout", win32_shim_GetKeyboardLayout, 4u },
    { 0x009674b4u, "USER32.dll", "MapVirtualKeyExA", win32_shim_MapVirtualKeyExA, 12u },
    { 0x009674b8u, "USER32.dll", "GetKeyState", win32_shim_GetKeyState, 4u },
    { 0x009674bcu, "USER32.dll", "IsIconic", win32_shim_IsIconic, 4u },
    { 0x009674c0u, "USER32.dll", "MessageBoxA", win32_shim_MessageBoxA, 16u },
    { 0x009674c4u, "USER32.dll", "ReleaseCapture", win32_shim_ReleaseCapture, 0u },
    { 0x009674c8u, "USER32.dll", "wvsprintfA", win32_shim_wvsprintfA, 12u },
    { 0x009674ccu, "USER32.dll", "LoadIconA", win32_shim_LoadIconA, 8u },
    { 0x009674d0u, "USER32.dll", "LoadCursorA", win32_shim_LoadCursorA, 8u },
    { 0x009674d4u, "USER32.dll", "RegisterClassExA", win32_shim_RegisterClassExA, 4u },
    { 0x009674d8u, "USER32.dll", "AdjustWindowRect", win32_shim_AdjustWindowRect, 12u },
    { 0x009674dcu, "USER32.dll", "CreateWindowExA", win32_shim_CreateWindowExA, 48u },
    { 0x009674e0u, "USER32.dll", "UpdateWindow", win32_shim_UpdateWindow, 4u },
    { 0x009674e4u, "USER32.dll", "SetCursor", win32_shim_SetCursor, 4u },
    { 0x009674e8u, "USER32.dll", "SetFocus", win32_shim_SetFocus, 4u },
    { 0x009674ecu, "USER32.dll", "SetForegroundWindow", win32_shim_SetForegroundWindow, 4u },
    { 0x009674f0u, "USER32.dll", "GetWindowRect", win32_shim_GetWindowRect, 8u },
    { 0x009674f4u, "USER32.dll", "ShowWindow", win32_shim_ShowWindow, 8u },
    { 0x009674f8u, "USER32.dll", "GetWindowLongA", win32_shim_GetWindowLongA, 8u },
    { 0x009674fcu, "USER32.dll", "DefWindowProcA", win32_shim_DefWindowProcA, 16u },
    { 0x00967500u, "USER32.dll", "PostMessageA", win32_shim_PostMessageA, 16u },
    { 0x00967000u, "ADVAPI32.dll", "CheckTokenMembership", win32_shim_CheckTokenMembership, 12u },
    { 0x00967004u, "ADVAPI32.dll", "FreeSid", win32_shim_FreeSid, 4u },
    { 0x00967008u, "ADVAPI32.dll", "RegCreateKeyA", win32_shim_RegCreateKeyA, 12u },
    { 0x0096700cu, "ADVAPI32.dll", "RegOpenKeyExA", win32_shim_RegOpenKeyExA, 20u },
    { 0x00967010u, "ADVAPI32.dll", "RegCloseKey", win32_shim_RegCloseKey, 4u },
    { 0x00967014u, "ADVAPI32.dll", "RegSetValueExA", win32_shim_RegSetValueExA, 24u },
    { 0x00967018u, "ADVAPI32.dll", "RegQueryValueExA", win32_shim_RegQueryValueExA, 24u },
    { 0x0096701cu, "ADVAPI32.dll", "CryptReleaseContext", win32_shim_CryptReleaseContext, 8u },
    { 0x00967020u, "ADVAPI32.dll", "CryptGenRandom", win32_shim_CryptGenRandom, 12u },
    { 0x00967024u, "ADVAPI32.dll", "CryptAcquireContextA", win32_shim_CryptAcquireContextA, 20u },
    { 0x00967028u, "ADVAPI32.dll", "AllocateAndInitializeSid", win32_shim_AllocateAndInitializeSid, 44u },
    { 0x0096745cu, "SHFOLDER.dll", "SHGetFolderPathA", win32_shim_SHGetFolderPathA, 20u },
    { 0x00967518u, "WS2_32.dll", "ord_8", win32_shim_ord_8, 4u },
    { 0x0096751cu, "WS2_32.dll", "ord_115", win32_shim_ord_115, 8u },
    { 0x00967520u, "WS2_32.dll", "ord_14", win32_shim_ord_14, 4u },
    { 0x00967524u, "WS2_32.dll", "ord_111", win32_shim_ord_111, 4u },
    { 0x00967528u, "WS2_32.dll", "ord_116", win32_shim_ord_116, 0u },
    { 0x0096752cu, "WS2_32.dll", "ord_9", win32_shim_ord_9, 4u },
    { 0x00967530u, "WS2_32.dll", "ord_15", win32_shim_ord_15, 16u },
    { 0x00967534u, "WS2_32.dll", "ord_11", win32_shim_ord_11, 12u },
    { 0x00967538u, "WS2_32.dll", "ord_52", win32_shim_ord_52, 4u },
    { 0x0096753cu, "WS2_32.dll", "ord_12", win32_shim_ord_12, 8u },
    { 0x00967540u, "WS2_32.dll", "WSACreateEvent", win32_shim_WSACreateEvent, 0u },
    { 0x00967544u, "WS2_32.dll", "WSACloseEvent", win32_shim_WSACloseEvent, 4u },
    { 0x00967548u, "WS2_32.dll", "WSASetEvent", win32_shim_WSASetEvent, 4u },
    { 0x0096754cu, "WS2_32.dll", "WSARecv", win32_shim_WSARecv, 28u },
    { 0x00967550u, "WS2_32.dll", "WSARecvFrom", win32_shim_WSARecvFrom, 36u },
    { 0x00967554u, "WS2_32.dll", "WSAResetEvent", win32_shim_WSAResetEvent, 4u },
    { 0x00967558u, "WS2_32.dll", "WSAWaitForMultipleEvents", win32_shim_WSAWaitForMultipleEvents, 20u },
    { 0x0096755cu, "WS2_32.dll", "WSAGetOverlappedResult", win32_shim_WSAGetOverlappedResult, 20u },
    { 0x00967560u, "WS2_32.dll", "ord_2", win32_shim_ord_2, 12u },
    { 0x00967564u, "WS2_32.dll", "ord_1", win32_shim_ord_1, 12u },
    { 0x00967568u, "WS2_32.dll", "ord_5", win32_shim_ord_5, 8u },
    { 0x0096756cu, "WS2_32.dll", "ord_6", win32_shim_ord_6, 8u },
    { 0x00967570u, "WS2_32.dll", "ord_57", win32_shim_ord_57, 20u },
    { 0x00967574u, "WS2_32.dll", "WSAIoctl", win32_shim_WSAIoctl, 36u },
    { 0x00967578u, "WS2_32.dll", "ord_55", win32_shim_ord_55, 8u },
    { 0x0096757cu, "WS2_32.dll", "ord_51", win32_shim_ord_51, 8u },
    { 0x00967580u, "WS2_32.dll", "ord_56", win32_shim_ord_56, 8u },
    { 0x00967584u, "WS2_32.dll", "ord_3", win32_shim_ord_3, 4u },
    { 0x00967588u, "WS2_32.dll", "ord_18", win32_shim_ord_18, 16u },
    { 0x0096758cu, "WS2_32.dll", "ord_19", win32_shim_ord_19, 24u },
    { 0x00967590u, "WS2_32.dll", "ord_16", win32_shim_ord_16, 24u },
    { 0x00967594u, "WS2_32.dll", "ord_4", win32_shim_ord_4, 12u },
    { 0x00967598u, "WS2_32.dll", "ord_7", win32_shim_ord_7, 20u },
    { 0x0096759cu, "WS2_32.dll", "ord_21", win32_shim_ord_21, 8u },
    { 0x009675a0u, "WS2_32.dll", "ord_10", win32_shim_ord_10, 4u },
    { 0x009675a4u, "WS2_32.dll", "ord_23", win32_shim_ord_23, 12u },
    { 0x009675a8u, "WS2_32.dll", "ord_20", win32_shim_ord_20, 20u },
    { 0x009675acu, "WS2_32.dll", "ord_22", win32_shim_ord_22, 12u },
    { 0x009675b0u, "WS2_32.dll", "ord_112", win32_shim_ord_112, 0u },
    { 0x009675b4u, "WS2_32.dll", "ord_17", win32_shim_ord_17, 20u },
    { 0x00967450u, "RPCRT4.dll", "UuidToStringA", win32_shim_UuidToStringA, 8u },
    { 0x00967454u, "RPCRT4.dll", "RpcStringFreeA", win32_shim_RpcStringFreeA, 4u },
    { 0x00967600u, "ole32.dll", "CoCreateGuid", win32_shim_CoCreateGuid, 4u },
    { 0x009671c4u, "MSVCP80.dll", "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ABV01@@Z", win32_shim_std_string_copy_ctor, 4u },
    { 0x009671c8u, "MSVCP80.dll", "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ", win32_shim_std_string_dtor, 0u },
    { 0x009671ccu, "MSVCP80.dll", "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z", win32_shim_std_string_ctor_cstr, 4u },
    { 0x00967508u, "WINMM.dll", "timeEndPeriod", win32_shim_timeEndPeriod, 4u },
    { 0x0096750cu, "WINMM.dll", "timeGetTime", win32_shim_timeGetTime, 0u },
    { 0x00967510u, "WINMM.dll", "timeBeginPeriod", win32_shim_timeBeginPeriod, 4u },
    { 0x00967448u, "NETAPI32.dll", "Netbios", win32_shim_Netbios, 4u },
};

size_t win32_get_import_count(void) { return 198; }
const win32_import_entry_t *win32_get_import_table(void) { return g_win32_imports; }

void win32_set_window_dims(uint32_t width, uint32_t height) {
    g_win_width = width;
    g_win_height = height;
}

void win32_post_key_event(uint32_t vk, bool down) {
    if (vk < 256u) {
        g_key_state[vk] = down ? 0x80u : 0x00u;
    }
    uint32_t next_head = (g_msg_head + 1u) % WIN32_MSG_QUEUE_CAPACITY;
    if (next_head != g_msg_tail) {
        g_msg_queue[g_msg_head][0] = 0x00010001u; /* hwnd */
        g_msg_queue[g_msg_head][1] = down ? 0x0100u : 0x0101u; /* WM_KEYDOWN / UP */
        g_msg_queue[g_msg_head][2] = vk; /* wParam */
        g_msg_queue[g_msg_head][3] = 0;  /* lParam */
        g_msg_head = next_head;
    }
}

bool win32_get_key_state(uint32_t vk) {
    return (vk < 256u) ? ((g_key_state[vk] & 0x80u) != 0) : false;
}

void win32_init_iat(void) {
    /* Bind all Win32 IAT slots into linear memory and g_dtab */
    for (size_t i = 0; i < 198; ++i) {
        uint32_t slot_va = g_win32_imports[i].slot_va;
        MR32(slot_va) = slot_va;
        uint32_t idx = slot_va - DISPATCH_TEXT_BASE;
        if (idx < DISPATCH_TEXT_SIZE) {
            g_dtab[idx] = g_win32_imports[i].handler;
        }
    }
}

uint32_t win32_create_event(void) {
    return alloc_handle(HANDLE_EVENT, "GuestEvent");
}

void win32_signal_event(uint32_t h) {
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 1u);
        PS_WASM_HOST_NOTIFY(&g_handles[idx].state, g_handles[idx].extra ? 0x7fffffffu : 1u);
    }
}

void win32_reset_event(uint32_t h) {
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES && g_handles[idx].type == HANDLE_EVENT) {
        PS_HOST_ATOMIC_STORE32(&g_handles[idx].state, 0u);
    }
}

uint32_t win32_get_event_state_addr(uint32_t h) {
    uint32_t idx = h >> 2;
    if (idx < MAX_WIN32_HANDLES) {
        return (uint32_t)(uintptr_t)&g_handles[idx].state;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Guest Thread Manager & Multi-Slot Worker Execution Loop
 * -------------------------------------------------------------------------- */
#define MAX_GUEST_THREADS GUEST_MAX_WORKERS
static guest_thread_desc_t g_guest_threads[MAX_GUEST_THREADS];
static uint32_t g_guest_thread_count = 0;
static volatile uint32_t g_workers_shutdown = 0;

uint32_t win32_get_guest_thread_count(void) {
    return PS_HOST_ATOMIC_LOAD32(&g_guest_thread_count);
}

uint32_t win32_create_guest_thread(uint32_t start_addr, uint32_t arglist, uint32_t stack_sz, uint32_t initflag, uint32_t *out_tid) {
    uint32_t cur = PS_HOST_ATOMIC_LOAD32(&g_guest_thread_count);
    if (cur >= MAX_GUEST_THREADS) return 0;
    uint32_t idx = PS_HOST_ATOMIC_FETCH_ADD32(&g_guest_thread_count, 1u);
    if (idx >= MAX_GUEST_THREADS) return 0;

    guest_thread_desc_t *th = &g_guest_threads[idx];

    uint32_t h = alloc_handle(HANDLE_THREAD, "GuestWorkerThread");
    uint32_t slot = h >> 2;
    if (slot < MAX_WIN32_HANDLES) {
        g_handles[slot].extra = idx;
    }

    uint32_t tid = 0x2001u + idx;
    if (out_tid) *out_tid = tid;

    th->handle = h;
    th->thread_id = tid;
    th->start_address = start_addr;
    th->arglist = arglist;
    th->stack_size = stack_sz;
    th->initflag = initflag;
    th->cpu_va = GUEST_WORKER_CPU_ADDR_N(idx);
    th->teb_va = GUEST_WORKER_TEB_ADDR_N(idx);
    th->stack_top_va = GUEST_WORKER_STACK_TOP_N(idx);
    th->suspended = (initflag & 4u) ? 1u : 0u; /* CREATE_SUSPENDED = 4 */
    th->exit_code = 0u;

    CPU *wcpu = (CPU *)(g_mem + th->cpu_va);
    memset(wcpu, 0, sizeof(CPU));
    wcpu->fcw = 0x037fu;
    guest_init_worker_teb_slot(wcpu, idx);

    /* Setup isolated worker x86 stack:
     * [esp + 4] = arglist
     * [esp]     = 0x00897709 (return address)
     */
    MR32(th->stack_top_va - 4u) = arglist;
    MR32(th->stack_top_va - 8u) = 0x00897709u;

    wcpu->esp = th->stack_top_va - 8u;
    wcpu->ebp = th->stack_top_va;
    wcpu->eip = start_addr;

    PS_HOST_ATOMIC_STORE32(&th->active, 1u);

    printf("[THREAD] CREATED: slot=%u, handle=0x%x, tid=0x%x, entry=0x%08x, arglist=0x%08x, cpu=0x%08x, esp=0x%08x, suspended=%u\n",
           idx, h, tid, start_addr, arglist, th->cpu_va, wcpu->esp, th->suspended);
    fflush(stdout);

    if (th->suspended) {
        printf("[THREAD] SUSPENDED: slot=%u, handle=0x%x holding execution pending ResumeThread\n", idx, h);
        fflush(stdout);
    } else {
        PS_HOST_ATOMIC_STORE32(&th->signal, 1u);
        PS_WASM_HOST_NOTIFY(&th->signal, 1u);
    }

    return h;
}

uint32_t win32_resume_guest_thread(uint32_t hThread) {
    uint32_t slot = hThread >> 2;
    if (slot < MAX_WIN32_HANDLES && g_handles[slot].type == HANDLE_THREAD) {
        uint32_t idx = g_handles[slot].extra;
        if (idx < MAX_GUEST_THREADS && PS_HOST_ATOMIC_LOAD32(&g_guest_threads[idx].active)) {
            uint32_t prev = g_guest_threads[idx].suspended;
            if (prev > 0u) {
                g_guest_threads[idx].suspended = prev - 1u;
                if (g_guest_threads[idx].suspended == 0u) {
                    printf("[THREAD] RESUMED: slot=%u, handle=0x%x, waking worker thread (prev_suspend=%u)\n", idx, hThread, prev);
                    fflush(stdout);
                    PS_HOST_ATOMIC_STORE32(&g_guest_threads[idx].signal, 1u);
                    PS_WASM_HOST_NOTIFY(&g_guest_threads[idx].signal, 1u);
                }
            }
            return prev;
        }
    }
    return 0;
}

const guest_thread_desc_t *win32_get_guest_thread(uint32_t hThread) {
    uint32_t slot = hThread >> 2;
    if (slot < MAX_WIN32_HANDLES && g_handles[slot].type == HANDLE_THREAD) {
        uint32_t idx = g_handles[slot].extra;
        if (idx < MAX_GUEST_THREADS && PS_HOST_ATOMIC_LOAD32(&g_guest_threads[idx].active)) {
            return &g_guest_threads[idx];
        }
    }
    return NULL;
}

void guest_worker_slot_run(uint32_t slot_idx) {
    if (slot_idx >= MAX_GUEST_THREADS) return;
    guest_thread_desc_t *th = &g_guest_threads[slot_idx];
    guest_worker_mailbox_t *mb = (guest_worker_mailbox_t *)(g_mem + GUEST_WORKER_MAILBOX_VA + slot_idx * sizeof(guest_worker_mailbox_t));

    /* Signal mailbox readiness to host and any waiters */
    PS_HOST_ATOMIC_STORE32(&mb->state, 1u); /* READY */
    PS_WASM_HOST_NOTIFY(&mb->state, 1u);

    while (!PS_HOST_ATOMIC_LOAD32(&g_workers_shutdown)) {
        while (PS_HOST_ATOMIC_LOAD32(&th->signal) == 0u && !PS_HOST_ATOMIC_LOAD32(&g_workers_shutdown)) {
#ifdef __wasm__
            PS_WASM_HOST_WAIT32(&th->signal, 0, 250000000ll);
#else
            return;
#endif
        }

        uint32_t sig = PS_HOST_ATOMIC_LOAD32(&th->signal);
        if (sig == 2u || PS_HOST_ATOMIC_LOAD32(&g_workers_shutdown)) {
            break;
        }
        if (sig == 0u) {
            continue;
        }

        /* Consume run signal */
        PS_HOST_ATOMIC_STORE32(&th->signal, 0u);
        PS_HOST_ATOMIC_STORE32(&mb->state, 2u); /* RUNNING */

        if (PS_HOST_ATOMIC_LOAD32(&th->active)) {
            CPU *c = (CPU *)(g_mem + GUEST_WORKER_CPU_ADDR_N(slot_idx));
            if (c->fs_base == 0u) {
                guest_init_worker_teb_slot(c, slot_idx);
            }
            uint32_t entry = th->start_address;
            mb->entry = entry;
            mb->cpu_va = th->cpu_va;
            if (entry) {
                printf("[THREAD] ENTRY_ENTERED: slot=%u executing start_address=0x%08x (esp=0x%08x, teb=0x%08x)\n",
                       slot_idx, entry, c->esp, c->fs_base);
                fflush(stdout);
                dispatch_indirect(c, entry);
                th->exit_code = c->eax;
                mb->exit_code = c->eax;
                PS_HOST_ATOMIC_FETCH_ADD32(&mb->completed, 1u);
                printf("[THREAD] EXITED: slot=%u entry 0x%08x completed (eax=0x%08x)\n", slot_idx, entry, c->eax);
                fflush(stdout);
            }
            uint32_t h = th->handle;
            uint32_t hslot = h >> 2;
            if (hslot < MAX_WIN32_HANDLES) {
                PS_HOST_ATOMIC_STORE32(&g_handles[hslot].state, 1u);
                PS_WASM_HOST_NOTIFY(&g_handles[hslot].state, 0x7fffffffu);
            }
        }
        PS_HOST_ATOMIC_STORE32(&mb->state, 1u); /* Back to READY */
    }
    PS_HOST_ATOMIC_STORE32(&mb->state, 3u); /* TERMINATED */
}

void guest_worker_thread_run(uint32_t cpu_va) {
    uint32_t slot_idx = 0u;
    if (cpu_va >= GUEST_WORKER_CPU_ADDR_N(0)) {
        slot_idx = (cpu_va - GUEST_WORKER_CPU_ADDR_N(0)) / GUEST_WORKER_CPU_STRIDE;
    }
    guest_worker_slot_run(slot_idx);
}

void guest_worker_thread_stop(void) {
    PS_HOST_ATOMIC_STORE32(&g_workers_shutdown, 1u);
    for (uint32_t i = 0; i < MAX_GUEST_THREADS; ++i) {
        PS_HOST_ATOMIC_STORE32(&g_guest_threads[i].signal, 2u);
        PS_WASM_HOST_NOTIFY(&g_guest_threads[i].signal, 1u);
    }
}
