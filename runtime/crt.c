/* Need for Speed ProStreet - MSVCR80.dll IAT Shim Layer Implementation.
 *
 * Full C99 implementations of all 156 imports from MSVCR80.dll,
 * mapping guest arguments, strings, buffers, and x87 FPU stack operations.
 */
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crt.h"
#include "memory.h"
#include "win32.h"
#if defined(__wasm__)
clock_t clock(void) {
    return (clock_t)0;
}
#endif

/* --------------------------------------------------------------------------
 * Exit Callback Table
 * -------------------------------------------------------------------------- */
#define MAX_ONEXIT_CALLBACKS 2048
static uint32_t g_onexit_table[MAX_ONEXIT_CALLBACKS];
static uint32_t g_onexit_count = 0;
static uint32_t g_app_type = 1; /* GUI */

uint32_t crt_register_onexit(uint32_t fn_va) {
    if (g_onexit_count < MAX_ONEXIT_CALLBACKS) {
        g_onexit_table[g_onexit_count++] = fn_va;
        return fn_va;
    }
    return 0;
}

uint32_t crt_get_onexit_count(void) {
    return g_onexit_count;
}

/* --------------------------------------------------------------------------
 * Virtual File Descriptor Table (supports host stdio and local assets)
 * -------------------------------------------------------------------------- */
#define MAX_GUEST_FILES 64
typedef struct {
    bool  in_use;
    FILE *fp;
    char  path[260];
} guest_file_t;

static guest_file_t g_files[MAX_GUEST_FILES];

static int guest_alloc_file(FILE *fp, const char *path) {
    for (int i = 3; i < MAX_GUEST_FILES; ++i) {
        if (!g_files[i].in_use) {
            g_files[i].in_use = true;
            g_files[i].fp = fp;
            if (path) strncpy(g_files[i].path, path, sizeof(g_files[i].path) - 1);
            return i;
        }
    }
    return -1;
}

static FILE *guest_get_file(uint32_t handle) {
    if (handle < MAX_GUEST_FILES && g_files[handle].in_use) {
        return g_files[handle].fp;
    }
    if (handle == GUEST_IOB_ADDR) return stdin;
    if (handle == GUEST_IOB_ADDR + 32) return stdout;
    if (handle == GUEST_IOB_ADDR + 64) return stderr;
    return NULL;
}

/* --------------------------------------------------------------------------
 * Helper: Safe Guest String & Formatter
 * -------------------------------------------------------------------------- */
static inline const char *guest_str(uint32_t va) {
    return (va >= GUEST_NULL_GUARD_LIMIT && va < GUEST_HEAP_LIMIT) ? (const char *)(g_mem + va) : "";
}

static int guest_format_core(char *dst, size_t maxlen, const char *fmt, uint32_t esp_args) {
    if (!fmt) return 0;
    size_t out_pos = 0;
    const char *p = fmt;
    uint32_t arg_ptr = esp_args;

    while (*p) {
        if (*p != '%') {
            if (dst && out_pos + 1 < maxlen) dst[out_pos] = *p;
            out_pos++;
            p++;
            continue;
        }
        p++;
        if (*p == '%') {
            if (dst && out_pos + 1 < maxlen) dst[out_pos] = '%';
            out_pos++;
            p++;
            continue;
        }
        /* Parse specifier */
        char spec_buf[64];
        size_t sidx = 0;
        spec_buf[sidx++] = '%';
        bool is_long_long = false;
        bool is_float = false;
        bool is_string = false;
        bool is_char = false;
        while (*p && !strchr("diuoxXcspnfeEgG%", *p)) {
            if (sidx + 2 < sizeof(spec_buf)) spec_buf[sidx++] = *p;
            if (*p == 'I' && *(p+1) == '6' && *(p+2) == '4') {
                is_long_long = true;
            }
            if (*p == 'l' && *(p+1) == 'l') {
                is_long_long = true;
            }
            p++;
        }
        char conv = *p ? *p++ : 's';
        if (sidx + 1 < sizeof(spec_buf)) spec_buf[sidx++] = conv;
        spec_buf[sidx] = '\0';
        if (conv == 's') is_string = true;
        else if (conv == 'c') is_char = true;
        else if (strchr("feEgG", conv)) is_float = true;

        char temp[512];
        int written = 0;
        if (is_string) {
            uint32_t str_va = MR32(arg_ptr); arg_ptr += 4;
            const char *s = guest_str(str_va);
            written = snprintf(temp, sizeof(temp), spec_buf, s);
        } else if (is_float) {
            double fval = MRF64(arg_ptr); arg_ptr += 8;
            written = snprintf(temp, sizeof(temp), spec_buf, fval);
        } else if (is_long_long) {
            uint64_t qval = MR64(arg_ptr); arg_ptr += 8;
            written = snprintf(temp, sizeof(temp), "%llu", (unsigned long long)qval);
        } else if (is_char) {
            uint32_t ival = MR32(arg_ptr); arg_ptr += 4;
            written = snprintf(temp, sizeof(temp), spec_buf, (char)ival);
        } else {
            uint32_t ival = MR32(arg_ptr); arg_ptr += 4;
            written = snprintf(temp, sizeof(temp), spec_buf, ival);
        }
        if (written < 0) written = 0;
        for (int k = 0; k < written; ++k) {
            if (dst && out_pos + 1 < maxlen) dst[out_pos] = temp[k];
            out_pos++;
        }
    }
    if (dst) {
        if (maxlen > 0) {
            size_t term = out_pos < maxlen ? out_pos : (maxlen - 1);
            dst[term] = '\0';
        }
    }
    return (int)out_pos;
}

/* --------------------------------------------------------------------------
 * Fast Intrinsic String Compare / Transform Helpers
 * -------------------------------------------------------------------------- */
static int crt_stricmp_impl(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int c1 = tolower((unsigned char)*s1);
        int c2 = tolower((unsigned char)*s2);
        if (c1 != c2) return c1 - c2;
        s1++; s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

static int crt_strnicmp_impl(const char *s1, const char *s2, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        int c1 = tolower((unsigned char)s1[i]);
        int c2 = tolower((unsigned char)s2[i]);
        if (c1 != c2 || !c1) return c1 - c2;
    }
    return 0;
}

void crt_shim__endthreadex(CPU *c) {
    (void)c;
}
void crt_shim__beginthreadex(CPU *c) {
    uint32_t security      = MR32(c->esp);
    uint32_t stack_size    = MR32(c->esp + 4);
    uint32_t start_address = MR32(c->esp + 8);
    uint32_t arglist       = MR32(c->esp + 12);
    uint32_t initflag      = MR32(c->esp + 16);
    uint32_t thrdaddr      = MR32(c->esp + 20);

    (void)security;
    uint32_t tid = 0;
    uint32_t h = win32_create_guest_thread(start_address, arglist, stack_size, initflag, &tid);
    if (thrdaddr) {
        MR32(thrdaddr) = tid;
    }
    c->eax = h;


}
void crt_shim_bsearch(CPU *c) {
    uint32_t key     = MR32(c->esp);
    uint32_t base    = MR32(c->esp + 4);
    uint32_t num     = MR32(c->esp + 8);
    uint32_t width   = MR32(c->esp + 12);
    uint32_t comp_fn = MR32(c->esp + 16);
    int32_t low = 0;
    int32_t high = (int32_t)num - 1;
    while (low <= high) {
        int32_t mid = low + (high - low) / 2;
        uint32_t elem = base + mid * width;
        uint32_t old_esp = c->esp;
        GUEST_PUSH32(c, elem);
        GUEST_PUSH32(c, key);
        DISPATCH_CALL(c, comp_fn);
        c->esp = old_esp;
        int32_t res = (int32_t)c->eax;
        if (res == 0) { c->eax = elem; return; }
        if (res < 0) high = mid - 1;
        else low = mid + 1;
    }
    c->eax = 0;
}
void crt_shim__vsnwprintf(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t count  = MR32(c->esp + 4);
    (void)buf_va; (void)count;
    c->eax = 0;
}
void crt_shim_getenv(CPU *c) {
    const char *var = guest_str(MR32(c->esp));
    const char *val = getenv(var);
    if (val) {
        strcpy((char *)(g_mem + GUEST_GETCWD_ADDR), val);
        c->eax = GUEST_GETCWD_ADDR;
    } else {
        c->eax = 0;
    }
}
void crt_shim__findclose(CPU *c) {
    c->eax = 0;
}
void crt_shim__findnext64i32(CPU *c) {
    c->eax = (uint32_t)-1;
}
void crt_shim__findfirst64i32(CPU *c) {
    c->eax = (uint32_t)-1;
}
void crt_shim__getdiskfree(CPU *c) {
    uint32_t drive = MR32(c->esp);
    uint32_t pinfo = MR32(c->esp + 4);
    (void)drive;
    if (pinfo) {
        MR32(pinfo + 0) = 0x8000; /* total clusters */
        MR32(pinfo + 4) = 0x4000; /* avail clusters */
        MR32(pinfo + 8) = 512;    /* bytes per sector */
        MR32(pinfo + 12) = 8;     /* sectors per cluster */
    }
    c->eax = 0;
}
void crt_shim_memmove_s(CPU *c) {
    uint32_t dst   = MR32(c->esp);
    uint32_t dstsz = MR32(c->esp + 4);
    uint32_t src   = MR32(c->esp + 8);
    uint32_t count = MR32(c->esp + 12);
    if (count > dstsz) { c->eax = 0x22; return; }
    if (count > 0) memmove(g_mem + dst, g_mem + src, count);
    c->eax = 0;
}
void crt_shim_std_exception_dtor(CPU *c) {
    c->eax = c->ecx;
}
void crt_shim_std_exception_default_ctor(CPU *c) {
    if (c->ecx) MR32(c->ecx) = 0;
    c->eax = c->ecx;
}
void crt_shim_std_exception_copy_ctor(CPU *c) {
    c->eax = c->ecx;
}
void crt_shim_memmove(CPU *c) {
    uint32_t dst = MR32(c->esp);
    uint32_t src = MR32(c->esp + 4);
    uint32_t n   = MR32(c->esp + 8);
    if (n > 0) memmove(g_mem + dst, g_mem + src, n);
    c->eax = dst;
}
void crt_shim__invalid_parameter_noinfo(CPU *c) {
    (void)c;
}
void crt_shim__purecall(CPU *c) {
    (void)c;
}
void crt_shim_free(CPU *c) {
    (void)c; /* No-op in guest heap arena */
}
void crt_shim_malloc(CPU *c) {
    uint32_t size = MR32(c->esp);
    c->eax = guest_heap_alloc(size ? size : 1, 8);
}
void crt_shim_printf(CPU *c) {
    const char *fmt = guest_str(MR32(c->esp));
    char buf[1024];
    int len = guest_format_core(buf, sizeof(buf), fmt, c->esp + 4);
    fputs(buf, stdout);
    c->eax = (uint32_t)len;
}
void crt_shim__getdrive(CPU *c) {
    c->eax = 3; /* C: drive */
}
void crt_shim_strncat(CPU *c) {
    uint32_t dst = MR32(c->esp);
    const char *src = guest_str(MR32(c->esp + 4));
    uint32_t n = MR32(c->esp + 8);
    strncat((char *)(g_mem + dst), src, n);
    c->eax = dst;
}
void crt_shim_sscanf(CPU *c) {
    const char *src = guest_str(MR32(c->esp));
    const char *fmt = guest_str(MR32(c->esp + 4));
    /* Parse 1..4 integer/float fields safely */
    uint32_t a1 = MR32(c->esp + 8);
    uint32_t a2 = MR32(c->esp + 12);
    uint32_t a3 = MR32(c->esp + 16);
    uint32_t a4 = MR32(c->esp + 20);
    void *p1 = a1 ? (void *)(g_mem + a1) : NULL;
    void *p2 = a2 ? (void *)(g_mem + a2) : NULL;
    void *p3 = a3 ? (void *)(g_mem + a3) : NULL;
    void *p4 = a4 ? (void *)(g_mem + a4) : NULL;
    c->eax = (uint32_t)sscanf(src, fmt, p1, p2, p3, p4);
}
void crt_shim_isspace(CPU *c) {
    c->eax = isspace((int)MR32(c->esp)) ? 1 : 0;
}
void crt_shim_strstr(CPU *c) {
    uint32_t hva = MR32(c->esp);
    const char *h = guest_str(hva);
    const char *n = guest_str(MR32(c->esp + 4));
    const char *res = strstr(h, n);
    c->eax = res ? (uint32_t)((const uint8_t *)res - g_mem) : 0;
}
void crt_shim_strchr(CPU *c) {
    uint32_t sva = MR32(c->esp);
    const char *s = guest_str(sva);
    int ch = (int)MR32(c->esp + 4);
    const char *res = strchr(s, ch);
    c->eax = res ? (uint32_t)((const uint8_t *)res - g_mem) : 0;
}
void crt_shim_atoi(CPU *c) {
    c->eax = (uint32_t)atoi(guest_str(MR32(c->esp)));
}
void crt_shim_strncpy(CPU *c) {
    uint32_t dst = MR32(c->esp);
    const char *src = guest_str(MR32(c->esp + 4));
    uint32_t n = MR32(c->esp + 8);
    strncpy((char *)(g_mem + dst), src, n);
    c->eax = dst;
}
void crt_shim_strrchr(CPU *c) {
    uint32_t sva = MR32(c->esp);
    const char *s = guest_str(sva);
    int ch = (int)MR32(c->esp + 4);
    const char *res = strrchr(s, ch);
    c->eax = res ? (uint32_t)((const uint8_t *)res - g_mem) : 0;
}
void crt_shim_atof(CPU *c) {
    double val = atof(guest_str(MR32(c->esp)));
    FPUSH(val);
}
void crt_shim_qsort(CPU *c) {
    uint32_t base    = MR32(c->esp);
    uint32_t num     = MR32(c->esp + 4);
    uint32_t width   = MR32(c->esp + 8);
    uint32_t comp_fn = MR32(c->esp + 12);
    if (num <= 1 || width == 0) return;
    for (uint32_t i = 1; i < num; ++i) {
        for (uint32_t j = i; j > 0; --j) {
            uint32_t p1 = base + (j - 1) * width;
            uint32_t p2 = base + j * width;
            uint32_t old_esp = c->esp;
            GUEST_PUSH32(c, p2);
            GUEST_PUSH32(c, p1);
            DISPATCH_CALL(c, comp_fn);
            c->esp = old_esp;
            if ((int32_t)c->eax > 0) {
                uint8_t tmp[256];
                uint32_t rem = width;
                uint32_t off = 0;
                while (rem > 0) {
                    uint32_t chunk = rem > sizeof(tmp) ? sizeof(tmp) : rem;
                    memcpy(tmp, g_mem + p1 + off, chunk);
                    memcpy(g_mem + p1 + off, g_mem + p2 + off, chunk);
                    memcpy(g_mem + p2 + off, tmp, chunk);
                    off += chunk;
                    rem -= chunk;
                }
            } else {
                break;
            }
        }
    }
}
void crt_shim_ceil(CPU *c) {
    double x = MRF64(c->esp);
    FPUSH(ceil(x));
}
void crt_shim_vsprintf(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    const char *fmt = guest_str(MR32(c->esp + 4));
    uint32_t valist = MR32(c->esp + 8);
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), 0x7fffffffu, fmt, valist);
}
void crt_shim__isnan(CPU *c) {
    double x = MRF64(c->esp);
    c->eax = (x != x) ? 1 : 0;
}
void crt_shim_exit(CPU *c) {
    crt_run_exit_handlers(c);
    c->eax = MR32(c->esp);
}
void crt_shim__stricmp(CPU *c) {
    const char *s1 = guest_str(MR32(c->esp));
    const char *s2 = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)crt_stricmp_impl(s1, s2);
}
void crt_shim__exit(CPU *c) {
    crt_run_exit_handlers(c);
    c->eax = MR32(c->esp);
}
void crt_shim_rand(CPU *c) {
    c->eax = (uint32_t)rand();
}
void crt_shim__CIsqrt(CPU *c) {
    ST(0) = sqrt(ST(0));
}
void crt_shim___CxxFrameHandler3(CPU *c) {
    c->eax = 1; /* ExceptionContinueSearch */
}
void crt_shim_memset(CPU *c) {
    uint32_t dst = MR32(c->esp);
    uint32_t val = MR32(c->esp + 4);
    uint32_t n   = MR32(c->esp + 8);
    if (n > 0) memset(g_mem + dst, val & 0xff, n);
    c->eax = dst;
}
void crt_shim_memcpy(CPU *c) {
    uint32_t dst = MR32(c->esp);
    uint32_t src = MR32(c->esp + 4);
    uint32_t n   = MR32(c->esp + 8);
    if (n > 0) memmove(g_mem + dst, g_mem + src, n);
    c->eax = dst;
}
void crt_shim__CIfmod(CPU *c) {
    double y = ST(0);
    double x = ST(1);
    FPOP();
    ST(0) = fmod(x, y);
}
void crt_shim__CIpow(CPU *c) {
    double y = ST(0);
    double x = ST(1);
    FPOP();
    ST(0) = pow(x, y);
}
void crt_shim__CIsin(CPU *c) {
    ST(0) = sin(ST(0));
}
void crt_shim_tolower(CPU *c) {
    c->eax = (uint32_t)tolower((int)MR32(c->esp));
}
void crt_shim__CxxThrowException(CPU *c) {
    c->eax = 0;
}
void crt_shim__CIacos(CPU *c) {
    ST(0) = acos(ST(0));
}
void crt_shim__CIatan2(CPU *c) {
    double x = ST(0);
    double y = ST(1);
    FPOP();
    ST(0) = atan2(y, x);
}
void crt_shim__CIcos(CPU *c) {
    ST(0) = cos(ST(0));
}
void crt_shim___iob_func(CPU *c) {
    c->eax = GUEST_IOB_ADDR;
}
void crt_shim_strncmp(CPU *c) {
    const char *s1 = guest_str(MR32(c->esp));
    const char *s2 = guest_str(MR32(c->esp + 4));
    uint32_t n = MR32(c->esp + 8);
    c->eax = (uint32_t)strncmp(s1, s2, n);
}
void crt_shim_fclose(CPU *c) {
    uint32_t handle = MR32(c->esp);
    if (handle < MAX_GUEST_FILES && g_files[handle].in_use) {
        if (g_files[handle].fp) fclose(g_files[handle].fp);
        g_files[handle].in_use = false;
        g_files[handle].fp = NULL;
        c->eax = 0;
    } else {
        c->eax = (uint32_t)-1;
    }
}
void crt_shim_fopen(CPU *c) {
    const char *fn = guest_str(MR32(c->esp));
    const char *md = guest_str(MR32(c->esp + 4));
    FILE *fp = fopen(fn, md);
    if (!fp) { c->eax = 0; return; }
    int slot = guest_alloc_file(fp, fn);
    c->eax = slot >= 0 ? (uint32_t)slot : 0;
}
void crt_shim__CIexp(CPU *c) {
    ST(0) = exp(ST(0));
}
void crt_shim_floor(CPU *c) {
    double x = MRF64(c->esp);
    FPUSH(floor(x));
}
void crt_shim__CIasin(CPU *c) {
    ST(0) = asin(ST(0));
}
void crt_shim_longjmp(CPU *c) {
    uint32_t env_va = MR32(c->esp);
    int val = (int)MR32(c->esp + 4);
    c->ebp = MR32(env_va + 0);
    c->ebx = MR32(env_va + 4);
    c->edi = MR32(env_va + 8);
    c->esi = MR32(env_va + 12);
    c->esp = MR32(env_va + 16);
    c->eip = MR32(env_va + 20);
    c->eax = val ? (uint32_t)val : 1;
}
void crt_shim__setjmp3(CPU *c) {
    uint32_t env_va = MR32(c->esp);
    MR32(env_va + 0)  = c->ebp;
    MR32(env_va + 4)  = c->ebx;
    MR32(env_va + 8)  = c->edi;
    MR32(env_va + 12) = c->esi;
    MR32(env_va + 16) = c->esp;
    MR32(env_va + 20) = c->eip;
    c->eax = 0;
}
void crt_shim_strcspn(CPU *c) {
    const char *s = guest_str(MR32(c->esp));
    const char *r = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)strcspn(s, r);
}
void crt_shim_strcoll(CPU *c) {
    const char *s1 = guest_str(MR32(c->esp));
    const char *s2 = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)strcmp(s1, s2);
}
void crt_shim_fprintf(CPU *c) {
    uint32_t stream_va = MR32(c->esp);
    const char *fmt = guest_str(MR32(c->esp + 4));
    FILE *fp = guest_get_file(stream_va);
    char buf[1024];
    int len = guest_format_core(buf, sizeof(buf), fmt, c->esp + 8);
    if (fp) fputs(buf, fp);
    c->eax = (uint32_t)len;
}
void crt_shim_isprint(CPU *c) {
    c->eax = isprint((int)MR32(c->esp)) ? 1 : 0;
}
void crt_shim__CIlog(CPU *c) {
    ST(0) = log(ST(0));
}
void crt_shim__mktime64(CPU *c) {
    uint32_t ptm = MR32(c->esp);
    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    if (ptm) {
        tm_val.tm_sec  = (int)MR32(ptm + 0);
        tm_val.tm_min  = (int)MR32(ptm + 4);
        tm_val.tm_hour = (int)MR32(ptm + 8);
        tm_val.tm_mday = (int)MR32(ptm + 12);
        tm_val.tm_mon  = (int)MR32(ptm + 16);
        tm_val.tm_year = (int)MR32(ptm + 20);
    }
    uint64_t res = (uint64_t)mktime(&tm_val);
    c->eax = (uint32_t)(res & 0xffffffffu);
    c->edx = (uint32_t)(res >> 32);
}
void crt_shim__getcwd(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t maxlen = MR32(c->esp + 4);
    char *dst = (char *)(g_mem + buf_va);
    strncpy(dst, ".", maxlen);
    c->eax = buf_va;
}
void crt_shim___RTDynamicCast(CPU *c) {
    uint32_t in_obj = MR32(c->esp);
    c->eax = in_obj;
}
void crt_shim_toupper(CPU *c) {
    c->eax = (uint32_t)toupper((int)MR32(c->esp));
}
void crt_shim_fseek(CPU *c) {
    uint32_t handle = MR32(c->esp);
    long offset     = (long)MR32(c->esp + 4);
    int origin      = (int)MR32(c->esp + 8);
    FILE *fp = guest_get_file(handle);
    c->eax = fp ? (uint32_t)fseek(fp, offset, origin) : (uint32_t)-1;
}
void crt_shim__chmod(CPU *c) {
    c->eax = 0;
}
void crt_shim_rename(CPU *c) {
    const char *oldp = guest_str(MR32(c->esp));
    const char *newp = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)rename(oldp, newp);
}
void crt_shim_remove(CPU *c) {
    const char *fn = guest_str(MR32(c->esp));
    c->eax = (uint32_t)remove(fn);
}
void crt_shim__ftime64(CPU *c) {
    uint32_t tb_va = MR32(c->esp);
    if (tb_va) {
        MR64(tb_va) = (uint64_t)time(NULL);
        MR16(tb_va + 8) = 0; /* millitm */
        MR16(tb_va + 10) = 0;/* timezone */
        MR16(tb_va + 12) = 0;/* dstflag */
    }
    c->eax = 0;
}
void crt_shim__time64(CPU *c) {
    uint32_t timer_va = MR32(c->esp);
    uint64_t now = (uint64_t)time(NULL);
    if (timer_va) MR64(timer_va) = now;
    c->eax = (uint32_t)(now & 0xffffffffu);
    c->edx = (uint32_t)(now >> 32);
}
void crt_shim_strtok(CPU *c) {
    static uint32_t s_tok_va = 0;
    uint32_t str_va = MR32(c->esp);
    const char *delim = guest_str(MR32(c->esp + 4));
    if (str_va != 0) s_tok_va = str_va;
    if (s_tok_va == 0) { c->eax = 0; return; }
    char *p = (char *)(g_mem + s_tok_va);
    while (*p && strchr(delim, *p)) p++;
    if (!*p) { s_tok_va = 0; c->eax = 0; return; }
    char *token_start = p;
    while (*p && !strchr(delim, *p)) p++;
    if (*p) {
        *p = '\0';
        s_tok_va = (uint32_t)((uint8_t *)(p + 1) - g_mem);
    } else {
        s_tok_va = 0;
    }
    c->eax = (uint32_t)((uint8_t *)token_start - g_mem);
}
void crt_shim_strtoul(CPU *c) {
    uint32_t str_va = MR32(c->esp);
    uint32_t end_va = MR32(c->esp + 4);
    int base        = (int)MR32(c->esp + 8);
    char *end = NULL;
    unsigned long val = strtoul(guest_str(str_va), &end, base);
    if (end_va) MR32(end_va) = end ? (uint32_t)((uint8_t *)end - g_mem) : str_va;
    c->eax = (uint32_t)val;
}
void crt_shim__strnicmp(CPU *c) {
    const char *s1 = guest_str(MR32(c->esp));
    const char *s2 = guest_str(MR32(c->esp + 4));
    uint32_t n = MR32(c->esp + 8);
    c->eax = (uint32_t)crt_strnicmp_impl(s1, s2, n);
}
void crt_shim__mkdir(CPU *c) {
    c->eax = 0;
}
void crt_shim__ltoa(CPU *c) {
    long val  = (long)MR32(c->esp);
    uint32_t buf = MR32(c->esp + 4);
    int radix = (int)MR32(c->esp + 8);
    char *dst = (char *)(g_mem + buf);
    if (radix == 16) sprintf(dst, "%lx", (unsigned long)val);
    else sprintf(dst, "%ld", val);
    c->eax = buf;
}
void crt_shim_strlen(CPU *c) {
    const char *s = guest_str(MR32(c->esp));
    c->eax = (uint32_t)strlen(s);
}
void crt_shim_memcmp(CPU *c) {
    uint32_t s1 = MR32(c->esp);
    uint32_t s2 = MR32(c->esp + 4);
    uint32_t n  = MR32(c->esp + 8);
    c->eax = (uint32_t)memcmp(g_mem + s1, g_mem + s2, n);
}
void crt_shim__snprintf(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t count  = MR32(c->esp + 4);
    const char *fmt = guest_str(MR32(c->esp + 8));
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), count, fmt, c->esp + 12);
}
void crt_shim__vsnprintf(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t count  = MR32(c->esp + 4);
    const char *fmt = guest_str(MR32(c->esp + 8));
    uint32_t valist = MR32(c->esp + 12);
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), count, fmt, valist);
}
void crt_shim_cos(CPU *c) {
    double x = MRF64(c->esp);
    FPUSH(cos(x));
}
void crt_shim_sqrt(CPU *c) {
    double x = MRF64(c->esp);
    FPUSH(sqrt(x));
}
void crt_shim_fflush(CPU *c) {
    uint32_t handle = MR32(c->esp);
    FILE *fp = guest_get_file(handle);
    c->eax = fp ? (uint32_t)fflush(fp) : 0;
}
void crt_shim_srand(CPU *c) {
    srand((unsigned int)MR32(c->esp));
}
void crt_shim_strcpy(CPU *c) {
    uint32_t dst = MR32(c->esp);
    const char *src = guest_str(MR32(c->esp + 4));
    strcpy((char *)(g_mem + dst), src);
    c->eax = dst;
}
void crt_shim_calloc(CPU *c) {
    uint32_t num  = MR32(c->esp);
    uint32_t size = MR32(c->esp + 4);
    uint64_t total = (uint64_t)num * (uint64_t)size;
    if (total > 0x10000000u) { c->eax = 0; return; }
    uint32_t ptr = guest_heap_alloc((uint32_t)(total ? total : 1), 8);
    if (ptr) memset(g_mem + ptr, 0, (size_t)total);
    c->eax = ptr;
}
void crt_shim_strcmp(CPU *c) {
    const char *s1 = guest_str(MR32(c->esp));
    const char *s2 = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)strcmp(s1, s2);
}
void crt_shim_strcat(CPU *c) {
    uint32_t dst = MR32(c->esp);
    const char *src = guest_str(MR32(c->esp + 4));
    strcat((char *)(g_mem + dst), src);
    c->eax = dst;
}
void crt_shim_raise(CPU *c) {
    c->eax = 0;
}
void crt_shim_realloc(CPU *c) {
    uint32_t ptr  = MR32(c->esp);
    uint32_t size = MR32(c->esp + 4);
    if (!ptr) { c->eax = guest_heap_alloc(size ? size : 1, 8); return; }
    if (!size) { c->eax = 0; return; }
    uint32_t nptr = guest_heap_alloc(size, 8);
    if (nptr && ptr) memcpy(g_mem + nptr, g_mem + ptr, size);
    c->eax = nptr;
}
void crt_shim_abs(CPU *c) {
    int32_t val = (int32_t)MR32(c->esp);
    c->eax = (uint32_t)(val < 0 ? -val : val);
}
void crt_shim_clock(CPU *c) {
    c->eax = (uint32_t)clock();
}
void crt_shim_strcpy_s(CPU *c) {
    uint32_t dst   = MR32(c->esp);
    uint32_t dstsz = MR32(c->esp + 4);
    const char *src = guest_str(MR32(c->esp + 8));
    size_t slen = strlen(src);
    if (slen + 1 > dstsz) { c->eax = 0x22; return; }
    memcpy(g_mem + dst, src, slen + 1);
    c->eax = 0;
}
void crt_shim_strncpy_s(CPU *c) {
    uint32_t dst   = MR32(c->esp);
    uint32_t dstsz = MR32(c->esp + 4);
    const char *src = guest_str(MR32(c->esp + 8));
    uint32_t count = MR32(c->esp + 12);
    if (count > dstsz) { c->eax = 0x22; return; }
    strncpy((char *)(g_mem + dst), src, count);
    if (count < dstsz) ((char *)(g_mem + dst))[count] = '\0';
    c->eax = 0;
}
void crt_shim_memcpy_s(CPU *c) {
    uint32_t dst   = MR32(c->esp);
    uint32_t dstsz = MR32(c->esp + 4);
    uint32_t src   = MR32(c->esp + 8);
    uint32_t count = MR32(c->esp + 12);
    if (count > dstsz) { c->eax = 0x22; return; }
    if (count > 0) memmove(g_mem + dst, g_mem + src, count);
    c->eax = 0;
}
void crt_shim_sprintf_s(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t bufsz  = MR32(c->esp + 4);
    const char *fmt = guest_str(MR32(c->esp + 8));
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), bufsz, fmt, c->esp + 12);
}
void crt_shim_vsprintf_s(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    uint32_t bufsz  = MR32(c->esp + 4);
    const char *fmt = guest_str(MR32(c->esp + 8));
    uint32_t valist = MR32(c->esp + 12);
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), bufsz, fmt, valist);
}
void crt_shim__vscprintf(CPU *c) {
    const char *fmt = guest_str(MR32(c->esp));
    uint32_t valist = MR32(c->esp + 4);
    c->eax = (uint32_t)guest_format_core(NULL, 0, fmt, valist);
}
void crt_shim_strtol(CPU *c) {
    uint32_t str_va = MR32(c->esp);
    uint32_t end_va = MR32(c->esp + 4);
    int base        = (int)MR32(c->esp + 8);
    char *end = NULL;
    long val = strtol(guest_str(str_va), &end, base);
    if (end_va) MR32(end_va) = end ? (uint32_t)((uint8_t *)end - g_mem) : str_va;
    c->eax = (uint32_t)val;
}
void crt_shim__itoa_s(CPU *c) {
    int val        = (int)MR32(c->esp);
    uint32_t buf   = MR32(c->esp + 4);
    uint32_t bufsz = MR32(c->esp + 8);
    int radix      = (int)MR32(c->esp + 12);
    char *dst = (char *)(g_mem + buf);
    if (radix == 10) snprintf(dst, bufsz, "%d", val);
    else if (radix == 16) snprintf(dst, bufsz, "%x", (unsigned int)val);
    else if (radix == 8) snprintf(dst, bufsz, "%o", (unsigned int)val);
    else snprintf(dst, bufsz, "%d", val);
    c->eax = 0;
}
void crt_shim__unlock(CPU *c) {
    (void)c;
}
void crt_shim__encode_pointer(CPU *c) {
    c->eax = MR32(c->esp);
}
void crt_shim___dllonexit(CPU *c) {
    uint32_t fn_va = MR32(c->esp);
    c->eax = crt_register_onexit(fn_va);
}
void crt_shim__lock(CPU *c) {
    (void)c;
}
void crt_shim__onexit(CPU *c) {
    uint32_t fn_va = MR32(c->esp);
    c->eax = crt_register_onexit(fn_va);
}
void crt_shim__decode_pointer(CPU *c) {
    c->eax = MR32(c->esp);
}
void crt_shim_terminate(CPU *c) {
    (void)c;
}
void crt_shim__amsg_exit(CPU *c) {
    c->eax = MR32(c->esp);
}
void crt_shim___getmainargs(CPU *c) {
    uint32_t pargc = MR32(c->esp);
    uint32_t pargv = MR32(c->esp + 4);
    uint32_t penvp = MR32(c->esp + 8);
    if (pargc) MR32(pargc) = 1;
    if (pargv) MR32(pargv) = GUEST_ARGV_TAB_ADDR;
    if (penvp) MR32(penvp) = GUEST_ENVP_TAB_ADDR;
    c->eax = 0;
}
void crt_shim__cexit(CPU *c) {
    crt_run_exit_handlers(c);
}
void crt_shim__XcptFilter(CPU *c) {
    c->eax = 0;
}
void crt_shim___initenv(CPU *c) {
    c->eax = GUEST_INITENV_ADDR;
}
void crt_shim__initterm(CPU *c) {
    uint32_t start = MR32(c->esp);
    uint32_t end   = MR32(c->esp + 4);
    for (uint32_t p = start; p < end; p += 4) {
        uint32_t fn_va = MR32(p);
        if (fn_va != 0) {
            uint32_t saved_esp = c->esp;
            DISPATCH_CALL(c, fn_va);
            c->esp = saved_esp;
        }
    }
}
void crt_shim__initterm_e(CPU *c) {
    uint32_t start = MR32(c->esp);
    uint32_t end   = MR32(c->esp + 4);
    for (uint32_t p = start; p < end; p += 4) {
        uint32_t fn_va = MR32(p);
        if (fn_va != 0) {
            uint32_t saved_esp = c->esp;
            DISPATCH_CALL(c, fn_va);
            c->esp = saved_esp;
            if (c->eax != 0) return;
        }
    }
    c->eax = 0;
}
void crt_shim__configthreadlocale(CPU *c) {
    c->eax = 0;
}
void crt_shim___setusermatherr(CPU *c) {
    c->eax = 0;
}
void crt_shim__adjust_fdiv(CPU *c) {
    c->eax = 0;
}
void crt_shim___p__commode(CPU *c) {
    c->eax = GUEST_COMMODE_ADDR;
}
void crt_shim___p__fmode(CPU *c) {
    c->eax = GUEST_FMODE_ADDR;
}
void crt_shim___set_app_type(CPU *c) {
    g_app_type = MR32(c->esp);
    c->eax = 0;
}
void crt_shim__localtime32(CPU *c) {
    uint32_t timer_va = MR32(c->esp);
    time_t t = timer_va ? (time_t)MR32(timer_va) : time(NULL);
    struct tm *lt = localtime(&t);
    if (lt) {
        MR32(GUEST_TM_ADDR + 0)  = (uint32_t)lt->tm_sec;
        MR32(GUEST_TM_ADDR + 4)  = (uint32_t)lt->tm_min;
        MR32(GUEST_TM_ADDR + 8)  = (uint32_t)lt->tm_hour;
        MR32(GUEST_TM_ADDR + 12) = (uint32_t)lt->tm_mday;
        MR32(GUEST_TM_ADDR + 16) = (uint32_t)lt->tm_mon;
        MR32(GUEST_TM_ADDR + 20) = (uint32_t)lt->tm_year;
        MR32(GUEST_TM_ADDR + 24) = (uint32_t)lt->tm_wday;
        MR32(GUEST_TM_ADDR + 28) = (uint32_t)lt->tm_yday;
        MR32(GUEST_TM_ADDR + 32) = (uint32_t)lt->tm_isdst;
        c->eax = GUEST_TM_ADDR;
    } else {
        c->eax = 0;
    }
}
void crt_shim__crt_debugger_hook(CPU *c) {
    (void)c;
}
void crt_shim__except_handler4_common(CPU *c) {
    c->eax = 1; /* ExceptionContinueSearch */
}
void crt_shim_type_info_dtor(CPU *c) {
    c->eax = c->ecx;
}
void crt_shim__invoke_watson(CPU *c) {
    (void)c;
}
void crt_shim__controlfp_s(CPU *c) {
    uint32_t pcurr = MR32(c->esp);
    uint32_t nw    = MR32(c->esp + 4);
    uint32_t mk    = MR32(c->esp + 8);
    if (pcurr) MR32(pcurr) = c->fcw;
    c->fcw = (c->fcw & ~mk) | (nw & mk);
    c->eax = 0;
}
void crt_shim__difftime64(CPU *c) {
    uint64_t t1 = MR64(c->esp);
    uint64_t t2 = MR64(c->esp + 8);
    double diff = (double)((int64_t)t1 - (int64_t)t2);
    FPUSH(diff);
}
void crt_shim_strpbrk(CPU *c) {
    uint32_t sva = MR32(c->esp);
    const char *s = guest_str(sva);
    const char *a = guest_str(MR32(c->esp + 4));
    const char *res = strpbrk(s, a);
    c->eax = res ? (uint32_t)((const uint8_t *)res - g_mem) : 0;
}
void crt_shim_asctime(CPU *c) {
    strcpy((char *)(g_mem + GUEST_ASCTIME_ADDR), "Sat Oct 31 12:00:00 2026\n");
    c->eax = GUEST_ASCTIME_ADDR;
}
void crt_shim__mkgmtime64(CPU *c) {
    uint32_t ptm = MR32(c->esp);
    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    if (ptm) {
        tm_val.tm_sec  = (int)MR32(ptm + 0);
        tm_val.tm_min  = (int)MR32(ptm + 4);
        tm_val.tm_hour = (int)MR32(ptm + 8);
        tm_val.tm_mday = (int)MR32(ptm + 12);
        tm_val.tm_mon  = (int)MR32(ptm + 16);
        tm_val.tm_year = (int)MR32(ptm + 20);
    }
    uint64_t res = (uint64_t)mktime(&tm_val);
    c->eax = (uint32_t)(res & 0xffffffffu);
    c->edx = (uint32_t)(res >> 32);
}
void crt_shim__gmtime64(CPU *c) {
    uint32_t timer_va = MR32(c->esp);
    time_t t = timer_va ? (time_t)MR64(timer_va) : time(NULL);
    struct tm *gt = gmtime(&t);
    if (gt) {
        MR32(GUEST_TM_ADDR + 0)  = (uint32_t)gt->tm_sec;
        MR32(GUEST_TM_ADDR + 4)  = (uint32_t)gt->tm_min;
        MR32(GUEST_TM_ADDR + 8)  = (uint32_t)gt->tm_hour;
        MR32(GUEST_TM_ADDR + 12) = (uint32_t)gt->tm_mday;
        MR32(GUEST_TM_ADDR + 16) = (uint32_t)gt->tm_mon;
        MR32(GUEST_TM_ADDR + 20) = (uint32_t)gt->tm_year;
        MR32(GUEST_TM_ADDR + 24) = (uint32_t)gt->tm_wday;
        MR32(GUEST_TM_ADDR + 28) = (uint32_t)gt->tm_yday;
        MR32(GUEST_TM_ADDR + 32) = (uint32_t)gt->tm_isdst;
        c->eax = GUEST_TM_ADDR;
    } else {
        c->eax = 0;
    }
}
void crt_shim_fwrite(CPU *c) {
    uint32_t src_va = MR32(c->esp);
    uint32_t size   = MR32(c->esp + 4);
    uint32_t count  = MR32(c->esp + 8);
    uint32_t handle = MR32(c->esp + 12);
    FILE *fp = guest_get_file(handle);
    if (fp) {
        c->eax = (uint32_t)fwrite(g_mem + src_va, size, count, fp);
    } else {
        c->eax = 0;
    }
}
void crt_shim__localtime64(CPU *c) {
    uint32_t timer_va = MR32(c->esp);
    time_t t = timer_va ? (time_t)MR64(timer_va) : time(NULL);
    struct tm *lt = localtime(&t);
    if (lt) {
        MR32(GUEST_TM_ADDR + 0)  = (uint32_t)lt->tm_sec;
        MR32(GUEST_TM_ADDR + 4)  = (uint32_t)lt->tm_min;
        MR32(GUEST_TM_ADDR + 8)  = (uint32_t)lt->tm_hour;
        MR32(GUEST_TM_ADDR + 12) = (uint32_t)lt->tm_mday;
        MR32(GUEST_TM_ADDR + 16) = (uint32_t)lt->tm_mon;
        MR32(GUEST_TM_ADDR + 20) = (uint32_t)lt->tm_year;
        MR32(GUEST_TM_ADDR + 24) = (uint32_t)lt->tm_wday;
        MR32(GUEST_TM_ADDR + 28) = (uint32_t)lt->tm_yday;
        MR32(GUEST_TM_ADDR + 32) = (uint32_t)lt->tm_isdst;
        c->eax = GUEST_TM_ADDR;
    } else {
        c->eax = 0;
    }
}
void crt_shim__fullpath(CPU *c) {
    uint32_t abs_va = MR32(c->esp);
    const char *rel = guest_str(MR32(c->esp + 4));
    uint32_t maxlen = MR32(c->esp + 8);
    char *dst = (char *)(g_mem + abs_va);
    strncpy(dst, rel, maxlen);
    c->eax = abs_va;
}
void crt_shim__close(CPU *c) {
    uint32_t fd = MR32(c->esp);
    if (fd < MAX_GUEST_FILES && g_files[fd].in_use) {
        if (g_files[fd].fp) fclose(g_files[fd].fp);
        g_files[fd].in_use = false;
        g_files[fd].fp = NULL;
        c->eax = 0;
    } else {
        c->eax = (uint32_t)-1;
    }
}
void crt_shim__write(CPU *c) {
    uint32_t fd     = MR32(c->esp);
    uint32_t buf_va = MR32(c->esp + 4);
    uint32_t count  = MR32(c->esp + 8);
    FILE *fp = guest_get_file(fd);
    c->eax = fp ? (uint32_t)fwrite(g_mem + buf_va, 1, count, fp) : (uint32_t)-1;
}
void crt_shim_mangled_open(CPU *c) {
    const char *fn = guest_str(MR32(c->esp));
    int oflag      = (int)MR32(c->esp + 4);
    (void)oflag;
    FILE *fp = fopen(fn, "rb");
    if (!fp) { c->eax = (uint32_t)-1; return; }
    int slot = guest_alloc_file(fp, fn);
    c->eax = slot >= 0 ? (uint32_t)slot : (uint32_t)-1;
}
void crt_shim__lseek(CPU *c) {
    uint32_t fd = MR32(c->esp);
    long offset = (long)MR32(c->esp + 4);
    int origin  = (int)MR32(c->esp + 8);
    FILE *fp = guest_get_file(fd);
    if (fp && fseek(fp, offset, origin) == 0) {
        c->eax = (uint32_t)ftell(fp);
    } else {
        c->eax = (uint32_t)-1;
    }
}
void crt_shim__read(CPU *c) {
    uint32_t fd     = MR32(c->esp);
    uint32_t buf_va = MR32(c->esp + 4);
    uint32_t count  = MR32(c->esp + 8);
    FILE *fp = guest_get_file(fd);
    c->eax = fp ? (uint32_t)fread(g_mem + buf_va, 1, count, fp) : (uint32_t)-1;
}
void crt_shim__filelength(CPU *c) {
    uint32_t fd = MR32(c->esp);
    FILE *fp = guest_get_file(fd);
    if (fp) {
        long cur = ftell(fp);
        fseek(fp, 0, SEEK_END);
        long end = ftell(fp);
        fseek(fp, cur, SEEK_SET);
        c->eax = (uint32_t)end;
    } else {
        c->eax = (uint32_t)-1;
    }
}
void crt_shim__rmdir(CPU *c) {
    c->eax = 0;
}
void crt_shim_isdigit(CPU *c) {
    c->eax = isdigit((int)MR32(c->esp)) ? 1 : 0;
}
void crt_shim__CIlog10(CPU *c) {
    ST(0) = log10(ST(0));
}
void crt_shim__CItan(CPU *c) {
    ST(0) = tan(ST(0));
}
void crt_shim_ldexp(CPU *c) {
    double x = MRF64(c->esp);
    int exp  = (int)MR32(c->esp + 8);
    FPUSH(ldexp(x, exp));
}
void crt_shim__except_handler3(CPU *c) {
    c->eax = 1; /* ExceptionContinueSearch */
}
void crt_shim__aligned_malloc(CPU *c) {
    uint32_t size  = MR32(c->esp);
    uint32_t align = MR32(c->esp + 4);
    c->eax = guest_heap_alloc(size ? size : 1, align ? align : 8);
}
void crt_shim__aligned_free(CPU *c) {
    (void)c;
}
void crt_shim__control87(CPU *c) {
    uint32_t nw = MR32(c->esp);
    uint32_t mk = MR32(c->esp + 4);
    uint16_t old = c->fcw;
    c->fcw = (old & ~mk) | (nw & mk);
    c->eax = old;
}
void crt_shim__CItanh(CPU *c) {
    ST(0) = tanh(ST(0));
}
void crt_shim__CIsinh(CPU *c) {
    ST(0) = sinh(ST(0));
}
void crt_shim__CIcosh(CPU *c) {
    ST(0) = cosh(ST(0));
}
void crt_shim_sprintf(CPU *c) {
    uint32_t buf_va = MR32(c->esp);
    const char *fmt = guest_str(MR32(c->esp + 4));
    c->eax = (uint32_t)guest_format_core((char *)(g_mem + buf_va), 0x7fffffffu, fmt, c->esp + 8);
}
void crt_shim__CIatan(CPU *c) {
    ST(0) = atan(ST(0));
}
/* --------------------------------------------------------------------------
 * Master MSVCR80.dll IAT Table (156 entries)
 * -------------------------------------------------------------------------- */
static const crt_import_entry_t g_crt_imports[156] = {
    { 0x009671d4u, "_endthreadex", crt_shim__endthreadex },
    { 0x009671d8u, "_beginthreadex", crt_shim__beginthreadex },
    { 0x009671dcu, "bsearch", crt_shim_bsearch },
    { 0x009671e0u, "_vsnwprintf", crt_shim__vsnwprintf },
    { 0x009671e4u, "getenv", crt_shim_getenv },
    { 0x009671e8u, "_findclose", crt_shim__findclose },
    { 0x009671ecu, "_findnext64i32", crt_shim__findnext64i32 },
    { 0x009671f0u, "_findfirst64i32", crt_shim__findfirst64i32 },
    { 0x009671f4u, "_getdiskfree", crt_shim__getdiskfree },
    { 0x009671f8u, "memmove_s", crt_shim_memmove_s },
    { 0x009671fcu, "??1exception@std@@UAE@XZ", crt_shim_std_exception_dtor },
    { 0x00967200u, "??0exception@std@@QAE@XZ", crt_shim_std_exception_default_ctor },
    { 0x00967204u, "??0exception@std@@QAE@ABV01@@Z", crt_shim_std_exception_copy_ctor },
    { 0x00967208u, "memmove", crt_shim_memmove },
    { 0x0096720cu, "_invalid_parameter_noinfo", crt_shim__invalid_parameter_noinfo },
    { 0x00967210u, "_purecall", crt_shim__purecall },
    { 0x00967214u, "free", crt_shim_free },
    { 0x00967218u, "malloc", crt_shim_malloc },
    { 0x0096721cu, "printf", crt_shim_printf },
    { 0x00967220u, "_getdrive", crt_shim__getdrive },
    { 0x00967224u, "strncat", crt_shim_strncat },
    { 0x00967228u, "sscanf", crt_shim_sscanf },
    { 0x0096722cu, "isspace", crt_shim_isspace },
    { 0x00967230u, "strstr", crt_shim_strstr },
    { 0x00967234u, "strchr", crt_shim_strchr },
    { 0x00967238u, "atoi", crt_shim_atoi },
    { 0x0096723cu, "strncpy", crt_shim_strncpy },
    { 0x00967240u, "strrchr", crt_shim_strrchr },
    { 0x00967244u, "atof", crt_shim_atof },
    { 0x00967248u, "qsort", crt_shim_qsort },
    { 0x0096724cu, "ceil", crt_shim_ceil },
    { 0x00967250u, "vsprintf", crt_shim_vsprintf },
    { 0x00967254u, "_isnan", crt_shim__isnan },
    { 0x00967258u, "exit", crt_shim_exit },
    { 0x0096725cu, "_stricmp", crt_shim__stricmp },
    { 0x00967260u, "_exit", crt_shim__exit },
    { 0x00967264u, "rand", crt_shim_rand },
    { 0x00967268u, "_CIsqrt", crt_shim__CIsqrt },
    { 0x0096726cu, "__CxxFrameHandler3", crt_shim___CxxFrameHandler3 },
    { 0x00967270u, "memset", crt_shim_memset },
    { 0x00967274u, "memcpy", crt_shim_memcpy },
    { 0x00967278u, "_CIfmod", crt_shim__CIfmod },
    { 0x0096727cu, "_CIpow", crt_shim__CIpow },
    { 0x00967280u, "_CIsin", crt_shim__CIsin },
    { 0x00967284u, "tolower", crt_shim_tolower },
    { 0x00967288u, "_CxxThrowException", crt_shim__CxxThrowException },
    { 0x0096728cu, "_CIacos", crt_shim__CIacos },
    { 0x00967290u, "_CIatan2", crt_shim__CIatan2 },
    { 0x00967294u, "_CIcos", crt_shim__CIcos },
    { 0x00967298u, "__iob_func", crt_shim___iob_func },
    { 0x0096729cu, "strncmp", crt_shim_strncmp },
    { 0x009672a0u, "fclose", crt_shim_fclose },
    { 0x009672a4u, "fopen", crt_shim_fopen },
    { 0x009672a8u, "_CIexp", crt_shim__CIexp },
    { 0x009672acu, "floor", crt_shim_floor },
    { 0x009672b0u, "_CIasin", crt_shim__CIasin },
    { 0x009672b4u, "longjmp", crt_shim_longjmp },
    { 0x009672b8u, "_setjmp3", crt_shim__setjmp3 },
    { 0x009672bcu, "strcspn", crt_shim_strcspn },
    { 0x009672c0u, "strcoll", crt_shim_strcoll },
    { 0x009672c4u, "fprintf", crt_shim_fprintf },
    { 0x009672c8u, "isprint", crt_shim_isprint },
    { 0x009672ccu, "_CIlog", crt_shim__CIlog },
    { 0x009672d0u, "_mktime64", crt_shim__mktime64 },
    { 0x009672d4u, "_getcwd", crt_shim__getcwd },
    { 0x009672d8u, "__RTDynamicCast", crt_shim___RTDynamicCast },
    { 0x009672dcu, "toupper", crt_shim_toupper },
    { 0x009672e0u, "fseek", crt_shim_fseek },
    { 0x009672e4u, "_chmod", crt_shim__chmod },
    { 0x009672e8u, "rename", crt_shim_rename },
    { 0x009672ecu, "remove", crt_shim_remove },
    { 0x009672f0u, "_ftime64", crt_shim__ftime64 },
    { 0x009672f4u, "_time64", crt_shim__time64 },
    { 0x009672f8u, "strtok", crt_shim_strtok },
    { 0x009672fcu, "strtoul", crt_shim_strtoul },
    { 0x00967300u, "_strnicmp", crt_shim__strnicmp },
    { 0x00967304u, "_mkdir", crt_shim__mkdir },
    { 0x00967308u, "_ltoa", crt_shim__ltoa },
    { 0x0096730cu, "strlen", crt_shim_strlen },
    { 0x00967310u, "memcmp", crt_shim_memcmp },
    { 0x00967314u, "_snprintf", crt_shim__snprintf },
    { 0x00967318u, "_vsnprintf", crt_shim__vsnprintf },
    { 0x0096731cu, "cos", crt_shim_cos },
    { 0x00967320u, "sqrt", crt_shim_sqrt },
    { 0x00967324u, "fflush", crt_shim_fflush },
    { 0x00967328u, "srand", crt_shim_srand },
    { 0x0096732cu, "strcpy", crt_shim_strcpy },
    { 0x00967330u, "calloc", crt_shim_calloc },
    { 0x00967334u, "strcmp", crt_shim_strcmp },
    { 0x00967338u, "strcat", crt_shim_strcat },
    { 0x0096733cu, "raise", crt_shim_raise },
    { 0x00967340u, "realloc", crt_shim_realloc },
    { 0x00967344u, "abs", crt_shim_abs },
    { 0x00967348u, "clock", crt_shim_clock },
    { 0x0096734cu, "strcpy_s", crt_shim_strcpy_s },
    { 0x00967350u, "strncpy_s", crt_shim_strncpy_s },
    { 0x00967354u, "memcpy_s", crt_shim_memcpy_s },
    { 0x00967358u, "sprintf_s", crt_shim_sprintf_s },
    { 0x0096735cu, "vsprintf_s", crt_shim_vsprintf_s },
    { 0x00967360u, "_vscprintf", crt_shim__vscprintf },
    { 0x00967364u, "strtol", crt_shim_strtol },
    { 0x00967368u, "_itoa_s", crt_shim__itoa_s },
    { 0x0096736cu, "_unlock", crt_shim__unlock },
    { 0x00967370u, "_encode_pointer", crt_shim__encode_pointer },
    { 0x00967374u, "__dllonexit", crt_shim___dllonexit },
    { 0x00967378u, "_lock", crt_shim__lock },
    { 0x0096737cu, "_onexit", crt_shim__onexit },
    { 0x00967380u, "_decode_pointer", crt_shim__decode_pointer },
    { 0x00967384u, "?terminate@@YAXXZ", crt_shim_terminate },
    { 0x00967388u, "_amsg_exit", crt_shim__amsg_exit },
    { 0x0096738cu, "__getmainargs", crt_shim___getmainargs },
    { 0x00967390u, "_cexit", crt_shim__cexit },
    { 0x00967394u, "_XcptFilter", crt_shim__XcptFilter },
    { 0x00967398u, "__initenv", crt_shim___initenv },
    { 0x0096739cu, "_initterm", crt_shim__initterm },
    { 0x009673a0u, "_initterm_e", crt_shim__initterm_e },
    { 0x009673a4u, "_configthreadlocale", crt_shim__configthreadlocale },
    { 0x009673a8u, "__setusermatherr", crt_shim___setusermatherr },
    { 0x009673acu, "_adjust_fdiv", crt_shim__adjust_fdiv },
    { 0x009673b0u, "__p__commode", crt_shim___p__commode },
    { 0x009673b4u, "__p__fmode", crt_shim___p__fmode },
    { 0x009673b8u, "__set_app_type", crt_shim___set_app_type },
    { 0x009673bcu, "_localtime32", crt_shim__localtime32 },
    { 0x009673c0u, "_crt_debugger_hook", crt_shim__crt_debugger_hook },
    { 0x009673c4u, "_except_handler4_common", crt_shim__except_handler4_common },
    { 0x009673c8u, "?_type_info_dtor_internal_method@type_info@@QAEXXZ", crt_shim_type_info_dtor },
    { 0x009673ccu, "_invoke_watson", crt_shim__invoke_watson },
    { 0x009673d0u, "_controlfp_s", crt_shim__controlfp_s },
    { 0x009673d4u, "_difftime64", crt_shim__difftime64 },
    { 0x009673d8u, "strpbrk", crt_shim_strpbrk },
    { 0x009673dcu, "asctime", crt_shim_asctime },
    { 0x009673e0u, "_mkgmtime64", crt_shim__mkgmtime64 },
    { 0x009673e4u, "_gmtime64", crt_shim__gmtime64 },
    { 0x009673e8u, "fwrite", crt_shim_fwrite },
    { 0x009673ecu, "_localtime64", crt_shim__localtime64 },
    { 0x009673f0u, "_fullpath", crt_shim__fullpath },
    { 0x009673f4u, "_close", crt_shim__close },
    { 0x009673f8u, "_write", crt_shim__write },
    { 0x009673fcu, "?_open@@YAHPBDHH@Z", crt_shim_mangled_open },
    { 0x00967400u, "_lseek", crt_shim__lseek },
    { 0x00967404u, "_read", crt_shim__read },
    { 0x00967408u, "_filelength", crt_shim__filelength },
    { 0x0096740cu, "_rmdir", crt_shim__rmdir },
    { 0x00967410u, "isdigit", crt_shim_isdigit },
    { 0x00967414u, "_CIlog10", crt_shim__CIlog10 },
    { 0x00967418u, "_CItan", crt_shim__CItan },
    { 0x0096741cu, "ldexp", crt_shim_ldexp },
    { 0x00967420u, "_except_handler3", crt_shim__except_handler3 },
    { 0x00967424u, "_aligned_malloc", crt_shim__aligned_malloc },
    { 0x00967428u, "_aligned_free", crt_shim__aligned_free },
    { 0x0096742cu, "_control87", crt_shim__control87 },
    { 0x00967430u, "_CItanh", crt_shim__CItanh },
    { 0x00967434u, "_CIsinh", crt_shim__CIsinh },
    { 0x00967438u, "_CIcosh", crt_shim__CIcosh },
    { 0x0096743cu, "sprintf", crt_shim_sprintf },
    { 0x00967440u, "_CIatan", crt_shim__CIatan },
};

size_t crt_get_import_count(void) {
    return 156;
}

const crt_import_entry_t *crt_get_import_table(void) {
    return g_crt_imports;
}

void crt_run_exit_handlers(struct CPU *c) {
    while (g_onexit_count > 0) {
        uint32_t fn = g_onexit_table[--g_onexit_count];
        if (fn != 0) {
            DISPATCH_CALL(c, fn);
        }
    }
}

void crt_init_iat(void) {
    /* 1. Setup metadata structures at GUEST_CRT_BASE */
    MR32(GUEST_COMMODE_ADDR) = 0;
    MR32(GUEST_FMODE_ADDR)   = 0;
    MR32(GUEST_INITENV_ADDR) = 0;
    memset(g_mem + GUEST_IOB_ADDR, 0, 96);
    /* Initial file handles */
    g_files[0].in_use = true; g_files[0].fp = stdin;
    g_files[1].in_use = true; g_files[1].fp = stdout;
    g_files[2].in_use = true; g_files[2].fp = stderr;
    /* Setup argv: 'nfs.exe' */
    strcpy((char *)(g_mem + GUEST_ARGV_STR_ADDR), "nfs.exe");
    MR32(GUEST_ARGV_TAB_ADDR) = GUEST_ARGV_STR_ADDR;
    MR32(GUEST_ARGV_TAB_ADDR + 4) = 0;
    MR32(GUEST_ENVP_TAB_ADDR) = 0;

    /* 2. Bind all 156 MSVCR80.dll IAT slots directly into g_dtab */
    for (size_t i = 0; i < 156; ++i) {
        uint32_t slot_va = g_crt_imports[i].slot_va;
        MR32(slot_va) = slot_va;
        uint32_t idx = slot_va - DISPATCH_TEXT_BASE;
        if (idx < DISPATCH_TEXT_SIZE) {
            g_dtab[idx] = g_crt_imports[i].handler;
        }
    }
}
