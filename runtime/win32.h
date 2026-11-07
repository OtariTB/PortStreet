/* Need for Speed ProStreet - Win32 Core Emulation Layer Header.
 *
 * Automatically generated from target binary PE import directory.
 * Total imported Win32 functions: 198.
 * Modules: KERNEL32, USER32, ADVAPI32, WINMM, SHFOLDER, ole32, RPCRT4, NETAPI32, MSVCP80, WS2_32.
 */
#ifndef PROSTREET_WIN32_H
#define PROSTREET_WIN32_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "cpu.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Win32 Import Record
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t    slot_va;
    const char *dll_name;
    const char *symbol_name;
    guest_fn_t  handler;
    uint32_t    arg_bytes;
} win32_import_entry_t;

/* --------------------------------------------------------------------------
 * Win32 Function Declarations (198 functions)
 * -------------------------------------------------------------------------- */
void win32_shim_MultiByteToWideChar(struct CPU *c); /* 0x00967040: KERNEL32.dll!MultiByteToWideChar */
void win32_shim_SuspendThread(struct CPU *c); /* 0x00967044: KERNEL32.dll!SuspendThread */
void win32_shim_ResumeThread(struct CPU *c); /* 0x00967048: KERNEL32.dll!ResumeThread */
void win32_shim_GetVersionExA(struct CPU *c); /* 0x0096704c: KERNEL32.dll!GetVersionExA */
void win32_shim_GetLongPathNameA(struct CPU *c); /* 0x00967050: KERNEL32.dll!GetLongPathNameA */
void win32_shim_GetDriveTypeA(struct CPU *c); /* 0x00967054: KERNEL32.dll!GetDriveTypeA */
void win32_shim_GetLogicalDrives(struct CPU *c); /* 0x00967058: KERNEL32.dll!GetLogicalDrives */
void win32_shim_FindClose(struct CPU *c); /* 0x0096705c: KERNEL32.dll!FindClose */
void win32_shim_FindNextFileA(struct CPU *c); /* 0x00967060: KERNEL32.dll!FindNextFileA */
void win32_shim_FindFirstFileA(struct CPU *c); /* 0x00967064: KERNEL32.dll!FindFirstFileA */
void win32_shim_FreeLibrary(struct CPU *c); /* 0x00967068: KERNEL32.dll!FreeLibrary */
void win32_shim_CreateDirectoryA(struct CPU *c); /* 0x0096706c: KERNEL32.dll!CreateDirectoryA */
void win32_shim_GetModuleHandleA(struct CPU *c); /* 0x00967070: KERNEL32.dll!GetModuleHandleA */
void win32_shim_GetSystemInfo(struct CPU *c); /* 0x00967074: KERNEL32.dll!GetSystemInfo */
void win32_shim_Sleep(struct CPU *c); /* 0x00967078: KERNEL32.dll!Sleep */
void win32_shim_Process32Next(struct CPU *c); /* 0x0096707c: KERNEL32.dll!Process32Next */
void win32_shim_Process32First(struct CPU *c); /* 0x00967080: KERNEL32.dll!Process32First */
void win32_shim_CreateToolhelp32Snapshot(struct CPU *c); /* 0x00967084: KERNEL32.dll!CreateToolhelp32Snapshot */
void win32_shim_SetErrorMode(struct CPU *c); /* 0x00967088: KERNEL32.dll!SetErrorMode */
void win32_shim_GetTickCount(struct CPU *c); /* 0x0096708c: KERNEL32.dll!GetTickCount */
void win32_shim_SetThreadPriority(struct CPU *c); /* 0x00967090: KERNEL32.dll!SetThreadPriority */
void win32_shim_GetSystemTimeAsFileTime(struct CPU *c); /* 0x00967094: KERNEL32.dll!GetSystemTimeAsFileTime */
void win32_shim_GetCurrentProcessId(struct CPU *c); /* 0x00967098: KERNEL32.dll!GetCurrentProcessId */
void win32_shim_GetCurrentThreadId(struct CPU *c); /* 0x0096709c: KERNEL32.dll!GetCurrentThreadId */
void win32_shim_SetUnhandledExceptionFilter(struct CPU *c); /* 0x009670a0: KERNEL32.dll!SetUnhandledExceptionFilter */
void win32_shim_UnhandledExceptionFilter(struct CPU *c); /* 0x009670a4: KERNEL32.dll!UnhandledExceptionFilter */
void win32_shim_GetCurrentProcess(struct CPU *c); /* 0x009670a8: KERNEL32.dll!GetCurrentProcess */
void win32_shim_TerminateProcess(struct CPU *c); /* 0x009670ac: KERNEL32.dll!TerminateProcess */
void win32_shim_CloseHandle(struct CPU *c); /* 0x009670b0: KERNEL32.dll!CloseHandle */
void win32_shim_InterlockedExchange(struct CPU *c); /* 0x009670b4: KERNEL32.dll!InterlockedExchange */
void win32_shim_ReleaseMutex(struct CPU *c); /* 0x009670b8: KERNEL32.dll!ReleaseMutex */
void win32_shim_CreateMutexW(struct CPU *c); /* 0x009670bc: KERNEL32.dll!CreateMutexW */
void win32_shim_GetSystemDirectoryA(struct CPU *c); /* 0x009670c0: KERNEL32.dll!GetSystemDirectoryA */
void win32_shim_LoadLibraryA(struct CPU *c); /* 0x009670c4: KERNEL32.dll!LoadLibraryA */
void win32_shim_LeaveCriticalSection(struct CPU *c); /* 0x009670c8: KERNEL32.dll!LeaveCriticalSection */
void win32_shim_TryEnterCriticalSection(struct CPU *c); /* 0x009670cc: KERNEL32.dll!TryEnterCriticalSection */
void win32_shim_EnterCriticalSection(struct CPU *c); /* 0x009670d0: KERNEL32.dll!EnterCriticalSection */
void win32_shim_DeleteCriticalSection(struct CPU *c); /* 0x009670d4: KERNEL32.dll!DeleteCriticalSection */
void win32_shim_InitializeCriticalSection(struct CPU *c); /* 0x009670d8: KERNEL32.dll!InitializeCriticalSection */
void win32_shim_WaitForSingleObject(struct CPU *c); /* 0x009670dc: KERNEL32.dll!WaitForSingleObject */
void win32_shim_CreateEventA(struct CPU *c); /* 0x009670e0: KERNEL32.dll!CreateEventA */
void win32_shim_GetDiskFreeSpaceExA(struct CPU *c); /* 0x009670e4: KERNEL32.dll!GetDiskFreeSpaceExA */
void win32_shim_SetWaitableTimer(struct CPU *c); /* 0x009670e8: KERNEL32.dll!SetWaitableTimer */
void win32_shim_SystemTimeToFileTime(struct CPU *c); /* 0x009670ec: KERNEL32.dll!SystemTimeToFileTime */
void win32_shim_GetSystemTime(struct CPU *c); /* 0x009670f0: KERNEL32.dll!GetSystemTime */
void win32_shim_CreateWaitableTimerA(struct CPU *c); /* 0x009670f4: KERNEL32.dll!CreateWaitableTimerA */
void win32_shim_DuplicateHandle(struct CPU *c); /* 0x009670f8: KERNEL32.dll!DuplicateHandle */
void win32_shim_GetCurrentThread(struct CPU *c); /* 0x009670fc: KERNEL32.dll!GetCurrentThread */
void win32_shim_TerminateThread(struct CPU *c); /* 0x00967100: KERNEL32.dll!TerminateThread */
void win32_shim_SleepEx(struct CPU *c); /* 0x00967104: KERNEL32.dll!SleepEx */
void win32_shim_GetThreadPriority(struct CPU *c); /* 0x00967108: KERNEL32.dll!GetThreadPriority */
void win32_shim_GetExitCodeThread(struct CPU *c); /* 0x0096710c: KERNEL32.dll!GetExitCodeThread */
void win32_shim_WriteFile(struct CPU *c); /* 0x00967110: KERNEL32.dll!WriteFile */
void win32_shim_SetFilePointer(struct CPU *c); /* 0x00967114: KERNEL32.dll!SetFilePointer */
void win32_shim_DeleteFileA(struct CPU *c); /* 0x00967118: KERNEL32.dll!DeleteFileA */
void win32_shim_MoveFileA(struct CPU *c); /* 0x0096711c: KERNEL32.dll!MoveFileA */
void win32_shim_ReadFile(struct CPU *c); /* 0x00967120: KERNEL32.dll!ReadFile */
void win32_shim_GetFileSize(struct CPU *c); /* 0x00967124: KERNEL32.dll!GetFileSize */
void win32_shim_GetProcAddress(struct CPU *c); /* 0x00967128: KERNEL32.dll!GetProcAddress */
void win32_shim_OutputDebugStringA(struct CPU *c); /* 0x0096712c: KERNEL32.dll!OutputDebugStringA */
void win32_shim_QueryPerformanceFrequency(struct CPU *c); /* 0x00967130: KERNEL32.dll!QueryPerformanceFrequency */
void win32_shim_SetEvent(struct CPU *c); /* 0x00967134: KERNEL32.dll!SetEvent */
void win32_shim_InterlockedCompareExchange(struct CPU *c); /* 0x00967138: KERNEL32.dll!InterlockedCompareExchange */
void win32_shim_PulseEvent(struct CPU *c); /* 0x0096713c: KERNEL32.dll!PulseEvent */
void win32_shim_GetPriorityClass(struct CPU *c); /* 0x00967140: KERNEL32.dll!GetPriorityClass */
void win32_shim_SetPriorityClass(struct CPU *c); /* 0x00967144: KERNEL32.dll!SetPriorityClass */
void win32_shim_RemoveDirectoryW(struct CPU *c); /* 0x00967148: KERNEL32.dll!RemoveDirectoryW */
void win32_shim_CreateDirectoryW(struct CPU *c); /* 0x0096714c: KERNEL32.dll!CreateDirectoryW */
void win32_shim_FindNextFileW(struct CPU *c); /* 0x00967150: KERNEL32.dll!FindNextFileW */
void win32_shim_FindFirstFileW(struct CPU *c); /* 0x00967154: KERNEL32.dll!FindFirstFileW */
void win32_shim_WideCharToMultiByte(struct CPU *c); /* 0x00967158: KERNEL32.dll!WideCharToMultiByte */
void win32_shim_MoveFileW(struct CPU *c); /* 0x0096715c: KERNEL32.dll!MoveFileW */
void win32_shim_DeleteFileW(struct CPU *c); /* 0x00967160: KERNEL32.dll!DeleteFileW */
void win32_shim_SetEndOfFile(struct CPU *c); /* 0x00967164: KERNEL32.dll!SetEndOfFile */
void win32_shim_CreateFileW(struct CPU *c); /* 0x00967168: KERNEL32.dll!CreateFileW */
void win32_shim_IsDebuggerPresent(struct CPU *c); /* 0x0096716c: KERNEL32.dll!IsDebuggerPresent */
void win32_shim_GetLastError(struct CPU *c); /* 0x00967170: KERNEL32.dll!GetLastError */
void win32_shim_IsBadReadPtr(struct CPU *c); /* 0x00967174: KERNEL32.dll!IsBadReadPtr */
void win32_shim_QueryPerformanceCounter(struct CPU *c); /* 0x00967178: KERNEL32.dll!QueryPerformanceCounter */
void win32_shim_CreateThread(struct CPU *c); /* 0x0096717c: KERNEL32.dll!CreateThread */
void win32_shim_GetFileSizeEx(struct CPU *c); /* 0x00967180: KERNEL32.dll!GetFileSizeEx */
void win32_shim_SetFilePointerEx(struct CPU *c); /* 0x00967184: KERNEL32.dll!SetFilePointerEx */
void win32_shim_RaiseException(struct CPU *c); /* 0x00967188: KERNEL32.dll!RaiseException */
void win32_shim_ReleaseSemaphore(struct CPU *c); /* 0x0096718c: KERNEL32.dll!ReleaseSemaphore */
void win32_shim_InterlockedDecrement(struct CPU *c); /* 0x00967190: KERNEL32.dll!InterlockedDecrement */
void win32_shim_CreateSemaphoreA(struct CPU *c); /* 0x00967194: KERNEL32.dll!CreateSemaphoreA */
void win32_shim_InterlockedExchangeAdd(struct CPU *c); /* 0x00967198: KERNEL32.dll!InterlockedExchangeAdd */
void win32_shim_SetThreadIdealProcessor(struct CPU *c); /* 0x0096719c: KERNEL32.dll!SetThreadIdealProcessor */
void win32_shim_TlsGetValue(struct CPU *c); /* 0x009671a0: KERNEL32.dll!TlsGetValue */
void win32_shim_TlsSetValue(struct CPU *c); /* 0x009671a4: KERNEL32.dll!TlsSetValue */
void win32_shim_TlsAlloc(struct CPU *c); /* 0x009671a8: KERNEL32.dll!TlsAlloc */
void win32_shim_CreateMutexA(struct CPU *c); /* 0x009671ac: KERNEL32.dll!CreateMutexA */
void win32_shim_VirtualProtect(struct CPU *c); /* 0x009671b0: KERNEL32.dll!VirtualProtect */
void win32_shim_GetCurrentDirectoryA(struct CPU *c); /* 0x009671b4: KERNEL32.dll!GetCurrentDirectoryA */
void win32_shim_ResetEvent(struct CPU *c); /* 0x009671b8: KERNEL32.dll!ResetEvent */
void win32_shim_CreateFileA(struct CPU *c); /* 0x009671bc: KERNEL32.dll!CreateFileA */
void win32_shim_DispatchMessageA(struct CPU *c); /* 0x00967464: USER32.dll!DispatchMessageA */
void win32_shim_TranslateMessage(struct CPU *c); /* 0x00967468: USER32.dll!TranslateMessage */
void win32_shim_GetMessageA(struct CPU *c); /* 0x0096746c: USER32.dll!GetMessageA */
void win32_shim_ShowCursor(struct CPU *c); /* 0x00967470: USER32.dll!ShowCursor */
void win32_shim_PeekMessageA(struct CPU *c); /* 0x00967474: USER32.dll!PeekMessageA */
void win32_shim_GetClientRect(struct CPU *c); /* 0x00967478: USER32.dll!GetClientRect */
void win32_shim_SetWindowLongA(struct CPU *c); /* 0x0096747c: USER32.dll!SetWindowLongA */
void win32_shim_DestroyWindow(struct CPU *c); /* 0x00967480: USER32.dll!DestroyWindow */
void win32_shim_SendInput(struct CPU *c); /* 0x00967484: USER32.dll!SendInput */
void win32_shim_SetCapture(struct CPU *c); /* 0x00967488: USER32.dll!SetCapture */
void win32_shim_SystemParametersInfoA(struct CPU *c); /* 0x0096748c: USER32.dll!SystemParametersInfoA */
void win32_shim_EnumDisplaySettingsA(struct CPU *c); /* 0x00967490: USER32.dll!EnumDisplaySettingsA */
void win32_shim_EndPaint(struct CPU *c); /* 0x00967494: USER32.dll!EndPaint */
void win32_shim_BeginPaint(struct CPU *c); /* 0x00967498: USER32.dll!BeginPaint */
void win32_shim_PostQuitMessage(struct CPU *c); /* 0x0096749c: USER32.dll!PostQuitMessage */
void win32_shim_MapVirtualKeyA(struct CPU *c); /* 0x009674a0: USER32.dll!MapVirtualKeyA */
void win32_shim_ToUnicode(struct CPU *c); /* 0x009674a4: USER32.dll!ToUnicode */
void win32_shim_GetForegroundWindow(struct CPU *c); /* 0x009674a8: USER32.dll!GetForegroundWindow */
void win32_shim_GetDesktopWindow(struct CPU *c); /* 0x009674ac: USER32.dll!GetDesktopWindow */
void win32_shim_GetKeyboardLayout(struct CPU *c); /* 0x009674b0: USER32.dll!GetKeyboardLayout */
void win32_shim_MapVirtualKeyExA(struct CPU *c); /* 0x009674b4: USER32.dll!MapVirtualKeyExA */
void win32_shim_GetKeyState(struct CPU *c); /* 0x009674b8: USER32.dll!GetKeyState */
void win32_shim_IsIconic(struct CPU *c); /* 0x009674bc: USER32.dll!IsIconic */
void win32_shim_MessageBoxA(struct CPU *c); /* 0x009674c0: USER32.dll!MessageBoxA */
void win32_shim_ReleaseCapture(struct CPU *c); /* 0x009674c4: USER32.dll!ReleaseCapture */
void win32_shim_wvsprintfA(struct CPU *c); /* 0x009674c8: USER32.dll!wvsprintfA */
void win32_shim_LoadIconA(struct CPU *c); /* 0x009674cc: USER32.dll!LoadIconA */
void win32_shim_LoadCursorA(struct CPU *c); /* 0x009674d0: USER32.dll!LoadCursorA */
void win32_shim_RegisterClassExA(struct CPU *c); /* 0x009674d4: USER32.dll!RegisterClassExA */
void win32_shim_AdjustWindowRect(struct CPU *c); /* 0x009674d8: USER32.dll!AdjustWindowRect */
void win32_shim_CreateWindowExA(struct CPU *c); /* 0x009674dc: USER32.dll!CreateWindowExA */
void win32_shim_UpdateWindow(struct CPU *c); /* 0x009674e0: USER32.dll!UpdateWindow */
void win32_shim_SetCursor(struct CPU *c); /* 0x009674e4: USER32.dll!SetCursor */
void win32_shim_SetFocus(struct CPU *c); /* 0x009674e8: USER32.dll!SetFocus */
void win32_shim_SetForegroundWindow(struct CPU *c); /* 0x009674ec: USER32.dll!SetForegroundWindow */
void win32_shim_GetWindowRect(struct CPU *c); /* 0x009674f0: USER32.dll!GetWindowRect */
void win32_shim_ShowWindow(struct CPU *c); /* 0x009674f4: USER32.dll!ShowWindow */
void win32_shim_GetWindowLongA(struct CPU *c); /* 0x009674f8: USER32.dll!GetWindowLongA */
void win32_shim_DefWindowProcA(struct CPU *c); /* 0x009674fc: USER32.dll!DefWindowProcA */
void win32_shim_PostMessageA(struct CPU *c); /* 0x00967500: USER32.dll!PostMessageA */
void win32_shim_CheckTokenMembership(struct CPU *c); /* 0x00967000: ADVAPI32.dll!CheckTokenMembership */
void win32_shim_FreeSid(struct CPU *c); /* 0x00967004: ADVAPI32.dll!FreeSid */
void win32_shim_RegCreateKeyA(struct CPU *c); /* 0x00967008: ADVAPI32.dll!RegCreateKeyA */
void win32_shim_RegOpenKeyExA(struct CPU *c); /* 0x0096700c: ADVAPI32.dll!RegOpenKeyExA */
void win32_shim_RegCloseKey(struct CPU *c); /* 0x00967010: ADVAPI32.dll!RegCloseKey */
void win32_shim_RegSetValueExA(struct CPU *c); /* 0x00967014: ADVAPI32.dll!RegSetValueExA */
void win32_shim_RegQueryValueExA(struct CPU *c); /* 0x00967018: ADVAPI32.dll!RegQueryValueExA */
void win32_shim_CryptReleaseContext(struct CPU *c); /* 0x0096701c: ADVAPI32.dll!CryptReleaseContext */
void win32_shim_CryptGenRandom(struct CPU *c); /* 0x00967020: ADVAPI32.dll!CryptGenRandom */
void win32_shim_CryptAcquireContextA(struct CPU *c); /* 0x00967024: ADVAPI32.dll!CryptAcquireContextA */
void win32_shim_AllocateAndInitializeSid(struct CPU *c); /* 0x00967028: ADVAPI32.dll!AllocateAndInitializeSid */
void win32_shim_SHGetFolderPathA(struct CPU *c); /* 0x0096745c: SHFOLDER.dll!SHGetFolderPathA */
void win32_shim_ord_8(struct CPU *c); /* 0x00967518: WS2_32.dll!ord_8 */
void win32_shim_ord_115(struct CPU *c); /* 0x0096751c: WS2_32.dll!ord_115 */
void win32_shim_ord_14(struct CPU *c); /* 0x00967520: WS2_32.dll!ord_14 */
void win32_shim_ord_111(struct CPU *c); /* 0x00967524: WS2_32.dll!ord_111 */
void win32_shim_ord_116(struct CPU *c); /* 0x00967528: WS2_32.dll!ord_116 */
void win32_shim_ord_9(struct CPU *c); /* 0x0096752c: WS2_32.dll!ord_9 */
void win32_shim_ord_15(struct CPU *c); /* 0x00967530: WS2_32.dll!ord_15 */
void win32_shim_ord_11(struct CPU *c); /* 0x00967534: WS2_32.dll!ord_11 */
void win32_shim_ord_52(struct CPU *c); /* 0x00967538: WS2_32.dll!ord_52 */
void win32_shim_ord_12(struct CPU *c); /* 0x0096753c: WS2_32.dll!ord_12 */
void win32_shim_WSACreateEvent(struct CPU *c); /* 0x00967540: WS2_32.dll!WSACreateEvent */
void win32_shim_WSACloseEvent(struct CPU *c); /* 0x00967544: WS2_32.dll!WSACloseEvent */
void win32_shim_WSASetEvent(struct CPU *c); /* 0x00967548: WS2_32.dll!WSASetEvent */
void win32_shim_WSARecv(struct CPU *c); /* 0x0096754c: WS2_32.dll!WSARecv */
void win32_shim_WSARecvFrom(struct CPU *c); /* 0x00967550: WS2_32.dll!WSARecvFrom */
void win32_shim_WSAResetEvent(struct CPU *c); /* 0x00967554: WS2_32.dll!WSAResetEvent */
void win32_shim_WSAWaitForMultipleEvents(struct CPU *c); /* 0x00967558: WS2_32.dll!WSAWaitForMultipleEvents */
void win32_shim_WSAGetOverlappedResult(struct CPU *c); /* 0x0096755c: WS2_32.dll!WSAGetOverlappedResult */
void win32_shim_ord_2(struct CPU *c); /* 0x00967560: WS2_32.dll!ord_2 */
void win32_shim_ord_1(struct CPU *c); /* 0x00967564: WS2_32.dll!ord_1 */
void win32_shim_ord_5(struct CPU *c); /* 0x00967568: WS2_32.dll!ord_5 */
void win32_shim_ord_6(struct CPU *c); /* 0x0096756c: WS2_32.dll!ord_6 */
void win32_shim_ord_57(struct CPU *c); /* 0x00967570: WS2_32.dll!ord_57 */
void win32_shim_WSAIoctl(struct CPU *c); /* 0x00967574: WS2_32.dll!WSAIoctl */
void win32_shim_ord_55(struct CPU *c); /* 0x00967578: WS2_32.dll!ord_55 */
void win32_shim_ord_51(struct CPU *c); /* 0x0096757c: WS2_32.dll!ord_51 */
void win32_shim_ord_56(struct CPU *c); /* 0x00967580: WS2_32.dll!ord_56 */
void win32_shim_ord_3(struct CPU *c); /* 0x00967584: WS2_32.dll!ord_3 */
void win32_shim_ord_18(struct CPU *c); /* 0x00967588: WS2_32.dll!ord_18 */
void win32_shim_ord_19(struct CPU *c); /* 0x0096758c: WS2_32.dll!ord_19 */
void win32_shim_ord_16(struct CPU *c); /* 0x00967590: WS2_32.dll!ord_16 */
void win32_shim_ord_4(struct CPU *c); /* 0x00967594: WS2_32.dll!ord_4 */
void win32_shim_ord_7(struct CPU *c); /* 0x00967598: WS2_32.dll!ord_7 */
void win32_shim_ord_21(struct CPU *c); /* 0x0096759c: WS2_32.dll!ord_21 */
void win32_shim_ord_10(struct CPU *c); /* 0x009675a0: WS2_32.dll!ord_10 */
void win32_shim_ord_23(struct CPU *c); /* 0x009675a4: WS2_32.dll!ord_23 */
void win32_shim_ord_20(struct CPU *c); /* 0x009675a8: WS2_32.dll!ord_20 */
void win32_shim_ord_22(struct CPU *c); /* 0x009675ac: WS2_32.dll!ord_22 */
void win32_shim_ord_112(struct CPU *c); /* 0x009675b0: WS2_32.dll!ord_112 */
void win32_shim_ord_17(struct CPU *c); /* 0x009675b4: WS2_32.dll!ord_17 */
void win32_shim_UuidToStringA(struct CPU *c); /* 0x00967450: RPCRT4.dll!UuidToStringA */
void win32_shim_RpcStringFreeA(struct CPU *c); /* 0x00967454: RPCRT4.dll!RpcStringFreeA */
void win32_shim_CoCreateGuid(struct CPU *c); /* 0x00967600: ole32.dll!CoCreateGuid */
void win32_shim_std_string_copy_ctor(struct CPU *c); /* 0x009671c4: MSVCP80.dll!??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@ABV01@@Z */
void win32_shim_std_string_dtor(struct CPU *c); /* 0x009671c8: MSVCP80.dll!??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@XZ */
void win32_shim_std_string_ctor_cstr(struct CPU *c); /* 0x009671cc: MSVCP80.dll!??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAE@PBD@Z */
void win32_shim_timeEndPeriod(struct CPU *c); /* 0x00967508: WINMM.dll!timeEndPeriod */
void win32_shim_timeGetTime(struct CPU *c); /* 0x0096750c: WINMM.dll!timeGetTime */
void win32_shim_timeBeginPeriod(struct CPU *c); /* 0x00967510: WINMM.dll!timeBeginPeriod */
void win32_shim_Netbios(struct CPU *c); /* 0x00967448: NETAPI32.dll!Netbios */

/* --------------------------------------------------------------------------
 * Win32 Subsystem Management API
 * -------------------------------------------------------------------------- */
void win32_init_iat(void);
size_t win32_get_import_count(void);
const win32_import_entry_t *win32_get_import_table(void);
void win32_post_key_event(uint32_t vk, bool down);
bool win32_get_key_state(uint32_t vk);
void win32_set_window_dims(uint32_t width, uint32_t height);
uint32_t win32_create_event(void);
void win32_signal_event(uint32_t h);
void win32_reset_event(uint32_t h);
uint32_t win32_get_event_state_addr(uint32_t h);
FILE *win32_open_game_file(const char *guest_path, bool read_only);

/* --------------------------------------------------------------------------
 * Guest Thread Management & Worker Loop API
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t          handle;
    uint32_t          thread_id;
    uint32_t          start_address;
    uint32_t          arglist;
    uint32_t          stack_size;
    uint32_t          initflag;
    uint32_t          cpu_va;
    uint32_t          teb_va;
    uint32_t          stack_top_va;
    uint32_t          suspended;
    uint32_t          active;
    uint32_t          exit_code;
    volatile uint32_t signal;
} guest_thread_desc_t;

typedef struct {
    volatile uint32_t state;        /* 0=UNINIT, 1=READY, 2=RUNNING, 3=TERMINATED */
    volatile uint32_t signal;       /* 0=WAIT, 1=RUN, 2=STOP */
    volatile uint32_t entry;        /* Guest function VA */
    volatile uint32_t cpu_va;       /* Guest CPU VA */
    volatile uint32_t completed;    /* Completed executions counter */
    volatile uint32_t exit_code;    /* Last exit code */
    uint32_t          reserved[2];  /* 32 bytes per worker slot */
} guest_worker_mailbox_t;

uint32_t win32_create_guest_thread(uint32_t start_addr, uint32_t arglist, uint32_t stack_sz, uint32_t initflag, uint32_t *out_tid);
uint32_t win32_resume_guest_thread(uint32_t hThread);
const guest_thread_desc_t *win32_get_guest_thread(uint32_t hThread);
uint32_t win32_get_guest_thread_count(void);
void guest_worker_slot_run(uint32_t slot_idx);
void guest_worker_thread_run(uint32_t cpu_va);
void guest_worker_thread_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* PROSTREET_WIN32_H */
