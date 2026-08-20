/* Chimera Win32 stub.
 *
 * A Windows-targeted .NET binary P/Invokes into kernel32.dll / ntdll.dll,
 * which do not exist on Linux, so the process dies at the first call
 * (typically GetStdHandle, before any user code). This stub exports the
 * handful of entry points such crackmes reach and returns benign values,
 * so the binary runs far enough to hit its key check.
 *
 * Every function returns 0 and writes nothing. `out` parameters therefore
 * keep the zero the CLR already gave them, which the anti-debug imports
 * (CheckRemoteDebuggerPresent, NtQueryInformationProcess) read as
 * "no debugger present" — so this doubles as the anti-debug bypass.
 *
 * The AMD64 SysV convention ignores surplus register args, so one nullary
 * body serves every signature; each real name is exported as an alias.
 */

static long chimera_stub(void) { return 0; }

#define STUB(name) long name(void) __attribute__((alias("chimera_stub")));

/* A missing export throws EntryPointNotFoundException at the first call and
 * kills the run, so cover the common console / anti-debug / loader surface a
 * Windows crackme reaches. The resolver installs this only for the target
 * assembly's own imports, so widening it never shadows a CLR-internal call. */

/* kernel32 — console */
STUB(GetStdHandle)
STUB(GetConsoleMode)
STUB(SetConsoleMode)
STUB(GetConsoleOutputCP)
STUB(SetConsoleTextAttribute)
STUB(WriteConsoleW)
STUB(WriteConsoleA)
STUB(ReadConsoleW)
STUB(GetConsoleScreenBufferInfo)
/* kernel32 — thread/process/anti-debug */
STUB(OpenThread)
STUB(GetCurrentThreadId)
STUB(GetCurrentProcessId)
STUB(GetCurrentProcess)
STUB(GetCurrentThread)
STUB(CloseHandle)
STUB(TerminateProcess)
STUB(CheckRemoteDebuggerPresent)
STUB(IsDebuggerPresent)
STUB(DebugActiveProcess)
STUB(OutputDebugStringA)
STUB(OutputDebugStringW)
/* kernel32 — timing (anti-debug often times a region) */
STUB(GetTickCount)
STUB(GetTickCount64)
STUB(QueryPerformanceCounter)
STUB(QueryPerformanceFrequency)
STUB(GetSystemTimeAsFileTime)
STUB(Sleep)
/* kernel32 — loader/memory */
STUB(LoadLibraryA)
STUB(LoadLibraryW)
STUB(GetModuleHandleA)
STUB(GetModuleHandleW)
STUB(GetProcAddress)
STUB(GetModuleFileNameW)
STUB(VirtualProtect)
STUB(VirtualQuery)
STUB(GetLastError)
STUB(SetLastError)
STUB(IsProcessorFeaturePresent)
/* ntdll */
STUB(NtQueryInformationProcess)
STUB(NtSetInformationThread)
STUB(NtQueryInformationThread)
STUB(NtQuerySystemInformation)
STUB(NtClose)
STUB(NtQueryObject)
STUB(NtGetContextThread)
