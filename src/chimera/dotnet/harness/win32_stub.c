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

/* kernel32 */
STUB(GetStdHandle)
STUB(GetConsoleMode)
STUB(SetConsoleMode)
STUB(OpenThread)
STUB(GetCurrentThreadId)
STUB(CloseHandle)
STUB(CheckRemoteDebuggerPresent)
STUB(IsDebuggerPresent)
STUB(GetCurrentProcess)
STUB(TerminateProcess)
STUB(GetTickCount)
STUB(OutputDebugStringA)
STUB(OutputDebugStringW)
/* ntdll */
STUB(NtQueryInformationProcess)
STUB(NtSetInformationThread)
STUB(NtQueryInformationThread)
STUB(NtClose)
