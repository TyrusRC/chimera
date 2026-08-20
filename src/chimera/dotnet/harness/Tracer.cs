// Chimera .NET tracer harness.
//
// Loads a target .NET assembly, installs Harmony postfix hooks on the
// methods named on the command line, drives the assembly's entry point
// with supplied stdin, and writes one JSON record per hook call to the
// trace file. Harmony detours the JIT-compiled native code rather than
// rewriting on-disk IL, so a runtime method-integrity (anti-tamper) check
// that hashes the IL image does not see the hooks.
//
// Usage:
//   chimera_dotnet_tracer <assembly> <trace-out> <stdin> <spec>...
//
// A <spec> is one of:
//   @neutralize-pinvoke   Skip every [DllImport] in the target and return
//                         default(T). Lets a Windows-only binary run on
//                         Linux (its kernel32/ntdll calls no-op) and, since
//                         those same imports are the anti-debug surface
//                         (CheckRemoteDebuggerPresent, NtQueryInformation-
//                         Process, ThreadHideFromDebugger), neutralizes it.
//   Type::Method          Hook a fully-qualified method in ANY loaded
//                         assembly — e.g. System.String::op_Equality — so a
//                         validator that bottoms out in a BCL comparison is
//                         observable even when its own methods are
//                         reflection-built delegates with random names.
//   Method                Hook every method of that (bare) name in the
//                         target assembly. The original behaviour.
//
// stdin may contain '\n'; each line answers one Console.ReadLine, which is
// what drives a menu-loop program to its key prompt.
//
// Each traced method's byte[]/string arguments and (byte[]/string/bool)
// return value are captured. This is deliberately generic: the caller
// picks what to watch.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using HarmonyLib;

static partial class Tracer
{
    static string _traceFile;
    static readonly object _lock = new object();
    static readonly HashSet<string> _wantedBare = new HashSet<string>();
    static readonly HashSet<string> _wantedQualified = new HashSet<string>();
    static bool _neutralizePinvoke;

    static void Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: tracer <assembly> <trace-out> <stdin> <spec>...");
            Environment.Exit(2);
        }
        var asmPath = args[0];
        _traceFile = args[1];
        var stdinLine = args[2];
        foreach (var m in args.Skip(3))
        {
            if (m == "@neutralize-pinvoke") _neutralizePinvoke = true;
            else if (m.Contains("::")) _wantedQualified.Add(m);
            else _wantedBare.Add(m);
        }

        File.WriteAllText(_traceFile, "");  // truncate

        var asm = Assembly.LoadFrom(asmPath);
        var harmony = new Harmony("chimera.dotnet.tracer");
        var postfix = new HarmonyMethod(typeof(Tracer).GetMethod(nameof(Postfix),
            BindingFlags.Static | BindingFlags.NonPublic));
        int hooked = 0;
        if (_neutralizePinvoke) hooked += InstallWin32Resolver(asm);
        hooked += HookBareNames(asm, harmony, postfix);
        hooked += HookQualified(harmony, postfix);
        Emit(new Dictionary<string, object> { ["event"] = "hooks_installed", ["count"] = hooked });

        var stdin = new StringReader(stdinLine + "\n");
        Console.SetIn(stdin);
        try
        {
            var ep = asm.EntryPoint;
            var pars = ep.GetParameters();
            var epArgs = pars.Length == 0 ? null : new object[] { new string[0] };
            ep.Invoke(null, epArgs);
        }
        catch (Exception e)
        {
            Emit(new Dictionary<string, object> {
                ["event"] = "entrypoint_threw",
                ["error"] = (e.InnerException ?? e).GetType().Name });
        }
        Emit(new Dictionary<string, object> { ["event"] = "done" });
    }

    // Windows DLLs a [DllImport] might name; each is redirected to the stub.
    // A P/Invoke method has no managed IL body, so Harmony cannot detour it
    // (preparing the detour itself throws DllNotFoundException). The runtime
    // resolver hook is the supported seam: it maps the whole library, so the
    // very first GetStdHandle call lands in the stub instead of dying.
    static readonly HashSet<string> _winLibs = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "kernel32", "kernel32.dll", "ntdll", "ntdll.dll",
        "user32", "user32.dll", "advapi32", "advapi32.dll",
    };
    static IntPtr _stubHandle = IntPtr.Zero;

    static int InstallWin32Resolver(Assembly asm)
    {
        var stub = Environment.GetEnvironmentVariable("CHIMERA_WIN32_STUB");
        if (string.IsNullOrEmpty(stub) || !File.Exists(stub))
        {
            Emit(new Dictionary<string, object> {
                ["event"] = "neutralize_failed", ["method"] = "*",
                ["error"] = "stub library missing" });
            return 0;
        }
        try { _stubHandle = NativeLibrary.Load(stub); }
        catch (Exception e)
        {
            Emit(new Dictionary<string, object> {
                ["event"] = "neutralize_failed", ["method"] = "*",
                ["error"] = e.GetType().Name });
            return 0;
        }
        NativeLibrary.SetDllImportResolver(asm, Win32Resolver);
        return 1;
    }

    static IntPtr Win32Resolver(string libraryName, Assembly assembly, DllImportSearchPath? paths)
    {
        var key = libraryName.ToLowerInvariant();
        if (_winLibs.Contains(key)) return _stubHandle;
        // A missing export on the stub throws; unknown libs fall through to
        // the default probing so genuinely-present native deps still load.
        return IntPtr.Zero;
    }

    static int HookBareNames(Assembly asm, Harmony harmony, HarmonyMethod postfix)
    {
        if (_wantedBare.Count == 0) return 0;
        int n = 0;
        foreach (var t in SafeGetTypes(asm))
            foreach (var m in t.GetMethods(BindingFlags.Static | BindingFlags.Instance
                                           | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (!_wantedBare.Contains(m.Name) || m.IsAbstract || m.ContainsGenericParameters)
                    continue;
                try { harmony.Patch(m, postfix: postfix); n++; }
                catch (Exception e) { Emit(new Dictionary<string, object> {
                    ["event"] = "hook_failed", ["method"] = m.Name,
                    ["error"] = e.GetType().Name }); }
            }
        return n;
    }

    // Hook a Type::Method named across every loaded assembly — used for BCL
    // comparison primitives the validator falls through to.
    static int HookQualified(Harmony harmony, HarmonyMethod postfix)
    {
        int n = 0;
        foreach (var spec in _wantedQualified)
        {
            var i = spec.IndexOf("::");
            var typeName = spec.Substring(0, i);
            var methodName = spec.Substring(i + 2);
            var type = ResolveType(typeName);
            if (type == null)
            {
                Emit(new Dictionary<string, object> {
                    ["event"] = "hook_failed", ["method"] = spec, ["error"] = "TypeNotFound" });
                continue;
            }
            foreach (var m in type.GetMethods(BindingFlags.Static | BindingFlags.Instance
                                              | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (m.Name != methodName || m.IsAbstract || m.ContainsGenericParameters) continue;
                try { harmony.Patch(m, postfix: postfix); n++; }
                catch (Exception e) { Emit(new Dictionary<string, object> {
                    ["event"] = "hook_failed", ["method"] = spec,
                    ["error"] = e.GetType().Name }); }
            }
        }
        return n;
    }

    static Type ResolveType(string name)
    {
        var t = Type.GetType(name);
        if (t != null) return t;
        foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
        {
            t = a.GetType(name);
            if (t != null) return t;
        }
        return null;
    }

    static void Postfix(MethodBase __originalMethod, object[] __args, object __result)
    {
        var rec = new Dictionary<string, object>
        {
            ["event"] = "call",
            ["method"] = __originalMethod.Name,
            ["args"] = (__args ?? new object[0]).Select(Describe).ToList(),
            ["result"] = Describe(__result),
        };
        Emit(rec);
    }

    static IEnumerable<Type> SafeGetTypes(Assembly a)
    {
        try { return a.GetTypes(); }
        catch (ReflectionTypeLoadException e) { return e.Types.Where(t => t != null); }
    }

    // Minimal JSON writer — no dependency, one object per line (JSONL).
    static void Emit(Dictionary<string, object> rec)
    {
        var line = ToJson(rec);
        lock (_lock) File.AppendAllText(_traceFile, line + "\n");
    }
}
