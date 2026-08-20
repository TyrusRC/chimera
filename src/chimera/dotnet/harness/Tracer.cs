// Chimera .NET tracer harness.
//
// Loads a target .NET assembly, installs Harmony postfix hooks on the
// methods named on the command line, drives the assembly's entry point
// with a supplied stdin line, and writes one JSON record per hook call to
// the trace file. Harmony detours the JIT-compiled native code rather than
// rewriting on-disk IL, so a runtime method-integrity (anti-tamper) check
// that hashes the IL image does not see the hooks.
//
// Usage:
//   chimera_dotnet_tracer <assembly> <trace-out> <stdin-line> <method>...
//
// Each traced method's byte[]/string arguments and (byte[]/string/bool)
// return value are captured. This is deliberately generic: the caller
// picks which methods to watch.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using HarmonyLib;

static class Tracer
{
    static string _traceFile;
    static readonly object _lock = new object();
    static readonly HashSet<string> _wanted = new HashSet<string>();

    static void Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: tracer <assembly> <trace-out> <stdin> <method>...");
            Environment.Exit(2);
        }
        var asmPath = args[0];
        _traceFile = args[1];
        var stdinLine = args[2];
        foreach (var m in args.Skip(3)) _wanted.Add(m);

        File.WriteAllText(_traceFile, "");  // truncate

        var asm = Assembly.LoadFrom(asmPath);
        var harmony = new Harmony("chimera.dotnet.tracer");
        var postfix = new HarmonyMethod(typeof(Tracer).GetMethod(nameof(Postfix),
            BindingFlags.Static | BindingFlags.NonPublic));

        int hooked = 0;
        foreach (var t in SafeGetTypes(asm))
            foreach (var m in t.GetMethods(BindingFlags.Static | BindingFlags.Instance
                                           | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (!_wanted.Contains(m.Name) || m.IsAbstract || m.ContainsGenericParameters)
                    continue;
                try { harmony.Patch(m, postfix: postfix); hooked++; }
                catch (Exception e) { Emit(new Dictionary<string, object> {
                    ["event"] = "hook_failed", ["method"] = m.Name,
                    ["error"] = e.GetType().Name }); }
            }
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

    static Dictionary<string, object> Describe(object v)
    {
        if (v == null) return new Dictionary<string, object> { ["type"] = "null" };
        if (v is byte[] b)
            return new Dictionary<string, object> {
                ["type"] = "byte[]", ["len"] = b.Length,
                ["hex"] = BitConverter.ToString(b).Replace("-", ""),
                ["ascii"] = Ascii(b) };
        if (v is string s)
            return new Dictionary<string, object> { ["type"] = "string", ["value"] = s };
        if (v is bool bl)
            return new Dictionary<string, object> { ["type"] = "bool", ["value"] = bl };
        return new Dictionary<string, object> {
            ["type"] = v.GetType().Name, ["value"] = v.ToString() };
    }

    static string Ascii(byte[] b)
    {
        var sb = new StringBuilder(b.Length);
        foreach (var c in b) sb.Append(c >= 32 && c < 127 ? (char)c : '.');
        return sb.ToString();
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

    static string ToJson(object o)
    {
        switch (o)
        {
            case null: return "null";
            case bool b: return b ? "true" : "false";
            case int i: return i.ToString();
            case string s: return Quote(s);
            case Dictionary<string, object> d:
                return "{" + string.Join(",", d.Select(kv => Quote(kv.Key) + ":" + ToJson(kv.Value))) + "}";
            case System.Collections.IEnumerable en:
                return "[" + string.Join(",", en.Cast<object>().Select(ToJson)) + "]";
            default: return Quote(o.ToString());
        }
    }

    static string Quote(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 32) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }
}
