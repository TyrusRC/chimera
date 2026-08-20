// Chimera .NET tracer harness — value description and JSONL serialization.
//
// Split from Tracer.cs because turning a hooked value into a trace record is
// a self-contained concern with no coupling to how methods are hooked. The
// csproj globs *.cs, so this compiles into the same assembly.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

static partial class Tracer
{
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
        // Integers and chars are how a bytecode VM moves the bytes it is
        // comparing: a memory-read primitive returns the expected key one
        // code point at a time. Capture them as numbers so the caller can
        // reconstruct the ASCII stream.
        if (v is char ch)
            return new Dictionary<string, object> {
                ["type"] = "char", ["value"] = ch.ToString(), ["code"] = (int)ch };
        if (v is int iv)
            return new Dictionary<string, object> { ["type"] = "int", ["value"] = iv };
        if (v is byte bv)
            return new Dictionary<string, object> { ["type"] = "int", ["value"] = (int)bv };
        return new Dictionary<string, object> {
            ["type"] = v.GetType().Name, ["value"] = v.ToString() };
    }

    static string Ascii(byte[] b)
    {
        var sb = new StringBuilder(b.Length);
        foreach (var c in b) sb.Append(c >= 32 && c < 127 ? (char)c : '.');
        return sb.ToString();
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
