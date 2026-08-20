"""Run and trace Windows .NET assemblies on Linux.

A .NET Framework binary (the common crackme / malware shape) will not run
under `dotnet` directly, but a small runtimeconfig shim points it at the
installed .NET Core runtime, which executes most self-contained assemblies
unchanged. From there the validation logic can be traced at runtime rather
than devirtualized statically — see `tracer`.
"""
