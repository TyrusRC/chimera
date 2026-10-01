// Chimera Ghidra post-script — decompile ONE function (the one containing the
// address in -Dchimera.decompile.addr) and write {ok,address,name,code} JSON to
// -Dchimera.out.dir/decompile_one.json. The standalone-Ghidra decompile backend
// for `chimera decompile --decompiler ghidra`, used when r2ghidra is unavailable.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileOne extends GhidraScript {
    public void run() throws Exception {
        // Args (robust across Ghidra versions) with a -D property fallback:
        //   getScriptArgs()[0] = output dir, [1] = target address.
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : System.getProperty("chimera.out.dir");
        String addrStr = args.length > 1 ? args[1] : System.getProperty("chimera.decompile.addr");
        int timeout = Integer.getInteger("chimera.decompile.timeout", 60);
        try (PrintWriter fh = new PrintWriter(new FileWriter(outDir + "/decompile_one.json"))) {
            try {
                long off = Long.decode(addrStr);
                Address addr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(off);
                Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (f == null) {
                    fh.print("{\"ok\":false,\"error\":" + jstr("no function containing " + addrStr) + "}");
                    return;
                }
                DecompInterface ifc = new DecompInterface();
                ifc.openProgram(currentProgram);
                DecompileResults res = ifc.decompileFunction(f, timeout, new ConsoleTaskMonitor());
                if (res == null || !res.decompileCompleted()) {
                    fh.print("{\"ok\":false,\"error\":\"decompile did not complete\"}");
                    return;
                }
                String code = res.getDecompiledFunction().getC();
                fh.print("{\"ok\":true,\"address\":" + jstr(addrStr)
                        + ",\"name\":" + jstr(f.getName())
                        + ",\"code\":" + jstr(code) + "}");
            } catch (Exception e) {
                fh.print("{\"ok\":false,\"error\":" + jstr(String.valueOf(e)) + "}");
            }
        }
    }

    static String jstr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append("\"").toString();
    }
}
