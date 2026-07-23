// Chimera Ghidra post-script — emits functions/strings/symbols/decompilations JSON.
//@category Chimera

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = System.getProperty("chimera.out.dir");
        if (outDir == null) outDir = getProjectRootFolder().getPathname() + "/output";
        new File(outDir).mkdirs();
        writeFunctions(outDir + "/functions.json");
        writeStrings(outDir + "/strings.json");
        writeSymbols(outDir + "/symbols.json");
        writeDecompilations(outDir + "/decompilations.json");
    }

    // Decompile each non-thunk/non-external function to C via the Ghidra
    // decompiler and emit [{"address","name","code"}]. Bounded by two JVM
    // system properties so a pathological binary can't wedge the pass:
    //   -Dchimera.decompile.max=<N>       cap function count (0 = unlimited)
    //   -Dchimera.decompile.timeout=<sec> per-function decompile timeout
    private void writeDecompilations(String path) throws Exception {
        int max = Integer.getInteger("chimera.decompile.max", 2000);
        int timeout = Integer.getInteger("chimera.decompile.timeout", 60);
        DecompInterface dec = new DecompInterface();
        try {
            if (!dec.openProgram(currentProgram)) {
                // Decompiler failed to initialize — emit an empty array so the
                // downstream ingester sees a well-formed (if empty) file.
                try (BufferedWriter w = new BufferedWriter(new FileWriter(path))) {
                    w.write("[]");
                }
                return;
            }
            Listing listing = currentProgram.getListing();
            FunctionIterator it = listing.getFunctions(true);
            try (BufferedWriter w = new BufferedWriter(new FileWriter(path))) {
                w.write("[");
                boolean first = true;
                int n = 0;
                while (it.hasNext() && !monitor.isCancelled()) {
                    if (max > 0 && n >= max) break;
                    Function f = it.next();
                    if (f.isThunk() || f.isExternal()) continue;
                    DecompileResults res = dec.decompileFunction(f, timeout, monitor);
                    if (res == null || !res.decompileCompleted()) continue;
                    DecompiledFunction dg = res.getDecompiledFunction();
                    if (dg == null) continue;
                    String code = dg.getC();
                    if (code == null || code.isEmpty()) continue;
                    if (!first) w.write(",");
                    first = false;
                    w.write(String.format(
                        "{\"address\":\"%s\",\"name\":%s,\"code\":%s}",
                        f.getEntryPoint(), jsonStr(f.getName()), jsonStr(code)));
                    n++;
                }
                w.write("]");
            }
        } finally {
            dec.dispose();
        }
    }

    private void writeFunctions(String path) throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionIterator it = listing.getFunctions(true);
        try (BufferedWriter w = new BufferedWriter(new FileWriter(path))) {
            w.write("[");
            boolean first = true;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (!first) w.write(",");
                first = false;
                w.write(String.format(
                    "{\"name\":%s,\"address\":\"%s\",\"size\":%d}",
                    jsonStr(f.getName()), f.getEntryPoint(), f.getBody().getNumAddresses()));
            }
            w.write("]");
        }
    }

    private void writeStrings(String path) throws Exception {
        try (BufferedWriter w = new BufferedWriter(new FileWriter(path))) {
            w.write("[");
            boolean first = true;
            for (var d : DefinedDataIterator.definedStrings(currentProgram)) {
                if (monitor.isCancelled()) break;
                Object v = d.getValue();
                if (v == null) continue;
                if (!first) w.write(",");
                first = false;
                w.write(String.format(
                    "{\"address\":\"%s\",\"value\":%s}",
                    d.getAddress(), jsonStr(v.toString())));
            }
            w.write("]");
        }
    }

    private void writeSymbols(String path) throws Exception {
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        try (BufferedWriter w = new BufferedWriter(new FileWriter(path))) {
            w.write("[");
            boolean first = true;
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                if (!first) w.write(",");
                first = false;
                w.write(String.format(
                    "{\"name\":%s,\"address\":\"%s\",\"type\":%s}",
                    jsonStr(s.getName()), s.getAddress(), jsonStr(s.getSymbolType().toString())));
            }
            w.write("]");
        }
    }

    private String jsonStr(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                      .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
