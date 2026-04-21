// Chimera Ghidra post-script — emits functions/strings/symbols JSON.
//@category Chimera

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
