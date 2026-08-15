// Export all decompilable functions from the current Ghidra program into one C-like text file.
// @category PolyDecomp

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class ExportDecompiledC extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ExportDecompiledC.java <output-file>");
        }

        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        DecompileOptions options = new DecompileOptions();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(currentProgram)) {
            throw new IOException("failed to initialize Ghidra decompiler: " + decompiler.getLastMessage());
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(output))) {
            writer.write("/* PolyDecomp Ghidra output\n");
            writer.write(" * Program: " + currentProgram.getName() + "\n");
            writer.write(" * Language: " + currentProgram.getLanguageID() + "\n");
            writer.write(" */\n\n");

            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                count++;
                monitor.setMessage("Decompiling " + function.getName());
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                DecompiledFunction decompiled = results.getDecompiledFunction();

                writer.write("/* ============================================================\n");
                writer.write(" * Function: " + function.getName() + "\n");
                writer.write(" * Entry: " + function.getEntryPoint() + "\n");
                writer.write(" * Signature: " + function.getSignature().getPrototypeString() + "\n");
                writer.write(" * ============================================================ */\n");

                if (decompiled != null) {
                    writer.write(decompiled.getC());
                }
                else {
                    writer.write("/* decompilation failed: " + results.getErrorMessage() + " */\n");
                }
                writer.write("\n\n");
            }
            writer.write("/* Functions visited: " + count + " */\n");
        }
        finally {
            decompiler.dispose();
        }
    }
}
