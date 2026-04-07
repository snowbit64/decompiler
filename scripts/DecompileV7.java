import java.io.File;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileV7 extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("Uso: DecompileV7 <outputDir> [timeoutSeconds]");
            return;
        }

        String outputDirPath = args[0];
        int timeoutSecs = (args.length > 1) ? Integer.parseInt(args[1]) : 45; // padrão para 32-bit

        File outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        println("=== Iniciando decompilação ARMv7 (32-bit) ===");
        println("Diretório de saída: " + outputDir.getAbsolutePath());
        println("Timeout por função: " + timeoutSecs + " segundos");

        DecompInterface iface = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            iface.setOptions(options);
            iface.setSimplificationStyle("decompile");
            iface.toggleCCode(true);
            iface.toggleSyntaxTree(false);
            iface.openProgram(currentProgram);

            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            int processed = 0;
            int success = 0;

            while (iter.hasNext() && !monitor.isCancelled()) {
                Function f = iter.next();
                processed++;

                if (f.isThunk()) continue;

                if (processed % 50 == 0) {
                    println("Processadas: " + processed + " funções | Sucesso: " + success);
                }

                try {
                    DecompileResults res = iface.decompileFunction(f, timeoutSecs, monitor);

                    if (res != null && res.getDecompiledFunction() != null) {
                        String code = res.getDecompiledFunction().getC();

                        String fileName = f.getName() + "_" + f.getEntryPoint().toString().replace(":", "_") + ".c";
                        File outFile = new File(outputDir, fileName);

                        try (PrintWriter pw = new PrintWriter(outFile)) {
                            pw.println("// Architecture: ARMv7 (32-bit)");
                            pw.println("// Function: " + f.getName());
                            pw.println("// Entry Point: " + f.getEntryPoint());
                            pw.println("// Signature: " + f.getSignature());
                            pw.println("// Mode: " + (f.getEntryPoint().getOffset() % 2 != 0 ? "Thumb" : "ARM"));
                            pw.println("// Size: " + f.getBody().getNumAddresses() + " bytes");
                            pw.println("// --------------------------------------------------");
                            pw.println(code);
                        }
                        success++;
                    } else {
                        println("Timeout ou falha na função: " + f.getName() + " @ " + f.getEntryPoint());
                    }
                } catch (Exception e) {
                    printerr("Erro ao decompilar " + f.getName() + ": " + e.getMessage());
                }
            }

            println("=== Extração ARMv7 concluída! ===");
            println("Total processado: " + processed + " | Sucesso: " + success);

        } finally {
            iface.dispose();
        }
    }
}