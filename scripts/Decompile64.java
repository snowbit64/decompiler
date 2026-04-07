import java.io.File;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class Decompile64 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputDir = getScriptArgs()[0];
        File dir = new File(outputDir);
        if (!dir.exists()) dir.mkdirs();

        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);

        // O Ghidra 11+ possui heurísticas excelentes para encontrar funções em AArch64
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        
        println("Iniciando extração de funções AArch64...");

        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            
            // Aumentamos o tempo para 60s pois funções 64-bit podem ser mais extensas
            DecompileResults res = iface.decompileFunction(f, 60, monitor);
            
            if (res != null && res.getDecompiledFunction() != null) {
                String code = res.getDecompiledFunction().getC();
                
                // Nomeia o arquivo com o endereço hexadecimal para facilitar a busca no IDA/Ghidra
                File outFile = new File(dir, f.getName() + "_" + f.getEntryPoint() + ".c");
                
                try (PrintWriter pw = new PrintWriter(outFile)) {
                    pw.println("// Architecture: AArch64 (64-bit)");
                    pw.println("// Entry Point: " + f.getEntryPoint());
                    pw.println("// Note: Registers X0-X7 hold the first 8 arguments.");
                    pw.println("// --------------------------------------------------");
                    pw.println(code);
                }
            }
        }
        iface.dispose();
        println("Extração concluída com sucesso!");
    }
}
