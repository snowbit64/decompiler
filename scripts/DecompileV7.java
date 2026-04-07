import java.io.File;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileV7 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputDir = getScriptArgs()[0];
        File dir = new File(outputDir);
        if (!dir.exists()) dir.mkdirs();

        // Configuração do Descompilador
        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);

        // Itera sobre todas as funções encontradas pela análise heurística
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            
            // Timeout de 30 segundos por função para evitar travamentos em loops complexos
            DecompileResults res = iface.decompileFunction(f, 30, monitor);
            
            if (res != null && res.getDecompiledFunction() != null) {
                String code = res.getDecompiledFunction().getC();
                File outFile = new File(dir, f.getName() + "_" + f.getEntryPoint() + ".c");
                try (PrintWriter pw = new PrintWriter(outFile)) {
                    pw.println("// Address: " + f.getEntryPoint());
                    pw.println("// Mode: " + (f.getEntryPoint().getOffset() % 2 != 0 ? "Thumb" : "ARM"));
                    pw.println(code);
                }
            }
        }
        iface.dispose();
    }
}
