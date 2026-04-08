import java.io.File;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

/**
 * Script de Decompilação para ARMv7 (32-bit)
 * 
 * Compatível com Ghidra 11.0.3
 * 
 * Características:
 * - Extrai pseudocódigo C de todas as funções
 * - Sanitiza nomes de arquivo para compatibilidade multiplataforma
 * - Trata timeouts graciosamente
 * - Gera metadados da função em cada arquivo
 * 
 * Uso: DecompileV7 <outputDir> [timeoutSeconds]
 * Exemplo: DecompileV7 /tmp/output 60
 */
public class DecompileV7 extends GhidraScript {

    /**
     * Sanitiza nome de função removendo caracteres especiais
     * Mantém apenas: letras, números, underscore e hífen
     */
    private String sanitizeFileName(String name) {
        if (name == null || name.isEmpty()) {
            return "function_unknown";
        }
        
        // Substitui caracteres especiais por underscore
        String sanitized = name.replaceAll("[^a-zA-Z0-9_\\-]", "_");
        
        // Remove underscores múltiplos
        sanitized = sanitized.replaceAll("_+", "_");
        
        // Remove underscore no início e fim
        sanitized = sanitized.replaceAll("^_+|_+$", "");
        
        // Se ficou vazio, usa padrão
        if (sanitized.isEmpty()) {
            sanitized = "function_unknown";
        }
        
        // Limita comprimento
        if (sanitized.length() > 180) {
            sanitized = sanitized.substring(0, 180);
        }
        
        return sanitized;
    }

    /**
     * Formata endereço para nome de arquivo
     */
    private String formatAddress(String address) {
        if (address == null || address.isEmpty()) {
            return "unknown_addr";
        }
        return address.replace(":", "").replace("-", "_").toLowerCase();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("Erro: Número incorreto de argumentos");
            printerr("Uso: DecompileV7 <outputDir> [timeoutSeconds]");
            return;
        }

        String outputDirPath = args[0];
        int timeoutSecs = (args.length > 1) ? Integer.parseInt(args[1]) : 60;

        if (timeoutSecs <= 0) {
            timeoutSecs = 60;
        }

        File outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        println("================================================");
        println("Decompilacao ARMv7 (32-bit) - Ghidra 11.0.3");
        println("================================================");
        println("Diretorio de saida: " + outputDir.getAbsolutePath());
        println("Timeout por funcao: " + timeoutSecs + " segundos");
        println("");

        DecompInterface iface = new DecompInterface();
        try {
            // Configurar opções de decompilação
            DecompileOptions options = new DecompileOptions();
            iface.setOptions(options);
            iface.setSimplificationStyle("decompile");
            iface.toggleCCode(true);
            iface.toggleSyntaxTree(false);
            iface.openProgram(currentProgram);

            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            int processed = 0;
            int success = 0;
            int failed = 0;
            long startTime = System.currentTimeMillis();

            while (iter.hasNext() && !monitor.isCancelled()) {
                Function f = iter.next();
                processed++;

                // Pular thunks
                if (f.isThunk()) continue;

                // Monitoramento de progresso
                if (processed % 50 == 0) {
                    println("Processadas: " + processed + " | Sucesso: " + success + " | Falhas: " + failed);
                }

                try {
                    // Tentar decompilação
                    DecompileResults res = iface.decompileFunction(f, timeoutSecs, monitor);

                    if (res != null && res.getDecompiledFunction() != null) {
                        String code = res.getDecompiledFunction().getC();

                        // Criar nome de arquivo sanitizado
                        String sanitizedName = sanitizeFileName(f.getName());
                        String address = formatAddress(f.getEntryPoint().toString());
                        String fileName = sanitizedName + "_" + address + ".c";
                        File outFile = new File(outputDir, fileName);

                        try (PrintWriter pw = new PrintWriter(outFile)) {
                            // Cabeçalho
                            pw.println("// Ghidra Decompiler Output - ARMv7 (32-bit)");
                            pw.println("// Function: " + f.getName());
                            pw.println("// Entry Point: " + f.getEntryPoint());
                            pw.println("// Size: " + f.getBody().getNumAddresses() + " bytes");
                            pw.println("// Signature: " + f.getSignature());
                            pw.println("");
                            pw.println(code);
                        }
                        success++;
                    } else {
                        failed++;
                    }
                } catch (Exception e) {
                    failed++;
                }
            }

            long endTime = System.currentTimeMillis();
            long durationSecs = (endTime - startTime) / 1000;

            println("");
            println("================================================");
            println("Relatorio Final - ARMv7");
            println("================================================");
            println("Funcoes processadas com sucesso: " + success);
            println("Funcoes falhadas: " + failed);
            println("Total processado: " + processed);
            println("Tempo total: " + durationSecs + " segundos");
            println("Extracao concluida!");

        } catch (Exception e) {
            printerr("Erro fatal: " + e.getMessage());
            e.printStackTrace();
        } finally {
            iface.dispose();
        }
    }
}
