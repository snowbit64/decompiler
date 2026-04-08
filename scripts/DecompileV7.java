import java.io.File;
import java.io.PrintWriter;
import java.util.regex.Pattern;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

/**
 * Script de Decompilação para ARMv7 (32-bit)
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
        
        // Limita comprimento (max 255 - extensão .c - hash)
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
        // Remove ':' e outros caracteres especiais
        return address.replace(":", "").replace("-", "_").toLowerCase();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("❌ Erro: Número incorreto de argumentos");
            printerr("Uso: DecompileV7 <outputDir> [timeoutSeconds]");
            printerr("Exemplo: DecompileV7 /tmp/output 60");
            return;
        }

        String outputDirPath = args[0];
        int timeoutSecs = (args.length > 1) ? Integer.parseInt(args[1]) : 60;

        // Validar timeout
        if (timeoutSecs <= 0) {
            printerr("⚠️  Aviso: timeout inválido, usando padrão de 60s");
            timeoutSecs = 60;
        }

        File outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        println("╔════════════════════════════════════════════════════╗");
        println("║  Decompilação ARMv7 (32-bit) - Ghidra Script      ║");
        println("╚════════════════════════════════════════════════════╝");
        println("📁 Diretório de saída: " + outputDir.getAbsolutePath());
        println("⏱️  Timeout por função: " + timeoutSecs + " segundos");
        println("📊 Arquitetura: ARM Little Endian 32-bit (v7)");
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
            int timeout = 0;
            long startTime = System.currentTimeMillis();

            while (iter.hasNext() && !monitor.isCancelled()) {
                Function f = iter.next();
                processed++;

                // Pular thunks (são apenas intermediários)
                if (f.isThunk()) continue;

                // Monitoramento de progresso a cada 50 funções
                if (processed % 50 == 0) {
                    println(String.format("⏳ Processadas: %d funções | ✓ Sucesso: %d | ✗ Falhas: %d | ⏱️  Timeout: %d",
                            processed, success, failed, timeout));
                }

                try {
                    // Tentar decompilação com timeout
                    DecompileResults res = iface.decompileFunction(f, timeoutSecs, monitor);

                    if (res != null && res.getDecompiledFunction() != null) {
                        String code = res.getDecompiledFunction().getC();

                        // Criar nome de arquivo sanitizado
                        String sanitizedName = sanitizeFileName(f.getName());
                        String address = formatAddress(f.getEntryPoint().toString());
                        String fileName = sanitizedName + "_" + address + ".c";
                        File outFile = new File(outputDir, fileName);

                        try (PrintWriter pw = new PrintWriter(outFile)) {
                            // Cabeçalho com metadados
                            pw.println("// ============================================");
                            pw.println("// GHIDRA DECOMPILER OUTPUT - ARMv7 (32-bit)");
                            pw.println("// ============================================");
                            pw.println("// Function Name: " + f.getName());
                            pw.println("// Entry Point: " + f.getEntryPoint());
                            pw.println("// Address (hex): 0x" + address);
                            pw.println("// Signature: " + f.getSignature());
                            pw.println("// Mode: " + (f.getEntryPoint().getOffset() % 2 != 0 ? "Thumb" : "ARM"));
                            pw.println("// Size: " + f.getBody().getNumAddresses() + " bytes");
                            pw.println("// Is External: " + f.isExternal());
                            pw.println("// Is Library: " + f.isLibraryFunction());
                            pw.println("// ============================================");
                            pw.println("");
                            pw.println(code);
                        }
                        success++;
                    } else {
                        // Decompilação falhou ou timeout
                        if (res != null && res.getDecompileStatus() != null) {
                            if (res.getDecompileStatus().contains("timeout")) {
                                timeout++;
                                println("⏱️  TIMEOUT: " + f.getName() + " @ " + f.getEntryPoint());
                            } else {
                                failed++;
                                println("❌ FALHA: " + f.getName() + " @ " + f.getEntryPoint());
                            }
                        } else {
                            failed++;
                            println("⚠️  Resultado nulo para: " + f.getName() + " @ " + f.getEntryPoint());
                        }
                    }
                } catch (Exception e) {
                    failed++;
                    printerr("❌ Erro ao decompilar " + f.getName() + ": " + e.getMessage());
                }
            }

            long endTime = System.currentTimeMillis();
            long durationSecs = (endTime - startTime) / 1000;

            println("");
            println("╔════════════════════════════════════════════════════╗");
            println("║              RELATÓRIO FINAL - ARMv7              ║");
            println("╚════════════════════════════════════════════════════╝");
            println(String.format("✓ Funções processadas com sucesso: %d", success));
            println(String.format("✗ Funções falhadas: %d", failed));
            println(String.format("⏱️  Funções com timeout: %d", timeout));
            println(String.format("📊 Total processado: %d funções", processed));
            println(String.format("⏳ Tempo total: %d segundos", durationSecs));
            println("✅ Extração ARMv7 concluída!");

        } catch (Exception e) {
            printerr("❌ Erro fatal na decompilação: " + e.getMessage());
            e.printStackTrace();
        } finally {
            iface.dispose();
        }
    }
}
