// Export bounded function, direct/indirect flow and p-code data for Sandworm.
//@category Sandworm
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import com.google.gson.*;
import java.nio.file.*;

public class SandwormExport extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        JsonObject root = new JsonObject();
        root.addProperty("schema_version", 1);
        root.addProperty("image_base", currentProgram.getImageBase().toString());
        JsonArray functions = new JsonArray();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        try {
            while (iterator.hasNext() && count++ < 256 && !monitor.isCancelled()) {
                Function function = iterator.next();
                JsonObject row = new JsonObject();
                row.addProperty("name", function.getName());
                row.addProperty("entry", function.getEntryPoint().toString());
                DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
                row.addProperty("completed", result.decompileCompleted());
                if (result.decompileCompleted()) {
                    String source = result.getDecompiledFunction().getC();
                    row.addProperty("c", source.substring(0, Math.min(source.length(), 32768)));
                } else row.addProperty("error", result.getErrorMessage());
                JsonArray instructions = new JsonArray();
                InstructionIterator listing = currentProgram.getListing().getInstructions(function.getBody(), true);
                int n = 0;
                while (listing.hasNext() && n++ < 512) {
                    Instruction instruction = listing.next();
                    JsonObject ins = new JsonObject();
                    ins.addProperty("address", instruction.getAddress().toString());
                    ins.addProperty("size", instruction.getLength());
                    ins.addProperty("text", instruction.toString());
                    ins.addProperty("computed_flow", instruction.getFlowType().isComputed());
                    JsonArray flows = new JsonArray();
                    for (Address address : instruction.getFlows()) flows.add(address.toString());
                    ins.add("targets", flows);
                    JsonArray pcode = new JsonArray();
                    for (PcodeOp operation : instruction.getPcode()) pcode.add(operation.toString());
                    ins.add("pcode", pcode);
                    instructions.add(ins);
                }
                row.add("instructions", instructions);
                functions.add(row);
            }
        } finally { decompiler.dispose(); }
        root.add("functions", functions);
        Files.writeString(Path.of(getScriptArgs()[0]), new Gson().toJson(root));
    }
}
