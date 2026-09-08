import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.util.Iterator;

public class CountFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("LANGUAGE=" + currentProgram.getLanguage().getLanguageID());
        println("COMPILER=" + currentProgram.getCompilerSpec().getCompilerSpecID());
        int n = 0;
        Iterator<Function> it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) { it.next(); n++; }
        println("FUNCTIONS_FOUND=" + n);
        for (String name : new String[]{"handle_frame", "rfid_isr_handler", "app_main", "consumer_task"}) {
            Function f = getGlobalFunctions(name).isEmpty() ? null : getGlobalFunctions(name).get(0);
            println("SYM " + name + "=" + (f == null ? "NOT_FOUND" : f.getEntryPoint().toString()));
        }
    }
}
