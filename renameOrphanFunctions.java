//TODO write a description for this script
//@author 
//@category symbol
//@keybinding 
//@menupath 
//@toolbar 


import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class renameOrphanFunctions extends GhidraScript {
	@Override
	public void run() throws Exception {
		FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
		while (funcIter.hasNext()) {
			Function func = funcIter.next();
			if (currentProgram.getReferenceManager().getReferenceCountTo(func.getEntryPoint()) == 0) {
				String n=func.getName().toLowerCase();
				if(n.equals("ofunc"))
					{func.setName(func.getName()+"_"+func.getEntryPoint(),SourceType.USER_DEFINED);}
				if(n.startsWith("fun_"))
					{func.setName(func.getName().replace("FUN","Ofunc"),SourceType.USER_DEFINED);}
				println(func.getName());
			}
			else{
				if(func.getName().startsWith("Ofunc_"))func.setName(func.getName().replace("Ofunc","FUN"),SourceType.USER_DEFINED);}
		}
	}

}
