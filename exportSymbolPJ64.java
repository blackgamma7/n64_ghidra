//creates symbol table for Project64
//@author Blackgamma7
//@category symbol
//@keybinding 
//@menupath 
//@toolbar 





import java.io.File;
import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;


public class exportSymbolPJ64 extends GhidraScript {

	@Override
	public void run() throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();
		File f = askFile("Where do you want symbols?", "here");
		FileWriter W = new FileWriter(f);
		while (it.hasNext() && !monitor.isCancelled()) {
			String datName="data";
			Symbol s = it.next();
			Address addr = s.getAddress();
			String name = s.getName();
			if (name.startsWith("FUN_") || !addr.isMemoryAddress()||s.getParentSymbol().getName().startsWith("switchD")||s.getParentSymbol().getName().startsWith("ConstFloats")) {continue;}
			if(Character.isDigit(name.charAt(0))){name="_"+name;}
			if(s.getSymbolType()!=SymbolType.FUNCTION){
			try{datName=getDataAt(addr).getBaseDataType().getName().toLowerCase();}
			catch(Exception e){datName="error";}}
			else{datName="code";}
			switch(datName){
				default:
				datName="data";
				break;
				case "undefined4":
				case "uint":
				datName="u32";
				break;
				case "undefined2":
				case "ushort":
				datName="u16";
				break;
				case "float":
				case "double":
				case "u32":
				case "s16":
				case "code":
				break;
				case "float[2]":
				datName="v2";
				break;
				case "float[3]":
				datName="v3";
				break;
				case "float[4]":
				datName="v4";
				break;
				case "undefined1":
				case "byte":
				case "bool":
				datName="u8";
				break;
				case "char":
				case "s8":
				datName="s8";
				break;
				case "short":
				datName="s16";
				break;
				case "int":
				datName="s32";
				break;
				case "undefined8":
				case "ulonglong":
				datName="u64";
				break;
				case "longlong":
				datName="s64";
				break;
			}
			W.write(addr+","+datName+","+name+"\n");
		}
		W.close();
		
	}
}
