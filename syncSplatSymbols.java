//loads and updates symbols in ghidra, then writes new ones to Splat symbol table
//@author 
//@category Symbol
//@keybinding 
//@menupath 
//@toolbar 
import java.io.*;
import java.util.*;

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

public class syncSplatSymbols extends GhidraScript {

    public void run() throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();
		String act="";
		File f = askFile("Where is symbol table?", "here");
		if(!f.exists())f.createNewFile();
		//read the new symbols
		try(BufferedReader br = new BufferedReader(new FileReader(f))){
			String line;
			List<String> Choices=Arrays.asList(new String[] { "replace", "skip", "replace all", "skip all"});
			while ((line = br.readLine()) != null) {
				String[] splatEnt=line.split("[=;/]+");
				try{
				Address addr= toAddr(splatEnt[1]);
				splatEnt[0]=SymbolUtilities.replaceInvalidChars(splatEnt[0],false);
				Symbol s=st.getPrimarySymbol​(addr);
				if(s!=null){if(!splatEnt[0].equals(s.getName())){
					if(!act.equals("Skip all")||!act.equals("replace all")||!s.getName().startsWith("FUN_"))
						act=askChoice("rename", "rename "+s.getName()+" to "+splatEnt[0]+"?",Choices,"replace");
					if(act.equals("replace all")||act.equals("replace")){
						println("renaming "+s.getName()+" to "+splatEnt[0]+"");
						s.setName(splatEnt[0],SourceType.IMPORTED);
						}
					}
				}
				else{createLabel(addr,splatEnt[0],false);println("added: "+line);}}
				catch(Exception e){println(line+" is not a valid entry.");}
			}
		}
		//add to the table
		FileWriter W = new FileWriter(f);
		String NamespaceExclude = askString("exclude nameSpaces?","are there any namespaces you wish to leave out?\nSeperate with commas");
		List<String> NSexclude=Arrays.asList(NamespaceExclude.split(","));
		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			Address addr = s.getAddress();
			String name = s.getName();
			//skip un-id'd funcs, jumptables, and other invalid symbols
			if (name.startsWith("FUN_") || !addr.isMemoryAddress()||s.getParentSymbol().getName().startsWith("switchD")||name.startsWith("prt_"+addr.toString())||name.startsWith("thunk_FUN_")) continue;
			//skip my custom label schemes
			if(name.equals("Ofunc_"+addr.toString())||s.getParentSymbol().getName().equals("ConstFloats"))continue;
			//exclude specified namespaces
			if(NSexclude.contains(s.getParentSymbol().getName()))continue;
			//clean up labels for compiler's sake
			if(Character.isDigit(name.charAt(0))){name="_"+name;}
			if(name.startsWith("-")){name=name.replaceFirst("-","neg");}
			//inline labeling
			String Nline ="// ";
			if(s.getSymbolType()==SymbolType.FUNCTION){Nline+="type:func";}
			else{
				Nline+="type:data";
				try{
					int datSize=getDataAt(addr).getBaseDataType().getLength();
					if(datSize>0) Nline+=" size:0x"+Integer.toHexString(datSize);
				}
				catch(Exception e){}
			}
			//big sanitizer, could use regex.
			String outp=SymbolUtilities.replaceInvalidChars(name,true).replace('?','_').replace(".","_").replace("-","_").replace("!","_")+" = 0x"+addr+"; "+Nline;
			boolean inFile=false;
			try(BufferedReader br = new BufferedReader(new FileReader(f))){
				String line;
				while ((line = br.readLine()) != null) {
					if(line.equals(outp)){
						println(line+" exists.");
						inFile=true;
						break;
					}
				}
			}
			if(!inFile){
			//overwrites, needs fixed
			W.append(outp+"\n");
			println(name+" "+addr+"="+s.getSymbolType()+" added.");}
		}
		W.close();
	}
}

