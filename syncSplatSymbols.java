
//loads and updates symbols in ghidra, then writes new ones to Splat symbol table
//@author 
//@category Symbol
//@keybinding 
//@menupath 
//@toolbar 
import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.*;

public class syncSplatSymbols extends GhidraScript {

	public void run() throws Exception {
		boolean appendThis;
		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();
		String act = "";
		String act2 = "";
		File f = askFile("Where is symbol table?", "here");
		if (!f.exists()) {
			f.createNewFile();
			appendThis = false;
		} else
			appendThis = askYesNo("Append or rewrite?",
					"Do you wish to append the file?\nYES: append current list\nNO: rewrite entire list");
		// read the new symbols
		try (BufferedReader br = new BufferedReader(new FileReader(f))) {
			String line;
			List<String> Choices = Arrays.asList(new String[] { "replace", "skip", "replace all", "skip all" });
			List<String> Choices2 = Arrays.asList(new String[] { "add", "skip", "add all", "skip all" });
			while ((line = br.readLine()) != null) {
				String[] splatEnt = line.split("[=;/]+");
				try {
					Address addr = toAddr(splatEnt[1]);
					splatEnt[0] = SymbolUtilities.replaceInvalidChars(splatEnt[0], false);
					if (splatEnt[0].contains("::")) {
						splatEnt[0] = splatEnt[0].substring(splatEnt[0].lastIndexOf("::") + 2);
					}
					Symbol s = st.getPrimarySymbol(addr);
					// skip generic labels
					if (!splatEnt[0].toLowerCase().equals("d_" + addr.toString()) && !splatEnt[0].toLowerCase().equals("func_" + addr.toString())
							&& !splatEnt[0].equals("DAT_" + addr.toString())
							&& !splatEnt[0].equals("D_" + addr.toString().toUpperCase())) {
						// does entry exist?
						if (s != null) {
							if (!splatEnt[0].equals(s.getName())) {
								// rename existing entry
								if (act.equals("skip all")) {
									continue;
								}
								if ((!act.equals("skip all") && !act.equals("replace all"))
										&& !s.getName().startsWith("FUN_")) {
									act = askChoice("rename", "rename " + s.getName() + " to " + splatEnt[0] + "?",
											Choices, "rename");
								}
								if (act.equals("replace all") || act.equals("replace")
										|| s.getName().startsWith("FUN_")) {
									println("renaming " + s.getName() + " to " + splatEnt[0] + "");
									s.setName(splatEnt[0], SourceType.IMPORTED);
								}
							}
						}
						// add new one
						else {
						    if(act2.equals("add all")){
								createLabel(addr, splatEnt[0], false);
								println("added: " + line);							
							}
							else if (!(act2.equals("skip all")) && !(act.equals("add all")))
								act2 = askChoice("add", "add " + splatEnt[0] + "?", Choices2, "add");
							if (act2.equals("add all") || act2.equals("add")) {
								createLabel(addr, splatEnt[0], false);
								println("added: " + line);
							}
						}
					}
				} catch (Exception e) {
					println(line + " is not a valid entry.");
				}
			}
		}
		// add to the table
		FileWriter W = new FileWriter(f, appendThis);
		// String NamespaceExclude = askString("exclude nameSpaces?","are there any
		// namespaces you wish to leave out?\nSeperate with commas");
		String NamespaceExclude = "_";
		// dirty kludge to add splat's PSX compatibility
		boolean IsPSX = currentProgram.getExecutableFormat().equals("PSX Executables Loader");
		List<String> NSexclude = Arrays.asList(NamespaceExclude.split(","));
		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			Address addr = s.getAddress();
			String name = s.getName();
			if(s.getParentSymbol().getSymbolType()==SymbolType.FUNCTION) continue;
			// skip un-id'd funcs, jumptables, and other invalid symbols
			if (name.startsWith("FUN_") || !addr.isMemoryAddress()
					|| s.getParentSymbol().getName().startsWith("switchD") || name.startsWith("prt_" + addr.toString())
					|| name.startsWith("thunk_FUN_") || name.startsWith("_gp_"))
				continue;
			// skip my custom label schemes. prefix '?' if you don't wanna share with the
			// class.
			if (name.equals("Ofunc_" + addr.toString()) || s.getParentSymbol().getName().equals("ConstFloats")
					|| name.startsWith("?"))
				continue;
			// and just in case
			if (name.endsWith("?"))
				continue;
			// exclude specified namespaces
			if (NSexclude.contains(s.getParentSymbol().getName()))
				continue;
			// clean up labels for compiler's sake
			if (Character.isDigit(name.charAt(0))) {
				name = "_" + name;
			}
			if (name.startsWith("-")) {
				name = name.replaceFirst("-", "neg");
			}
			// inline labeling
			String Nline = "// ";
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				Nline += "type:func";
				// getting code size problematic, feature removed.
			} else if (getDataAt(addr)!=null){
			   DataType dat = getDataAt(addr).getBaseDataType();
			   if(getDataAt(addr).hasStringValue()){
			   Nline += "type:asciz";
			   } else{
			   	switch(dat.getName().toLowerCase()){
				default:
				break;
				case "undefined4":
				case "uint":
				Nline += "type:u32";
				break;
				case "undefined2":
				case "ushort":
				Nline += "type:u16";
				break;
				case "float":
				Nline += "type:f32";
				break;
				case "double":
				Nline += "type:f64";
				break;
				case "undefined1":
				case "byte":
				case "bool":
				Nline += "type:u8";
				break;
				case "char":
				case "s8":
				case "sbyte":
				Nline += "type:s8";
				break;
				case "short":
				case "s16":
				Nline += "type:s16";
				break;
				case "int":
				Nline += "type:s32";
				break;
				case "undefined8":
				case "ulonglong":
				case "u64":
				Nline += "type:u64";
				break;
				case "longlong":
				Nline += "type:s64";
				case "float[3]":
				case "vec3f":
				Nline += "type:vec3f";
				break;
			   }}
				try {
					int datSize = dat.getLength();
					if (datSize > 0)
						Nline += " size:0x" + Long.toHexString(datSize);
				} catch (Exception e) {
				}
			}
			// Add rom offset.

			if (addr.getAddressSpace().isOverlaySpace()) {
				Nline += " rom: 0x"
						+ Long.toHexString(currentProgram.getMemory().getAddressSourceInfo(addr).getFileOffset());
			} else if (IsPSX) {
				// todo: add rom to PSX table?
			} else if ((addr.subtract(getMemoryBlock(".ram").getStart()) > 0)) {
				if ((addr.getOffset() >= 0xA0000000) && (addr.getOffset() < 0xB0000000)) {
					continue;
				} // Not Register address?
				// if in rom, just get the physical address. IF I CAN GET THIS TO WORK.
				// if(addr.subtract(0xB0000000).getOffset()>=0){Nline+="
				// rom:0x"+Long.toHexString(addr.getOffset()-0xB0000000);}
				// check for bss.
				try {
					if (addr.subtract(getMemoryBlock(".ram.bss").getStart()) < 0) {
						Nline += " rom:0x"
								+ Long.toHexString(addr.subtract(getMemoryBlock(".ram").getStart()) + 0x1000);
					}
				} catch (Exception e) {
					println("please identify the bss of the program and name the memory block \".ram.bss\" first.\nHint: \'entrypoint\' clears it out.");
					return;
				}
			}
			// big sanitizer, could use regex.
			name = SymbolUtilities.replaceInvalidChars(name, true).replace('?', '_').replace(".", "_").replace("-", "_")
					.replace("!", "_");
			String ns = s.getParentNamespace().getName();
			if (ns != null && !ns.equals("os") && !ns.equals("ConstFloats")
					&& !s.isGlobal() && s.getParentSymbol().getSymbolType() != SymbolType.FUNCTION) {
				name = ns + "::" + name;
			}
			String outp = name + " = 0x" + addr + "; " + Nline;
			boolean inFile = false;
			try (BufferedReader br = new BufferedReader(new FileReader(f))) {
				String line;
				while ((line = br.readLine()) != null) {
					// check for duplicate names in file. for compiler's sake.
					String[] ent = line.split(" ");
					if (ent[0].equals(name) && s.getParentSymbol().getSymbolType() != SymbolType.FUNCTION) {
						if (addr.toString().equals(ent[2].substring(2, 10).toLowerCase())) {
							println(name + " exists.");
							inFile = true;
							break;
						}

						println(name + " has duplicate name. renaming.");
						outp = name + "_" + addr + " = 0x" + addr + "; " + Nline;
					}
				}
			}
			if (!inFile) {
				W.append(outp + "\n");
				println(name + " " + addr + "=" + s.getSymbolType() + " added.");
			}
		}
		W.close();
	}
}
