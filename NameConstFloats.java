//Rename Floats and Doubles With read-only calls.
//@author Blackgamma7
//@category Symbol
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

public class NameConstFloats extends GhidraScript {

    public void run() throws Exception {
	Listing listing;
	Memory memory;
	SymbolTable symbolTable;

		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		symbolTable = currentProgram.getSymbolTable();
		Data data = getFirstData();
		//first iteration: find floats based on operand
		while ((data != null) && (!monitor.isCancelled())) {
		try{
		String n=data.getDataType().getName();
		if (n.equals("undefined4")||n.equals("undefined8")){
		println(data.getMinAddress().toString());
		Reference[] refs=symbolTable.getPrimarySymbol(data.getMinAddress()).getReferences();
		if(refs.length>0){
				for(Reference ref:refs){
				println(ref.getFromAddress().toString());
				  String opc=listing.getCodeUnitAt(ref.getFromAddress()).getMnemonicString().toLowerCase();
				  if(opc.equals("lwc1")||opc.equals("_lwc1")||opc.equals("swc1")||opc.equals("MOVSS")||opc.equals("FLD m32fp")){
				  listing.clearCodeUnits(data.getMinAddress(),data.getMaxAddress(),false);
					  listing.createData(data.getMinAddress(),new FloatDataType());break;}
				  if(opc.equals("ldc1")||opc.equals("_ldc1")||opc.equals("sdc1")||opc.equals("MOVSD")||opc.equals("FLD m64fp")){
				  listing.clearCodeUnits(data.getMinAddress(),data.getMaxAddress(),false);
				listing.createData(data.getMinAddress(),new DoubleDataType());break;}
		}}
		}}
		catch(Exception e){}
		data = getDataAfter(data);
		}
		data = getFirstData();
		//second: name them if they're constant.
		try{
			symbolTable.createNameSpace(symbolTable.getNamespace("Global",null),"ConstFloats",SourceType.USER_DEFINED);
		}
		catch(Exception e){}
		while ((data != null) && (!monitor.isCancelled())) {
			if (!data.isPointer() && data.isInitializedMemory() &&
				(data.getBaseDataType().getName().toLowerCase().equals("float")) ||
				(data.getBaseDataType().getName().toLowerCase().equals("double"))) {
				Symbol sym = symbolTable.getPrimarySymbol(data.getMinAddress());
				boolean readOnly=true;
				try{
				Reference[] refs=sym.getReferences();
				for(Reference ref:refs){
					if(ref.getReferenceType().isWrite()){readOnly=false;}
					}
				}
				catch(Exception e){readOnly=false;}
				if ((sym != null) && ((sym.getSource() == SourceType.DEFAULT) ||
					(sym.getSource() == SourceType.ANALYSIS))&&readOnly){
					String val=data.getDefaultValueRepresentation();
					char ForD = data.getBaseDataType().getName().charAt(0);
					String newlabel=null;
					switch(val){
					case "1.5707965":
					case "1.5707964897155762":
					case "1.5707963267948966":
					newlabel="PIover2_"+ForD;
					break;
					case "0.016666668":
					case "0.016666666666666666":
					newlabel="1over60_"+ForD;
					break;
					case "2.14748365E9" :
					case "2.147483648E9":
					newlabel="INT_MAX_"+ForD;
					break;
					case "3.14159" :
					case "3.1415927":
					case "3.141593" :
					case "3.14" :
					case "3.141592653589793":
					newlabel="PI_"+ForD;
					break;
					case "-3.141592653589793":
					newlabel="NegPI_"+ForD;
					break;
					case "6.2831855" :
					case "6.283185307179586":
					newlabel="TAU_"+ForD;
					break;
					case "0.017453":
					case "0.017453292519943295":
					case "0.017453292":
					newlabel="DtoR_"+ForD;
					break;
					case "0.7853981633974483":
					newlabel="DtoR45_"+ForD;
					break;
					case "-0.7853981633974483":
					newlabel="NegDtoR45_"+ForD;
					break;
					case "2.71828" :
					newlabel="E_"+ForD;
					break;
					case "57.29578" :
					newlabel="RadInDeg_"+ForD;
					break;
					case "4.294967296E9" :
					newlabel="UINT_MAX_"+ForD;
					break;
					case "32767.0":
					newlabel="SHORT_MAX_"+ForD;
					break;
					case "-32767.0":
					newlabel="SHORT_MIN_"+ForD;
					break;
					case "65535.0":
					newlabel="USHORT_MAX_"+ForD;
					break;
					case "1.4426950408889634":
					newlabel="LOG2E_"+ForD;
					break;
					case "0.6931471805599453":
					case "0.69314718246":
					newlabel="LN2_"+ForD;
					break;
					default:
					newlabel=val+ForD;
					break;}
					Symbol newSym = symbolTable.createLabel(data.getMinAddress(), newlabel,symbolTable.getNamespace("ConstFloats",null),SourceType.ANALYSIS);
					println(data.getMinAddress().toString() + " " + newlabel);
					if (!newSym.isPrimary()) {
						newSym.setPrimary();
					}

				}
			}
			data = getDataAfter(data);
		}
	}
}
