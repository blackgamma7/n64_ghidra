# Ghidra Notes
These are some notes for those who are using Ghidra to examine the code in Nintendo 64 titles. Some of these notes can be applied to other platforms as well. Some of the issues referenced may be addressed by the time you read this.

## Ghidra is more of a guess than a definite answer
As a Jack-of-all-trades, Ghidra... "Does its best" when decompiling code for the various systems. As such, there are quirks with how code is sometimes interpreted. It is good for "greater scope" analysis, with its memory view, reference tracking, and structure defining. However, if you are looking to test matching code, I would recommend something more specialized like Mips2C or decomp.me to test each function.

## Ghidra has trouble finding for-loops
while the decompiler sometimes finds for-loops in code, it can be thrown off if the incrementing value is not a 32-bit int. example:
```
void ForLoopExample(void){
  uint uVar1;

  uVar1=0;
  do{
    //some code
    uVar1 = uVar1 + 1 & 0xFF;
  }while( Uvar1 < 99);
  return;
}
```
In this instance, "uVar1" would be the incrementing value, and it's type would be that of an unsigned char. Thus, a more accurate representation of the code would be:
```
void ForLoopExample(void){
  byte uVar1; //or whatever typedef you prefer
  
  for(uVar1=0;uVar1<99;uVar1++){
    //some code
  }
}
```

## Ghidra doesn't always recognize integer types

As with the above example, the data type of uVar1 was an unsigned char. With some procesors, if the value is declared as something other than the highest bit rate stored on a processor, the compiler will use an AND operation or some bitshifting back and forth to maintain the data type. some examples:
```
//variable is unsigned 16-bit
Uvar1= Uvar1 + x & 0xFFFF;
//variable is unsigned 8-bit
Uvar2= Uvar2 + x & 0xFF;
//variable is signed 16-bit
iVar3=( iVar3 + x )<<0x10; //this can also appear as " * 0x10000"
iVar3= iVar3>>0x10;
```
you may change these within the decompiled function, but code will be added to enforce the more inaccurate data type.


## Ghidra optimizes out unused arguments and variables.
You may find functions that, when called, have paramaters set, but when viewing the function, it's blank. An example below:
```
//code code code
FuncWith2Args(x,y)
//code code code
void FuncWith2Args(void){
  return;
}
```
This is where it's important to note the assembly of the function, notably for instructions that push the argument-holding registers to the stack and edit the function manually to compensate. also, note any remainig instructions that modify the stack pointer - these are making room for local variables. It could be very likely the matching code looks more like this:
```
void FuncWith2Args(int x, float y){
 int z[5];
}
```
also note the "blank" instruction itself may be a dummied printf or sprintf function. You can identify these if one of the first 2 arguments are pointers to strings with format specifiers ("%d,%c,%x",ect).

## .bss
While most loaders are smart enough to recognize this section of the code - where data is zeroed due to not having an inital value - some do not have this feature. This can be due to it not yet being implimented or variations on how that section is cleared. Typically, it is amoung the first set of instructions in the program, and can often look like this:
```
void start(void){
  uint* puVar1;
  int uVar2;

  puVar1=&DAT_XXXXXXXX;
  uVar2=0xYYYYY;
  do{
    uVar2=uVar2-4;
    *puVar1=0;
  }while(uVar2!=0);
  //more init code
  return; //or "while(true){}" in some cases.
}
```
in this case, DAT_XXXXXXXX refers to the start of the .bss section, and 0xYYYYY its size. Go into Memory Map, split the .ram section from XXXXXXXX and then split it again, giving the first split a size of YYYYY and untick the "initalized" checkbox.
Also note that such code is usually asm.

## Nintendo 64 specific

### Mips jump/branch/call

The Mips processor family has a unique quirk wherein when it reaches a jump or call instruction, it does one more just before the jump. While Ghidra (for the most part) takes this into consideration, this can lead to inaccuracies with the decompiler, especially when the last instruction before the jump is to load a value:
```
void BranchIssueExample(int x){
  someStruct* y;
  int z;
  y = &gSomeStruct;
  if( x == 0){
    z = y->someField;
  }
  else{
    //code code code
    z = y->someField;
  }
  if(z==x){
    //code code code
  }
  return;
}
```
the instruction to load y->someField was duplicated by the compiler for efficency, but it threw off the decompiler. With that in mind, it would be more accurate to write the code as:
```
void BranchIssueExample(int x){
 someStruct* y;

  y = &gSomeStruct;
  if(x!=0){
    //code code code
  }
  if(y->someField==x){
    //code code code
  }
}
```


### Mips 1 doubles

The processor in the Nintendo 64 uses the MIPS III instruction set, which is compatible with the previous 2 versions. As such, some developers compiled their code with the older versions in mind. In particular, MIPS I would split double-precision floats amoung 2 FPU registers, due to a lack of 64-bit registers. this REALLY throws Ghidra off, leading to code that can look like this:
```
void MIPS1DoublesIssue(void){
  undefined4 in_register_00001020;
  
  FuncWithFloatArg((float)(double)CONCAT44(in_register_00001020,gDoubleGlobal._4_4));
  return;
}
```
this is currently a compatibility issue with Ghidra. in_register_00001020 in this case refers to the f5 FPU register. Again, this issue may be resolved in other revisions after the time of this writing.

### The N64 is 64-bit...ish.

The R4300i features instructions and registers for 64-bit values, but apart from the aformentioned doubles and any hand-written assembly, most the code compiles into 32-bit instructions.

```
void Move64Bitglobals(void){
  uint x;
  uint y;
  
  x=g64BitGlobalA._0_4;
  y=g64BitGlobalA._4_4;
  g64BitGlobalB._0_4=x;
  g64BitGlobalB._4_4=y;
  return;
}
```
this may be rewritten to match as:
```
void Move64Bitglobals(void){
  g64BitGlobalB=g64BitGlobalA;
}
```

### Arguments and returns are 32-bit, and floats are weird.

Like with the above example, arguments and return values are stored in the bottom half of the applicable register (except for doubles when not compiled in MIPS 1).  This means if the value is 64-bit and not in the argument stack (starting at 0x10, after the  4 aX registers are loaded) then it will be split into 2 registers. As such, if you believe the return or argument to be 64-bit, you should follow the example below when editing the function:
```
longlong FuncWith64BitArgsAndReturn(longlong x, longlong y, longlong z)

longlong | <RETURN> | v0_lo:4,v1_lo:4
longlong | x        | a0_lo:4,a1_lo:4
longlong | y        | a2_lo:4,a3_lo:4
longlong | z        | stack[0x10]:8
```

float arguments have some unique rules. Ghidra defaults to having the first 2 declared in the f12 and f14 registers respectively. In truth, it's a bit more complicated. if the first two arguments are floats, then yes, they would be f12 and f14, and any further args would skip the first and/or second aX registers:
```
void StartsWith2Floats(float x, float y, int z, float w)

void  | <RETURN> | <VOID>
float | x        | f12:4
float | y        | f14:4
int   | z        | a2_lo:4
float | w        | a3_lo:4
```
furthermore, if the first argument is NOT a float, this is ignored and it follows the aformentioned rule of "first 4 in aX, rest in stack" with f12 and f14 not used at all:
```
float StartsWithAPointer(void* p, float x, float y, float z, float w)

float | <RETURN> | f2
void* | p        | a0_lo:4
float | x        | a1_lo:4
float | y        | a2_lo:4
float | z        | a3_lo:4
float | w        | stack[0x10]:4
```
In MIPS 1 compatibility, the rule about spliting doubles in registers also applies for arguments:
```
void MIPS1DoubleFunc(double x, double y)
void   | <RETURN> | <VOID>
double | x        | f12:4,f13:4
double | y        | f14:4,f15:4
```
