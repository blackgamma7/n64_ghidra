# Ghidra tools by Blackgamma7

a few Ghidra tools devloped for reverse-engineering Nintendo64 titles.

* **N64 OS.gdt** an archive file of common N64 OS structures, typedefs and functions. Incomplete, but a decent jumping-off point.
* **exportSymbolPJ64** dumps a symbol table readable by Project 64.
* **renameOrphanFunctions** looks for orphaned functions and labels them "Ofunc_address"
* **NameConstFloats** finds constant float values and gives them a label of their value. makes interpreted code more readable.
* **SyncSplatSymbols** allows for collaboration by updating Ghidra's symbol table and then dumping it to a symbol table readable by Splat.

## other tools
* [Splat](https://github.com/ethteck/splat) the dissasembly tool that takes the symbol table generated by SyncSplatSymbols.
* [N64LoaderWV](https://github.com/zeroKilo/N64LoaderWV) A Ghidra loading tool for getting started with your project.
