# GhidraSCN3
A work-in-progress Scenario Script v3 (d3t) processor module for Ghidra

## Usage
Copy into `Ghidra\Processors\SCN3`. 

Build and run with `..\..\..\support\sleigh.bat data\languages\SCN3.slaspec && ..\..\..\ghidraRun.bat`.

## Current Issues
* PUSH's are currently not all implemented, but most are.
* A good way to dispay how function calls to "engine functions" are constructed needs to be decided on. Arguments are passed by referring to the stack pointer directly, so passing it by reference or directly referencing the registers are the main two ways to go about it.
* maybe more?
