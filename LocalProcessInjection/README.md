## Local Process Injection
This is the first injection script I made with Go.

## How it works?
Alloactes memory in current process using VirtualAlloc.
Uses memcpy from C import to copy shellcode into allocated memory. 

## How to build?
- go build main.go

## How to run?
- Open CMD
- C:\Path\main.exe
