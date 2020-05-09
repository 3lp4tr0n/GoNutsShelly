## How it works?
Inject shellcode into remote process by using CreateRemoteThread.
Can also add VirtualProtectEx (just in case).

## What to change?
Change shellcode and PID. (Will make it more user friendly soon).

## How to build?
- go build mainrpi.go
 
## How to run?
- Open CMD
- C:\path\mainrpi.exe
